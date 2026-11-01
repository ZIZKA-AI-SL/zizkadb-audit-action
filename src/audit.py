"""ZizkaDB Audit: verify an AI agent's recorded history and produce audit evidence."""

from __future__ import annotations

import hashlib
import json
import os
import sys
import urllib.error

import zizkadb_ci as z

MARKER = "<!-- zizkadb-audit-action -->"
OUT_DIR = "zizkadb-audit"
HEADS_FILE = "chain-heads.json"
HEADS_VERSION = 1
HEX = set("0123456789abcdef")


def _head(value) -> dict | None:
    """A stored chain head as {sequence_no, chain_hash}, or None if it is not one."""
    if not isinstance(value, dict):
        return None
    seq, link = value.get("sequence_no"), value.get("chain_hash")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        return None
    if not isinstance(link, str) or len(link) != 64 or not set(link.lower()) <= HEX:
        return None
    return {"sequence_no": seq, "chain_hash": link.lower()}


def load_anchors(path: str) -> tuple[dict[str, dict], str]:
    """Stored chain heads per agent, read from `chain-heads.json` (written by this
    action) or from an earlier `report.json`.

    Returns ({agent: head}, note). A missing file is a first run, not an error:
    the audit runs unanchored and writes the heads the next run starts from.
    A file that exists but cannot be read stops the audit, so a damaged or
    swapped anchor never turns into a silent unanchored pass."""
    if not path:
        return {}, ""
    if not os.path.exists(path):
        return {}, f"No stored chain heads at `{path}` yet: this run is the first one, and its heads are the anchor for the next run."
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as e:
        raise SystemExit(f"`anchor` file `{path}` is not valid JSON: {e}")
    agents = data.get("agents") if isinstance(data, dict) else None
    heads: dict[str, dict] = {}
    if isinstance(agents, dict):                      # chain-heads.json
        items = agents.items()
    elif isinstance(agents, list):                    # report.json of an earlier run
        items = ((a.get("agent"), a.get("chain_head")) for a in agents if isinstance(a, dict))
    else:
        raise SystemExit(f"`anchor` file `{path}` has no `agents`: pass a chain-heads.json or report.json from an earlier audit.")
    for agent, value in items:
        head = _head(value)
        if isinstance(agent, str) and agent and head:
            heads[agent] = head
    if not heads:
        raise SystemExit(f"`anchor` file `{path}` holds no valid chain head (sequence_no + 64-hex chain_hash).")
    return heads, f"Anchored to {len(heads)} stored chain head{'s' if len(heads) != 1 else ''} from `{path}`."


def run_url() -> str:
    server = z.env("GITHUB_SERVER_URL", "https://github.com")
    repo, run_id = z.env("GITHUB_REPOSITORY"), z.env("GITHUB_RUN_ID")
    return f"{server}/{repo}/actions/runs/{run_id}" if repo and run_id else ""


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def time_range(path: str) -> tuple[str, str, int]:
    first = last = ""
    count = 0
    with open(path, encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            ts = json.loads(line).get("timestamp", "")
            first = first or ts
            last = ts
            count += 1
    return first, last, count


def audit_agent(api: z.Api, agent: str, anchor: dict | None = None) -> dict:
    if anchor:
        chain = api.chain(agent, after_seq=anchor["sequence_no"], anchor=anchor["chain_hash"])
    else:
        chain = api.chain(agent)
    summary = chain.get("summary") or {}
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in agent)
    export = os.path.join(OUT_DIR, "history", f"{safe}.ndjson")
    os.makedirs(os.path.dirname(export), exist_ok=True)
    with open(export, "wb") as f:
        f.write(api.export(agent))
    first, last, exported = time_range(export)
    return {
        "agent": agent,
        "intact": bool(chain.get("intact")),
        "events": summary.get("events", exported),
        "chained": summary.get("chained", 0),
        "deletions": summary.get("tombstones", 0),
        "erasure_receipts": summary.get("receipts", 0),
        "breaks": summary.get("breaks", 0),
        "checksum_mismatches": summary.get("checksum_mismatch", 0),
        "problems": (chain.get("problems") or [])[:20],
        "chain_head": chain.get("chain_head"),
        "anchored_from": anchor,
        "first_event": first,
        "last_event": last,
        "export_file": os.path.relpath(export, OUT_DIR),
        "export_sha256": sha256(export),
        "exported_events": exported,
    }


def missing_agent(agent: str, anchor: dict) -> dict:
    """An agent with a stored head is gone: its whole history was deleted
    (or renamed) since the anchor was written."""
    return {
        "agent": agent, "intact": False, "events": 0, "chained": 0, "deletions": 0,
        "erasure_receipts": 0, "breaks": 1, "checksum_mismatches": 0,
        "problems": [{"sequence_no": anchor["sequence_no"], "problem": "agent_missing"}],
        "chain_head": None, "anchored_from": anchor, "first_event": "", "last_event": "",
        "export_file": "", "export_sha256": "", "exported_events": 0,
    }


def next_heads(results: list[dict], anchors: dict[str, dict]) -> dict[str, dict]:
    """The heads the next run starts from. An intact agent moves its head
    forward; a broken one keeps its stored head, so a break is reported again
    next time instead of becoming the new trusted starting point."""
    heads = dict(anchors)
    for r in results:
        head = _head(r.get("chain_head"))
        if r["intact"] and head:
            heads[r["agent"]] = head
    return dict(sorted(heads.items()))


PROBLEMS = {
    "checksum_mismatch": "content changed after it was recorded",
    "chain_break": "chain link broken: an event was inserted, removed or reordered",
    "checksum_missing": "event has no checksum",
    "anchor_mismatch": "history before the stored chain head was rewritten",
    "head_mismatch": "the newest recorded link is missing: recent events were removed",
    "tombstone_missing_checksum": "deletion record is incomplete",
    "unchained_after_chain_start": "event added outside the chain",
    "agent_missing": "the agent and its history are gone since the stored chain head",
}


def describe_problem(p) -> str:
    if not isinstance(p, dict):
        return z.short(p, 200)
    kind = str(p.get("problem", "problem"))
    where = f"event #{p['sequence_no']}" if p.get("sequence_no") is not None else "event"
    if p.get("event_id"):
        where += f" (`{str(p['event_id'])[:8]}`)"
    return f"{where}: {PROBLEMS.get(kind, kind.replace('_', ' '))}"


def report_markdown(results: list[dict], meta: dict) -> str:
    ok = all(r["intact"] for r in results)
    verdict = "✅ History intact" if ok else "❌ History changed or incomplete"
    lines = [
        f"# ZizkaDB audit report: {verdict}\n",
        f"Generated {meta['generated_at']} by [ZizkaDB Audit](https://github.com/ZIZKA-AI-SL/zizkadb-audit-action) "
        f"with [ZizkaDB]({z.REPO_URL}), the open-source causal database for AI agents.\n",
        "| | |", "|---|---|",
        f"| Repository | `{meta['repository'] or 'local'}` |",
        f"| Commit | `{meta['commit'][:12] or '-'}` |",
        f"| Workflow run | {meta['run_url'] or '-'} |",
        f"| ZizkaDB | `{meta['zizkadb']}` |",
        f"| Agents | {len(results)} |\n",
        "## Hash-chain verification\n",
        "| Agent | Result | Checked from | Events | Deletions (tombstones) | Breaks | Checksum mismatches | First event | Last event |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for r in results:
        lines.append(
            f"| `{r['agent']}` | {'✅ intact' if r['intact'] else '❌ broken'} | {anchor_label(r)} | {r['events']} | "
            f"{r['deletions']} | {r['breaks']} | {r['checksum_mismatches']} | "
            f"{r['first_event'][:19] or '-'} | {r['last_event'][:19] or '-'} |")
    if meta.get("anchor_note"):
        lines.append(f"\n{meta['anchor_note']}")
    broken = [r for r in results if not r["intact"]]
    if broken:
        lines.append("\n## Problems found\n")
        for r in broken:
            lines.append(f"**`{r['agent']}`**\n")
            for p in r["problems"]:
                lines.append(f"- {describe_problem(p)}")
            lines.append("")
    lines += [
        "\n## Exported history\n",
        "| File | Events | SHA-256 |", "|---|---|---|",
    ]
    for r in results:
        if r["export_file"]:
            lines.append(f"| `{r['export_file']}` | {r['exported_events']} | `{r['export_sha256']}` |")
    lines += [
        f"\n## Chain heads for the next audit\n\n`{HEADS_FILE}` holds each agent's newest link. "
        "Store it outside ZizkaDB (for example committed to this repository) and pass it as `anchor` "
        "next time: the next audit then proves that nothing up to these heads was rewritten, "
        "even by someone who rebuilt the whole chain inside the database. A broken agent keeps "
        "its old head, so the break is not trusted later.\n",
        "## What this evidence supports\n",
        "- **Automatic recording of events** over the agent's operation, with timestamps "
        "(EU AI Act Article 12 record-keeping).",
        "- **Traceability** of each decision to its cause through recorded parent links.",
        "- **Integrity:** every event carries a checksum and a per-agent hash chain; deletions "
        "leave tombstones, so edits, insertions and silent deletions show up as breaks.",
        f"\n---\n{z.FOOTER}",
    ]
    return "\n".join(lines) + "\n"


def anchor_label(r: dict) -> str:
    a = r.get("anchored_from")
    return f"🔗 stored head #{a['sequence_no']}" if a else "first event (no anchor)"


def summary_markdown(results: list[dict], anchor_note: str = "") -> str:
    ok = all(r["intact"] for r in results)
    rows = "\n".join(
        f"| `{r['agent']}` | {'✅ intact' if r['intact'] else '❌ broken'} | {anchor_label(r)} | {r['events']} | {r['deletions']} | {r['breaks']} |"
        for r in results)
    problems = [f"- `{r['agent']}`: {describe_problem(p)}" for r in results if not r["intact"] for p in r["problems"][:5]]
    return (
        f"### ZizkaDB Audit: {'✅ agent history intact' if ok else '❌ agent history changed or incomplete'}\n\n"
        "| Agent | Hash chain | Checked from | Events | Deletions | Breaks |\n|---|---|---|---|---|---|\n"
        f"{rows}\n\n"
        + ("\n".join(problems) + "\n\n" if problems else "")
        + (f"{anchor_note}\n\n" if anchor_note else "")
        + 
        "The full report, `report.json` and the exported history are in the **`zizkadb-audit`** artifact"
        f" of this run{', with a GitHub attestation on the report' if z.truthy('INPUT_ATTEST') else ''}.\n"
        f"<sub>How the hash chain works: [ZizkaDB security docs]({z.REPO_URL}/blob/main/docs/security/assessment.md)</sub>\n"
    )


def main() -> int:
    command = z.env("INPUT_RUN")
    host = z.env("INPUT_HOST")
    key = z.env("INPUT_API_KEY")
    image = z.env("INPUT_IMAGE", "ghcr.io/zizka-ai-sl/zizkadb:latest")

    if not host:
        if not command:
            raise SystemExit("Set `run` (the command that runs your agent), or `host` and `api-key` for an existing ZizkaDB.")
        host = z.start_local(image)
        key = z.LOCAL_KEY
        zizkadb = image
    else:
        if not key:
            raise SystemExit("`api-key` is required with `host`.")
        zizkadb = host
    zenv = {"ZIZKADB_HOST": host, "ZIZKADB_API_KEY": key}
    z.export_env(zenv)

    anchors, anchor_note = load_anchors(z.env("INPUT_ANCHOR"))
    exit_code, output = (z.run_command(command, zenv) if command else (0, ""))
    api = z.Api(host, key)
    try:
        agents = [a["agent"] for a in api.agents()]
        wanted = [a.strip() for a in z.env("INPUT_AGENTS").split(",") if a.strip()]
        if wanted:
            agents = [a for a in agents if a in wanted]
        results = [audit_agent(api, a, anchors.get(a)) for a in agents]
        results += [missing_agent(a, h) for a, h in sorted(anchors.items())
                    if a not in agents and (not wanted or a in wanted)]
    except (urllib.error.URLError, OSError) as e:
        z.write_summary(f"### ZizkaDB Audit\n\nCould not read from ZizkaDB at `{host}`: {e}\n\n{z.FOOTER}")
        return exit_code or 1

    if not results:
        z.write_summary(
            "### ZizkaDB Audit: no agent history to verify\n\n"
            "Your command ran, but no agent logged to ZizkaDB. `ZIZKADB_HOST` and `ZIZKADB_API_KEY` "
            f"are set for it; [connect your agent]({z.CONNECT_URL}) and run again.\n\n{z.FOOTER}")
        z.set_output("intact", "")
        z.set_output("command-exit-code", str(exit_code))
        return exit_code

    os.makedirs(OUT_DIR, exist_ok=True)
    meta = {
        "generated_at": z.now_iso(),
        "repository": z.env("GITHUB_REPOSITORY"),
        "commit": z.env("GITHUB_SHA"),
        "run_url": run_url(),
        "zizkadb": zizkadb,
        "anchor_note": anchor_note,
    }
    with open(os.path.join(OUT_DIR, "report.md"), "w", encoding="utf-8") as f:
        f.write(report_markdown(results, meta))
    with open(os.path.join(OUT_DIR, "report.json"), "w", encoding="utf-8") as f:
        json.dump({**meta, "intact": all(r["intact"] for r in results), "agents": results}, f, indent=2)
    heads = next_heads(results, anchors)
    with open(os.path.join(OUT_DIR, HEADS_FILE), "w", encoding="utf-8") as f:
        json.dump({"version": HEADS_VERSION, **{k: meta[k] for k in ("generated_at", "repository", "commit", "run_url")},
                   "agents": heads}, f, indent=2)
        f.write("\n")
    z.save_history(api, [], os.path.join(OUT_DIR, "history"))  # import helper next to the files

    summary = summary_markdown(results, anchor_note)
    if z.agent_limit_hit(output):
        summary += "\n" + z.agent_limit_markdown()
    artifact = z.artifact_name("zizkadb-audit")
    summary = summary.replace("**`zizkadb-audit`** artifact", f"**`{artifact}`** artifact")
    summary += f"\n{z.open_locally_markdown(artifact)}\n{z.FOOTER}"
    z.write_summary(summary)
    status = z.upsert_pr_comment(MARKER, summary) if z.truthy("INPUT_COMMENT") else "disabled"
    z.log(f"PR comment: {status}")

    intact = all(r["intact"] for r in results)
    z.set_output("intact", "true" if intact else "false")
    z.set_output("agents", str(len(results)))
    z.set_output("events", str(sum(r["events"] for r in results)))
    z.set_output("report", os.path.join(OUT_DIR, "report.md"))
    z.set_output("artifact-name", artifact)
    z.set_output("chain-heads", os.path.join(OUT_DIR, HEADS_FILE))
    z.set_output("anchored", str(sum(1 for r in results if r.get("anchored_from"))))
    z.set_output("command-exit-code", str(exit_code))
    if exit_code:
        return exit_code
    if not intact and z.truthy("INPUT_FAIL_ON_BROKEN"):
        print("::error::ZizkaDB hash chain is broken: the recorded history was changed or is incomplete.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
