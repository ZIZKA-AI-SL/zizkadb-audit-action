"""End-to-end tests of anchored audits (standard library only).

A small stand-in for the ZizkaDB REST API serves /v1/agents, /v1/events/chain and
/v1/events/export with the same chain rule as ZizkaDB
(chain_hash = sha256(prev + ":" + checksum), resume from after_seq + anchor),
and src/audit.py runs against it exactly as the action runs it.

    python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

def read(path: str) -> str:
    with open(path, encoding="utf-8") as f:
        return f.read()


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AUDIT = os.path.join(ROOT, "src", "audit.py")


def link(prev: str, checksum: str) -> str:
    return hashlib.sha256(f"{prev}:{checksum}".encode()).hexdigest()


class Store:
    """In-memory agents and their chained events."""

    def __init__(self):
        self.agents: dict[str, list[dict]] = {}

    def log(self, agent: str, text: str, salt: str = "") -> dict:
        events = self.agents.setdefault(agent, [])
        seq = (events[-1]["sequence_no"] if events else 0) + 1
        checksum = hashlib.sha256(f"{salt}{agent}:{seq}:{text}".encode()).hexdigest()
        prev = events[-1]["chain_hash"] if events else ""
        event = {"event_id": f"00000000-0000-0000-0000-{seq:012d}", "agent": agent, "event": "step",
                 "data": {"text": text}, "sequence_no": seq, "timestamp": f"2026-11-01T10:00:{seq:02d}+00:00",
                 "checksum": checksum, "chain_hash": link(prev, checksum)}
        events.append(event)
        return event

    def rewrite(self, agent: str, texts: list[str]) -> None:
        """A database writer replaces the whole history and recomputes every
        checksum and link: the chain is consistent again on its own."""
        self.agents[agent] = []
        for t in texts:
            self.log(agent, t, salt="forged:")

    def verify(self, agent: str, after_seq: int | None, anchor: str | None) -> dict:
        events = self.agents.get(agent, [])
        problems = []
        prev = anchor or ""
        if anchor is not None:
            at = next((e for e in events if e["sequence_no"] == after_seq), None)
            if at is None or at["chain_hash"] != anchor:
                problems.append({"sequence_no": after_seq, "problem": "anchor_mismatch"})
        walked = [e for e in events if e["sequence_no"] > (after_seq or 0)]
        for e in walked:
            if e["chain_hash"] != link(prev, e["checksum"]):
                problems.append({"sequence_no": e["sequence_no"], "event_id": e["event_id"], "problem": "chain_break"})
            prev = e["chain_hash"]
        if walked:
            head = {"sequence_no": walked[-1]["sequence_no"], "chain_hash": walked[-1]["chain_hash"]}
        elif anchor is not None and not problems:
            head = {"sequence_no": after_seq, "chain_hash": anchor}
        else:
            head = None
        breaks = sum(1 for p in problems if p["problem"] != "checksum_mismatch")
        return {"intact": not problems, "problems": problems, "chain_head": head,
                "summary": {"events": len(walked), "chained": len(walked), "tombstones": 0,
                            "receipts": 0, "breaks": breaks, "checksum_mismatch": 0}}


class Handler(BaseHTTPRequestHandler):
    store: Store = None  # set per server

    def log_message(self, *args):  # quiet
        pass

    def _send(self, code: int, body: bytes, kind: str = "application/json"):
        self.send_response(code)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.headers.get("Authorization") != "Bearer test-key":
            return self._send(401, b'{"detail":"bad key"}')
        url = urllib.parse.urlparse(self.path)
        q = {k: v[0] for k, v in urllib.parse.parse_qs(url.query).items()}
        if url.path == "/v1/agents":
            return self._send(200, json.dumps([{"agent": a} for a in self.store.agents]).encode())
        if url.path == "/v1/events/chain":
            after = int(q["after_seq"]) if "after_seq" in q else None
            return self._send(200, json.dumps(self.store.verify(q["agent"], after, q.get("anchor"))).encode())
        if url.path == "/v1/events/export":
            lines = "".join(json.dumps(e) + "\n" for e in self.store.agents.get(q["agent"], []))
            return self._send(200, lines.encode(), "application/x-ndjson")
        return self._send(404, b'{"detail":"not found"}')


class AnchoredAuditTest(unittest.TestCase):
    def setUp(self):
        self.store = Store()
        handler = type("H", (Handler,), {"store": self.store})
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.host = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.tmp = tempfile.TemporaryDirectory()
        self.work = self.tmp.name

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()

    def audit(self, anchor: str = "", **extra) -> tuple[int, dict, dict, str]:
        out = os.path.join(self.work, "out.txt")
        summary = os.path.join(self.work, "summary.md")
        for p in (out, summary):
            open(p, "w").close()
        env = {**os.environ, "INPUT_HOST": self.host, "INPUT_API_KEY": "test-key", "INPUT_ANCHOR": anchor,
               "INPUT_COMMENT": "false", "INPUT_ATTEST": "false", "INPUT_FAIL_ON_BROKEN": "true",
               "GITHUB_OUTPUT": out, "GITHUB_STEP_SUMMARY": summary, "GITHUB_ENV": os.path.join(self.work, "env"),
               "GITHUB_REPOSITORY": "acme/agents", "GITHUB_SHA": "a" * 40, "GITHUB_RUN_ID": "1", **extra}
        r = subprocess.run([sys.executable, AUDIT], cwd=self.work, env=env, capture_output=True, text=True)
        outputs = dict(line.split("=", 1) for line in read(out).splitlines() if "=" in line)
        report_path = os.path.join(self.work, "zizkadb-audit", "report.json")
        report = json.loads(read(report_path)) if os.path.exists(report_path) else {}
        return r.returncode, outputs, report, r.stdout + r.stderr + read(summary)

    def heads_path(self) -> str:
        return os.path.join(self.work, "zizkadb-audit", "chain-heads.json")

    def keep_heads(self) -> str:
        """Store the heads outside the run's output folder, as a workflow would."""
        kept = os.path.join(self.work, "stored-heads.json")
        with open(self.heads_path()) as src, open(kept, "w") as dst:
            dst.write(src.read())
        return kept

    # ── tests ───────────────────────────────────────────────────────────────

    def test_first_run_without_anchor_file_writes_heads(self):
        for t in ("ask", "think", "act"):
            self.store.log("refund-agent", t)
        code, out, report, text = self.audit(anchor=os.path.join(self.work, "missing.json"))
        self.assertEqual(code, 0, text)
        self.assertEqual(out["intact"], "true")
        self.assertEqual(out["anchored"], "0")
        heads = json.loads(read(self.heads_path()))
        self.assertEqual(heads["version"], 1)
        self.assertEqual(heads["agents"]["refund-agent"]["sequence_no"], 3)
        self.assertIn("first one", text)

    def test_anchored_run_checks_only_new_events_and_moves_the_head(self):
        for t in ("ask", "think"):
            self.store.log("refund-agent", t)
        self.audit()
        stored = self.keep_heads()
        self.store.log("refund-agent", "act")
        code, out, report, text = self.audit(anchor=stored)
        self.assertEqual(code, 0, text)
        self.assertEqual(out["anchored"], "1")
        agent = report["agents"][0]
        self.assertEqual(agent["anchored_from"]["sequence_no"], 2)
        self.assertEqual(agent["events"], 1)
        self.assertEqual(json.loads(read(self.heads_path()))["agents"]["refund-agent"]["sequence_no"], 3)
        self.assertIn("stored head #2", text)

    def test_full_rewrite_passes_alone_but_fails_from_the_anchor(self):
        for t in ("ask", "think", "refund 900 EUR"):
            self.store.log("refund-agent", t)
        self.audit()
        stored = self.keep_heads()
        self.store.rewrite("refund-agent", ["ask", "think", "refund 9 EUR", "close"])
        code, out, _, text = self.audit()                      # the chain is consistent on its own
        self.assertEqual((code, out["intact"]), (0, "true"), text)
        code, out, report, text = self.audit(anchor=stored)    # but not from the stored head
        self.assertEqual(code, 1, text)
        self.assertEqual(out["intact"], "false")
        self.assertEqual(report["agents"][0]["problems"][0]["problem"], "anchor_mismatch")
        self.assertIn("rewritten", text)

    def test_broken_agent_keeps_its_old_head(self):
        for t in ("ask", "think"):
            self.store.log("refund-agent", t)
        self.audit()
        stored = self.keep_heads()
        old = json.loads(read(stored))["agents"]["refund-agent"]
        self.store.rewrite("refund-agent", ["ask", "think", "act"])
        code, _, _, _ = self.audit(anchor=stored)
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(read(self.heads_path()))["agents"]["refund-agent"], old)

    def test_deleted_agent_is_reported(self):
        self.store.log("refund-agent", "ask")
        self.audit()
        stored = self.keep_heads()
        del self.store.agents["refund-agent"]
        self.store.log("new-agent", "hello")
        code, out, report, text = self.audit(anchor=stored)
        self.assertEqual(code, 1, text)
        gone = next(a for a in report["agents"] if a["agent"] == "refund-agent")
        self.assertEqual(gone["problems"][0]["problem"], "agent_missing")
        self.assertIn("gone since the stored chain head", text)

    def test_earlier_report_json_works_as_anchor(self):
        self.store.log("refund-agent", "ask")
        self.audit()
        report = os.path.join(self.work, "old-report.json")
        with open(os.path.join(self.work, "zizkadb-audit", "report.json")) as src, open(report, "w") as dst:
            dst.write(src.read())
        self.store.log("refund-agent", "act")
        code, out, _, text = self.audit(anchor=report)
        self.assertEqual((code, out["anchored"]), (0, "1"), text)

    def test_unreadable_anchor_stops_the_audit(self):
        bad = os.path.join(self.work, "bad.json")
        for content in ("{not json", '{"agents": {"a": {"sequence_no": 1, "chain_hash": "xyz"}}}'):
            with open(bad, "w") as f:
                f.write(content)
            self.store.log("refund-agent", "ask")
            code, _, _, text = self.audit(anchor=bad)
            self.assertNotEqual(code, 0)
            self.assertIn("anchor", text)


if __name__ == "__main__":
    unittest.main()
