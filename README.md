# ZizkaDB Audit: prove your AI agent's history is intact

> Part of **[ZizkaDB](https://github.com/ZIZKA-AI-SL/ZizkaDB)**, the open-source causal database for AI agents.

[![OpenSSF Baseline](https://www.bestpractices.dev/projects/16048/baseline)](https://www.bestpractices.dev/projects/16048)
[![ZizkaDB](https://img.shields.io/github/stars/ZIZKA-AI-SL/ZizkaDB?label=ZizkaDB&style=flat)](https://github.com/ZIZKA-AI-SL/ZizkaDB)

Auditors, incident reviews and the EU AI Act ask the same question: **can you show what your agent did, and prove the record was not changed afterwards?** This action records your agent's run in ZizkaDB, checks every agent's hash chain, and produces an audit report with the exported history, attested by GitHub.

| Agent | Hash chain | Events | Deletions | Breaks |
|---|---|---|---|---|
| `refund-agent` | ✅ intact | 5 | 0 | 0 |

If an event was edited, inserted, reordered or deleted without a tombstone, the check reports **❌ broken**, names the event, and fails the step.

## Quick start

```yaml
permissions:
  contents: read
  pull-requests: write   # PR comment
  id-token: write        # attestation
  attestations: write    # attestation

jobs:
  agent-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install -r requirements.txt zizkadb-sdk
      - uses: ZIZKA-AI-SL/zizkadb-audit-action@v1
        with:
          run: pytest tests/agent
```

The action:

1. **Starts ZizkaDB inside the runner** (the open-source single container). No account, no secrets; **the data never leaves the runner**.
2. **Runs your command** with `ZIZKADB_HOST` and `ZIZKADB_API_KEY` set, so the ZizkaDB SDK in your agent records there.
3. **Verifies each agent's hash chain**: every event's checksum and its link to the previous event, plus tombstones for deletions.
4. **Exports the full history** (NDJSON) with a SHA-256 per file.
5. **Writes `report.md` and `report.json`** and adds a **GitHub artifact attestation**, so anyone can later check that this workflow run produced them, unchanged:

   ```bash
   gh attestation verify report.md -R your-org/your-repo
   ```
6. **Uploads** everything as a `zizkadb-audit-…` artifact (the summary names it; kept 90 days; download and archive it for longer retention), and posts a summary in the job summary and on the pull request.

## Audit a running ZizkaDB

Point it at your self-hosted ZizkaDB, for example on a schedule:

```yaml
on:
  schedule: [{ cron: "0 6 * * 1" }]   # every Monday
jobs:
  audit:
    runs-on: ubuntu-latest
    permissions: { contents: read, id-token: write, attestations: write }
    steps:
      - uses: ZIZKA-AI-SL/zizkadb-audit-action@v1
        with:
          host: https://zizkadb.example.com
          api-key: ${{ secrets.ZIZKADB_API_KEY }}
```

## Catch a full rewrite: anchor each audit to the last one

A hash chain proves the history is consistent **with itself**. Someone with write access to the database could still rebuild the whole chain, every checksum and link recomputed, and a plain check would pass. The fix is a fixed point outside the database: the chain head of the last audit.

Every audit writes `chain-heads.json` (each agent's newest link, attested with the report). Pass the last one back as `anchor`, and each agent is checked **from its stored head**:

- a rewrite of anything up to that head fails with `anchor_mismatch`, even when the new chain is consistent;
- an agent whose whole history disappeared fails with `agent_missing`;
- only the events since the last audit are walked, so a weekly audit stays fast as the history grows;
- a broken agent keeps its old head in the new file, so a break is reported again next time, never trusted as the new starting point.

Store the heads where the database writer cannot reach them. Git works well: every change is a reviewed, attributed commit, and the attestation proves each heads file came from this workflow.

```yaml
on:
  schedule: [{ cron: "0 6 * * 1" }]   # every Monday
  workflow_dispatch:
permissions:
  contents: write        # commit the new heads
  id-token: write        # attestation
  attestations: write    # attestation
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      # Trust the stored heads only if this repository's audit workflow produced them.
      - name: Verify the stored heads
        if: hashFiles('.zizkadb/chain-heads.json') != ''
        env: { GH_TOKEN: "${{ github.token }}" }
        run: gh attestation verify .zizkadb/chain-heads.json -R "$GITHUB_REPOSITORY"
      - id: audit
        uses: ZIZKA-AI-SL/zizkadb-audit-action@v1
        with:
          host: https://zizkadb.example.com
          api-key: ${{ secrets.ZIZKADB_API_KEY }}
          anchor: .zizkadb/chain-heads.json      # missing on the first run: that run starts the anchor
      - name: Store the new heads
        if: always() && steps.audit.outputs.chain-heads != ''
        run: |
          mkdir -p .zizkadb && cp "${{ steps.audit.outputs.chain-heads }}" .zizkadb/chain-heads.json
          git config user.name "github-actions[bot]"
          git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
          git add .zizkadb/chain-heads.json
          git commit -m "ZizkaDB audit: chain heads of run ${{ github.run_id }}" || exit 0
          git push
```

An earlier `report.json` works as `anchor` too.

## What the report contains

- Repository, commit, workflow run and ZizkaDB version
- Per agent: result, events, deletions (tombstones), breaks, checksum mismatches, first and last event
- The problems found, in plain language, with event numbers
- The exported history files and their SHA-256
- Where each agent was checked from: its first event, or a stored chain head (`anchor`)
- Each agent's chain head (`report.json` and `chain-heads.json`), to store outside ZizkaDB and pass back as `anchor`
- What the evidence supports: automatic recording of events with timestamps (EU AI Act Article 12 record-keeping), traceability of each decision to its cause, and integrity of the record

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `run` | | Command that runs your agent or its tests. Required unless `host` is set. |
| `host` | | Audit an existing ZizkaDB instead of a local one. |
| `api-key` | | API key for `host`; pass it from a secret. |
| `agents` | all | Comma-separated agent names to audit. |
| `anchor` | | Path to the chain heads of an earlier audit (`chain-heads.json` or `report.json`). Each agent is checked from its stored head; a missing file is a first run. |
| `fail-on-broken` | `true` | Fail the step when a hash chain is broken. |
| `attest` | `true` | Attest the report and history (needs `id-token: write`, `attestations: write`). |
| `comment` | `true` | Post and update a PR comment (needs `pull-requests: write`). |
| `artifact-name` | `zizkadb-audit-<job>-<random>` | Name of the uploaded artifact; unique by default so matrix jobs and repeated steps do not collide. |
| `image` | `ghcr.io/zizka-ai-sl/zizkadb:latest` | ZizkaDB image for the local instance; pin a version for reproducible runs. |
| `github-token` | `${{ github.token }}` | Token used for the PR comment. |

## Outputs

| Output | Description |
|--------|-------------|
| `intact` | `true` if every chain is intact, `false` if not, empty if nothing was recorded |
| `agents` | Agents audited |
| `events` | Events verified |
| `report` | Path of `report.md` |
| `artifact-name` | Name of the uploaded audit artifact |
| `chain-heads` | Path of `chain-heads.json`: the anchor for the next audit |
| `anchored` | Agents checked from a stored chain head |
| `command-exit-code` | Exit code of `run` |

## Good to know

- **One agent per run** on the local instance: open-source ZizkaDB records one agent per install. Multiple agents, fleets and agent-to-agent recording are in [ZizkaDB Cloud](https://db.zizka.ai).
- **Telemetry.** The ZizkaDB SDK in your agent sends an anonymous install count; set `ZIZKADB_TELEMETRY: "false"` in the job's `env` to turn it off. [Details](https://github.com/ZIZKA-AI-SL/ZizkaDB/blob/main/docs/telemetry.md).
- **Why did the agent fail?** Use [ZizkaDB Why](https://github.com/ZIZKA-AI-SL/zizkadb-why-action) for causal chains in your PR.
- **In your editor:** the same Why and Audit answers in Claude Code and other coding agents: [ZizkaDB skills](https://github.com/ZIZKA-AI-SL/zizkadb-skills).
- How the hash chain works: [ZizkaDB security docs](https://github.com/ZIZKA-AI-SL/ZizkaDB/blob/main/docs/security/assessment.md).

## Beyond CI

ZizkaDB runs on your own servers too: a tamper-evident audit log, causal `why()`, time travel, agent memory and search, on Postgres.

**[⭐ Star ZizkaDB on GitHub](https://github.com/ZIZKA-AI-SL/ZizkaDB)** · [Run it locally in 60 seconds](https://github.com/ZIZKA-AI-SL/ZizkaDB#quickstart-60-seconds) · [Docs](https://db.zizka.ai/docs)

---

MIT licensed. Security issues: founder@zizka.ai ([policy](https://github.com/ZIZKA-AI-SL/ZizkaDB/blob/main/SECURITY.md)).
