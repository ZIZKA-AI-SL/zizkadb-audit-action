"""Shared helpers for the ZizkaDB GitHub Actions (standard library only).

Starts a throwaway ZizkaDB in the runner, runs the user's command against it,
talks to the REST API, and writes job summaries, outputs and PR comments.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

REPO_URL = "https://github.com/ZIZKA-AI-SL/ZizkaDB"
DOCS_URL = f"{REPO_URL}/blob/main/docs/integrate/github-actions.md"
CONNECT_URL = f"{REPO_URL}/blob/main/CONNECT.md"
CLOUD_URL = "https://db.zizka.ai"
# Well-known key the image accepts in ENV=development; the container is
# reachable only from this runner (127.0.0.1) and deleted with the job.
LOCAL_KEY = "zizkadb_dev_local"
CONTAINER = "zizkadb-action"
FOOTER = (
    f"<sub>Recorded by [ZizkaDB]({REPO_URL}), the open-source causal database "
    f"for AI agents · [⭐ Star on GitHub]({REPO_URL}) · "
    f"[How this works]({DOCS_URL})</sub>"
)


def log(msg: str) -> None:
    print(f"[zizkadb] {msg}", flush=True)


def env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


def truthy(name: str, default: str = "true") -> bool:
    return env(name, default).lower() in ("1", "true", "yes", "on")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def artifact_name(default_base: str) -> str:
    """The input name, or `<base>-<job>-<random>`: unique when the action runs
    more than once in a workflow run (matrix jobs, repeated steps)."""
    chosen = env("INPUT_ARTIFACT_NAME")
    if chosen:
        return chosen
    job = "".join(c if c.isalnum() or c in "-_" else "-" for c in env("GITHUB_JOB", "job"))[:40]
    return f"{default_base}-{job}-{os.urandom(3).hex()}"


# ── ZizkaDB lifecycle ───────────────────────────────────────────────────────

def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start_local(image: str, timeout: int = 180) -> str:
    """Run the open-source single-container image; return its API URL."""
    subprocess.run(["docker", "rm", "-f", CONTAINER], capture_output=True)
    port = _free_port()
    log(f"Starting ZizkaDB ({image}) on 127.0.0.1:{port} ...")
    subprocess.run(
        [
            "docker", "run", "-d", "--name", CONTAINER,
            "-e", "ENV=development",
            # The action reports on the user's agent; a demo agent would take
            # the self-hosted install's single agent slot.
            "-e", "ZIZKADB_SEED_DEMO=false",
            "-p", f"127.0.0.1:{port}:8000",
            image,
        ],
        check=True, stdout=subprocess.DEVNULL,
    )
    host = f"http://127.0.0.1:{port}"
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{host}/health", timeout=3) as r:
                if r.status == 200:
                    log(f"ZizkaDB is ready at {host}")
                    return host
        except OSError:
            pass
        running = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", CONTAINER],
            capture_output=True, text=True,
        ).stdout.strip()
        if running != "true":
            break
        time.sleep(2)
    logs = subprocess.run(["docker", "logs", "--tail", "40", CONTAINER],
                          capture_output=True, text=True)
    sys.stderr.write(logs.stdout + logs.stderr)
    raise SystemExit("ZizkaDB did not start. The last container log lines are above.")


def run_command(command: str, extra_env: dict[str, str]) -> tuple[int, str]:
    """Run the user's command with ZIZKADB_* set; stream and capture output."""
    log(f"Running: {command}")
    proc = subprocess.Popen(
        ["bash", "-o", "pipefail", "-c", command],
        env={**os.environ, **extra_env},
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
    )
    captured: list[str] = []
    assert proc.stdout is not None
    for line in proc.stdout:
        sys.stdout.write(line)
        captured.append(line)
        if len(captured) > 20000:
            captured = captured[-10000:]
    proc.wait()
    log(f"Command exited with code {proc.returncode}")
    return proc.returncode, "".join(captured)


def agent_limit_hit(output: str) -> bool:
    """Self-hosted ZizkaDB is one agent per install; the API answers 409."""
    return "agent_limit_reached" in output


# ── REST API ────────────────────────────────────────────────────────────────

class Api:
    def __init__(self, host: str, key: str):
        self.host = host.rstrip("/")
        self.key = key

    def _req(self, method: str, path: str, params: dict | None = None,
             body: dict | None = None, raw: bool = False):
        url = self.host + path
        if params:
            url += "?" + urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers={
            "Authorization": f"Bearer {self.key}",
            "Content-Type": "application/json",
            "User-Agent": "zizkadb-github-action",
        })
        with urllib.request.urlopen(req, timeout=60) as r:
            payload = r.read()
        return payload if raw else json.loads(payload or b"null")

    def agents(self) -> list[dict]:
        return self._req("GET", "/v1/agents") or []

    def events(self, agent: str, after: str | None = None, limit: int = 500) -> list[dict]:
        out = self._req("GET", "/v1/events", {"agent": agent, "limit": limit, "after": after})
        return out if isinstance(out, list) else (out or {}).get("events", [])

    def why(self, event_id: str, depth: int = 25) -> dict:
        return self._req("GET", f"/v1/events/{event_id}/why", {"depth": depth})

    def chain(self, agent: str, after_seq: int | None = None, anchor: str | None = None) -> dict:
        """Hash-chain check. With ``after_seq`` + ``anchor`` (a stored chain head) it
        resumes from that head and proves nothing before it was rewritten."""
        return self._req("GET", "/v1/events/chain",
                         {"agent": agent, "after_seq": after_seq, "anchor": anchor})

    def export(self, agent: str) -> bytes:
        return self._req("GET", "/v1/events/export", {"agent": agent}, raw=True)


# ── Output ──────────────────────────────────────────────────────────────────

def write_summary(markdown: str) -> None:
    path = env("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write(markdown + "\n")
    else:
        print(markdown)


def set_output(name: str, value: str) -> None:
    path = env("GITHUB_OUTPUT")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as f:
        if "\n" in value:
            f.write(f"{name}<<ZIZKADB_EOF\n{value}\nZIZKADB_EOF\n")
        else:
            f.write(f"{name}={value}\n")


def export_env(values: dict[str, str]) -> None:
    """Make ZIZKADB_* available to later steps of the job."""
    path = env("GITHUB_ENV")
    if path:
        with open(path, "a", encoding="utf-8") as f:
            for k, v in values.items():
                f.write(f"{k}={v}\n")


def _pr_number() -> int | None:
    path = env("GITHUB_EVENT_PATH")
    if not path or not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        event = json.load(f)
    pr = event.get("pull_request") or {}
    return pr.get("number")


def upsert_pr_comment(marker: str, body: str) -> str:
    """Create or update this action's comment on the pull request.

    Returns a short status for the summary; never raises (fork PRs get a
    read-only token, which is expected)."""
    token = env("INPUT_GITHUB_TOKEN")
    number = _pr_number()
    repo = env("GITHUB_REPOSITORY")
    if not (token and number and repo):
        return "skipped (not a pull request)"
    api = env("GITHUB_API_URL", "https://api.github.com")
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "zizkadb-github-action",
    }
    full = f"{marker}\n{body}"
    try:
        req = urllib.request.Request(
            f"{api}/repos/{repo}/issues/{number}/comments?per_page=100", headers=headers)
        with urllib.request.urlopen(req, timeout=30) as r:
            existing = next((c for c in json.load(r) if marker in (c.get("body") or "")), None)
        if existing:
            method, url = "PATCH", f"{api}/repos/{repo}/issues/comments/{existing['id']}"
        else:
            method, url = "POST", f"{api}/repos/{repo}/issues/{number}/comments"
        req = urllib.request.Request(url, data=json.dumps({"body": full}).encode(),
                                     method=method, headers=headers)
        urllib.request.urlopen(req, timeout=30).close()
        return "posted"
    except urllib.error.HTTPError as e:
        if e.code in (403, 404):
            return ("not posted: the token cannot write PR comments (fork PR, or add "
                    "`permissions: pull-requests: write`)")
        return f"not posted: GitHub API error {e.code}"
    except OSError as e:
        return f"not posted: {e}"


def short(value, limit: int = 80) -> str:
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def save_history(api: Api, agents: list[str], out_dir: str) -> list[str]:
    """Export each agent's events as NDJSON next to an import helper."""
    os.makedirs(out_dir, exist_ok=True)
    files = []
    for agent in agents:
        safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in agent)
        path = os.path.join(out_dir, f"{safe}.ndjson")
        with open(path, "wb") as f:
            f.write(api.export(agent))
        files.append(path)
    helper = os.path.join(os.path.dirname(os.path.abspath(__file__)), "open_in_dashboard.py")
    with open(helper, encoding="utf-8") as src, \
            open(os.path.join(out_dir, "open_in_dashboard.py"), "w", encoding="utf-8") as dst:
        dst.write(src.read())
    return files


def open_locally_markdown(artifact: str) -> str:
    return (
        "<details><summary><b>Open this run in the ZizkaDB dashboard</b></summary>\n\n"
        f"1. Download the **`{artifact}`** artifact from this workflow run and unzip it.\n"
        "2. Start an empty local ZizkaDB (one container, about a minute):\n\n"
        "   ```bash\n"
        "   docker run -d --name zizkadb-run -e ENV=development -e ZIZKADB_SEED_DEMO=false \\\n"
        "     -p 127.0.0.1:8000:8000 -p 127.0.0.1:3001:3001 ghcr.io/zizka-ai-sl/zizkadb\n"
        "   ```\n"
        "3. Load the recorded history and open the dashboard:\n\n"
        "   ```bash\n"
        "   python3 open_in_dashboard.py *.ndjson\n"
        "   ```\n\n"
        f"Click any event, then **Why? (causal)**. More: [{REPO_URL.split('//')[1]}]({REPO_URL})\n"
        "</details>\n"
    )


def agent_limit_markdown() -> str:
    return (
        "> [!NOTE]\n"
        "> **A second agent was refused.** This action runs the open-source ZizkaDB, "
        "which records **one agent per install**; the first agent your tests logged was "
        "recorded, later agents got `409 agent_limit_reached`. Log every step under one "
        f"agent name, or use [ZizkaDB Cloud]({CLOUD_URL}) for multiple agents and fleets.\n"
    )
