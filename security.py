"""
Major Labs Sentinel · static security sweep

READ-ONLY. Fetches public source for catalogued MCP server repos via the GitHub
API and flags security-relevant code patterns. It NEVER connects to, runs,
installs, or probes any MCP server. Findings are heuristic *static* signals
(attack surface visible in the source), tuned for precision, not confirmed
vulnerabilities. Every finding carries the file, line, and snippet so a false
positive is obvious and cheap to dismiss.

Per the publishing decision, only AGGREGATE statistics are surfaced publicly;
per-repo findings stay in the database for coordinated maintainer disclosure.

Run: python3 security.py [--limit N] [--repos owner/name ...]
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import subprocess
import sys
import time
from pathlib import Path

DB_PATH = Path(__file__).parent / "scans.db"

SOURCE_EXT = (".py", ".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx")
SKIP_PATH = re.compile(r"(^|/)(node_modules|dist|build|vendor|\.venv|venv|test|tests|__tests__|examples?|docs?|\.git)/", re.I)
MAX_FILES = 12
MAX_BLOB = 200_000  # skip files larger than this (bytes)

# (category, language, weight, compiled pattern, description). Precision-favoring:
# we flag specific high-signal sinks, accepting that aggregate stats absorb noise.
def _c(p):
    return re.compile(p)

CHECKS = [
    # category, langs, weight, pattern, description
    ("command_injection", {"py"}, 30, _c(r"shell\s*=\s*True"), "subprocess with shell=True"),
    ("command_injection", {"py"}, 30, _c(r"\bos\.(system|popen)\("), "os.system / os.popen"),
    ("command_injection", {"js"}, 30, _c(r"child_process(\.|\s*\.\s*)?(exec|execSync)\s*\("), "child_process.exec"),
    ("command_injection", {"js"}, 30, _c(r"\.exec\s*\(\s*[`'\"]?\$\{|\.exec\s*\(\s*[a-zA-Z_$][\w$]*\s*\+"), "exec with interpolated string"),
    ("code_execution", {"py"}, 30, _c(r"(?<![\w.])eval\s*\(|(?<![\w.])exec\s*\("), "eval/exec"),
    ("code_execution", {"js"}, 30, _c(r"(?<![\w.])eval\s*\(|new\s+Function\s*\(|vm\.runInNewContext"), "eval / new Function / vm"),
    ("unsafe_deserialization", {"py"}, 15, _c(r"pickle\.loads?\s*\(|yaml\.load\s*\((?![^)]*Safe)"), "pickle / unsafe yaml.load"),
    ("ssrf_surface", {"py"}, 20, _c(r"(requests\.(get|post|put|request|delete)|urllib\.request\.urlopen|httpx\.(get|post|client))\s*\(\s*[a-zA-Z_]"), "outbound request to a non-literal URL"),
    ("ssrf_surface", {"js"}, 20, _c(r"(fetch|axios(\.\w+)?|got|http\.request)\s*\(\s*[a-zA-Z_$`]"), "outbound request to a non-literal URL"),
    ("hardcoded_secret", {"py", "js"}, 15, _c(r"(sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,})"), "hardcoded credential"),
    # path_traversal (open(var,'w')) was dropped from v0: too noisy (most file
    # writes are benign). A precise version needs taint tracking, not regex.
]


def lang_of(path: str) -> str:
    return "py" if path.endswith(".py") else "js"


def gh(endpoint: str):
    cmd = ["gh", "api", "-H", "Accept: application/vnd.github+json", endpoint]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        return None
    if r.returncode != 0:
        return None
    try:
        return json.loads(r.stdout) if r.stdout.strip() else None
    except json.JSONDecodeError:
        return None


def rate_limit_wait():
    """Pause until the GitHub core rate limit resets when it runs low, so a long
    run produces clean data instead of a wave of failed (falsely 'clean') fetches.
    The /rate_limit endpoint does not itself count against the limit."""
    data = gh("/rate_limit")
    try:
        core = data["resources"]["core"]
    except (TypeError, KeyError):
        return
    if core.get("remaining", 9999) < 75:
        wait = max(0, int(core.get("reset", 0)) - int(time.time())) + 5
        if wait > 0:
            print(f"  rate limit low ({core['remaining']} left); sleeping {wait}s until reset", flush=True)
            time.sleep(wait)


def init_db(conn):
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS security_findings (
            full_name TEXT, category TEXT, path TEXT, line INTEGER,
            snippet TEXT, weight INTEGER, scanned_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS security_scores (
            full_name TEXT PRIMARY KEY, score INTEGER, tier TEXT,
            files_scanned INTEGER, finding_count INTEGER,
            categories TEXT, scanned_at TEXT DEFAULT (datetime('now'))
        );
        """
    )


def source_files(full_name: str, default_branch: str):
    tree = gh(f"/repos/{full_name}/git/trees/{default_branch}?recursive=1")
    if not isinstance(tree, dict):
        return None  # fetch failed — caller skips (do NOT score as clean)
    picks = []
    for node in tree.get("tree", []):
        if node.get("type") != "blob":
            continue
        path = node.get("path", "")
        if not path.endswith(SOURCE_EXT) or SKIP_PATH.search("/" + path):
            continue
        if (node.get("size") or 0) > MAX_BLOB:
            continue
        # Prefer shallow paths (root, src/) — the real server usually lives there.
        depth = path.count("/")
        picks.append((depth, path))
    picks.sort()
    return [p for _, p in picks[:MAX_FILES]]


def fetch_content(full_name: str, path: str):
    data = gh(f"/repos/{full_name}/contents/{path}")
    if not isinstance(data, dict) or data.get("encoding") != "base64":
        return None
    try:
        return base64.b64decode(data["content"]).decode("utf-8", "replace")
    except Exception:
        return None


def scan_content(path: str, content: str):
    lang = lang_of(path)
    findings = []
    lines = content.splitlines()
    for category, langs, weight, pat, desc in CHECKS:
        if lang not in langs:
            continue
        for m in pat.finditer(content):
            line_no = content.count("\n", 0, m.start()) + 1
            snippet = lines[line_no - 1].strip()[:160] if line_no - 1 < len(lines) else ""
            # Skip obvious comment lines to cut noise.
            if snippet.lstrip().startswith(("#", "//", "*")):
                continue
            findings.append((category, path, line_no, snippet, weight, desc))
    return findings


def score_for(findings) -> tuple:
    cats = {f[0] for f in findings}
    total = sum({  # weight once per category present, not per hit
        c: next(f[4] for f in findings if f[0] == c) for c in cats
    }.values())
    total = min(total, 100)
    tier = "High" if total > 30 else "Elevated" if total > 0 else "Low"
    return total, tier, sorted(cats)


def scan_repo(conn, full_name: str, default_branch: str):
    files = source_files(full_name, default_branch)
    if files is None:
        return None  # tree fetch failed; skip so the aggregate stays honest
    all_findings = []
    for path in files:
        content = fetch_content(full_name, path)
        if content:
            all_findings.extend(scan_content(path, content))
    score, tier, cats = score_for(all_findings)
    conn.execute("DELETE FROM security_findings WHERE full_name=?", (full_name,))
    for category, path, line_no, snippet, weight, _desc in all_findings:
        conn.execute(
            "INSERT INTO security_findings (full_name, category, path, line, snippet, weight) VALUES (?,?,?,?,?,?)",
            (full_name, category, path, line_no, snippet, weight),
        )
    conn.execute(
        "INSERT INTO security_scores (full_name, score, tier, files_scanned, finding_count, categories, scanned_at) "
        "VALUES (?,?,?,?,?,?, datetime('now')) ON CONFLICT(full_name) DO UPDATE SET "
        "score=excluded.score, tier=excluded.tier, files_scanned=excluded.files_scanned, "
        "finding_count=excluded.finding_count, categories=excluded.categories, scanned_at=excluded.scanned_at",
        (full_name, score, tier, len(files), len(all_findings), ",".join(cats)),
    )
    conn.commit()
    return score, tier, len(files), len(all_findings), cats


def main():
    import sqlite3
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0, help="cap repos scanned (0 = all active)")
    ap.add_argument("--repos", nargs="*", help="scan only these owner/name repos")
    args = ap.parse_args()

    conn = sqlite3.connect(DB_PATH, timeout=60)  # wait out the concurrent harvest's commit locks
    conn.execute("PRAGMA busy_timeout=60000")
    init_db(conn)

    if args.repos:
        rows = [(r, "main") for r in args.repos]
        # try to get real default branch
        rows = [(r, (gh(f"/repos/{r}") or {}).get("default_branch", "main")) for r in args.repos]
    else:
        q = ("SELECT full_name, default_branch FROM repos WHERE archived=0 AND fork=0 "
             "AND pushed_at > date('now','-180 day') ORDER BY stargazers_count DESC")
        if args.limit:
            q += f" LIMIT {args.limit}"
        rows = [(r[0], r[1] or "main") for r in conn.execute(q)]

    print(f"security sweep (READ-ONLY static analysis): {len(rows)} repos\n")
    skipped = 0
    for i, (full_name, branch) in enumerate(rows, 1):
        rate_limit_wait()
        try:
            result = scan_repo(conn, full_name, branch)
            if result is None:
                skipped += 1
                sys.stderr.write(f"  [{i}/{len(rows)}] {full_name}: fetch failed, skipped\n")
                continue
            score, tier, nf, nfind, cats = result
            if i % 25 == 0 or tier != "Low":
                print(f"  [{i}/{len(rows)}] {full_name:<45} {tier:>8} ({score:>3})  files={nf} findings={nfind} {','.join(cats)}", flush=True)
        except Exception as e:
            skipped += 1
            sys.stderr.write(f"  {full_name}: {e}\n")
    print(f"\n  scanned {len(rows) - skipped}, skipped {skipped} (fetch failures excluded from stats)")

    print("\n=== aggregate (the only thing we publish) ===")
    total = conn.execute("SELECT COUNT(*) FROM security_scores").fetchone()[0]
    for tier in ("High", "Elevated", "Low"):
        n = conn.execute("SELECT COUNT(*) FROM security_scores WHERE tier=?", (tier,)).fetchone()[0]
        print(f"  {tier:>8} surface: {n}")
    print("  by category (repos with >=1 finding):")
    for cat, n in conn.execute(
        "SELECT category, COUNT(DISTINCT full_name) FROM security_findings GROUP BY category ORDER BY 2 DESC"
    ):
        pct = round(100 * n / total, 1) if total else 0
        print(f"    {cat:<24} {n:>4}  ({pct}% of scanned)")
    conn.close()


if __name__ == "__main__":
    main()
