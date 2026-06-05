"""
Major Labs Sentinel · analyze pass  (Python 3.9 compatible)

For each repo discovered, pull deeper signals:
  - README content (look for stdio / HTTP-SSE indicators, install instructions)
  - Dependency manifest files (package.json, pyproject.toml, requirements.txt, Cargo.toml)
  - Latest commit signal (already in repos table from discovery)

No vulnerability scoring yet. That's Stage 2.

Run: python3 analyze.py [--limit N]
"""

from __future__ import annotations
import argparse
import base64
import json
import re
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

DB_PATH = Path(__file__).parent / "scans.db"

# Files we look for in each repo root.
MANIFEST_PATHS = [
    "package.json",
    "pyproject.toml",
    "requirements.txt",
    "Cargo.toml",
    "go.mod",
]

# Phrases in READMEs that hint at runtime mode.
STDIO_PATTERNS = re.compile(
    r"\b(stdio|claude_desktop_config|mcpServers|cursor\.json|"
    r"add to (?:your )?claude(?: desktop)?|mcp install|"
    r"npx [^\s]+mcp|uvx [^\s]+)",
    re.IGNORECASE,
)
HTTP_PATTERNS = re.compile(
    r"\b(SSE|server-sent events|HTTP transport|streamable HTTP|"
    r"https?://[^\s]+/mcp|/sse|expose endpoint|deploy on|"
    r"docker run.*\-p\s+\d+)",
    re.IGNORECASE,
)


def gh(*args: str) -> dict | list | None:
    cmd = ["gh", "api", "-H", "Accept: application/vnd.github+json", *args]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        # Quiet 404s — many repos don't have all manifests.
        return None
    try:
        return json.loads(result.stdout) if result.stdout.strip() else None
    except json.JSONDecodeError:
        return None


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS repo_analysis (
            full_name TEXT PRIMARY KEY,
            readme_bytes INTEGER,
            readme_excerpt TEXT,
            transport_stdio INTEGER,
            transport_http INTEGER,
            transport_signal TEXT,
            has_package_json INTEGER,
            has_pyproject INTEGER,
            has_requirements INTEGER,
            has_cargo INTEGER,
            has_go_mod INTEGER,
            analyzed_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (full_name) REFERENCES repos(full_name)
        );

        CREATE TABLE IF NOT EXISTS repo_manifests (
            full_name TEXT,
            manifest TEXT,
            content_bytes INTEGER,
            content_excerpt TEXT,
            captured_at TEXT DEFAULT (datetime('now')),
            PRIMARY KEY (full_name, manifest)
        );
        """
    )


def fetch_readme(full_name: str) -> dict | None:
    data = gh(f"/repos/{full_name}/readme")
    if not isinstance(data, dict):
        return None
    content_b64 = data.get("content")
    if not content_b64:
        return None
    try:
        raw = base64.b64decode(content_b64).decode("utf-8", errors="replace")
    except Exception:
        return None
    return {"size": data.get("size") or 0, "content": raw}


def fetch_manifest(full_name: str, path: str) -> str | None:
    data = gh(f"/repos/{full_name}/contents/{path}")
    if not isinstance(data, dict):
        return None
    content_b64 = data.get("content")
    if not content_b64:
        return None
    try:
        return base64.b64decode(content_b64).decode("utf-8", errors="replace")
    except Exception:
        return None


def classify_transport(readme: str) -> tuple[bool, bool, str]:
    has_stdio = bool(STDIO_PATTERNS.search(readme))
    has_http = bool(HTTP_PATTERNS.search(readme))
    if has_stdio and has_http:
        sig = "both"
    elif has_stdio:
        sig = "stdio"
    elif has_http:
        sig = "http"
    else:
        sig = "unclear"
    return has_stdio, has_http, sig


def analyze_repo(conn: sqlite3.Connection, full_name: str) -> dict:
    readme = fetch_readme(full_name)
    readme_bytes = 0
    readme_excerpt = ""
    has_stdio = has_http = False
    transport_signal = "no_readme"
    if readme:
        readme_bytes = readme["size"]
        readme_excerpt = readme["content"][:1200]
        has_stdio, has_http, transport_signal = classify_transport(readme["content"])

    # Lightweight manifest detection — just check existence + capture small excerpt.
    manifest_flags = {p: False for p in MANIFEST_PATHS}
    for path in MANIFEST_PATHS:
        time.sleep(0.05)  # gentle on the API
        content = fetch_manifest(full_name, path)
        if content is None:
            continue
        manifest_flags[path] = True
        conn.execute(
            """
            INSERT INTO repo_manifests (full_name, manifest, content_bytes, content_excerpt)
            VALUES (?,?,?,?)
            ON CONFLICT(full_name, manifest) DO UPDATE SET
                content_bytes=excluded.content_bytes,
                content_excerpt=excluded.content_excerpt,
                captured_at=datetime('now')
            """,
            (full_name, path, len(content), content[:4000]),
        )

    conn.execute(
        """
        INSERT INTO repo_analysis (
            full_name, readme_bytes, readme_excerpt,
            transport_stdio, transport_http, transport_signal,
            has_package_json, has_pyproject, has_requirements, has_cargo, has_go_mod,
            analyzed_at
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?, datetime('now'))
        ON CONFLICT(full_name) DO UPDATE SET
            readme_bytes=excluded.readme_bytes,
            readme_excerpt=excluded.readme_excerpt,
            transport_stdio=excluded.transport_stdio,
            transport_http=excluded.transport_http,
            transport_signal=excluded.transport_signal,
            has_package_json=excluded.has_package_json,
            has_pyproject=excluded.has_pyproject,
            has_requirements=excluded.has_requirements,
            has_cargo=excluded.has_cargo,
            has_go_mod=excluded.has_go_mod,
            analyzed_at=datetime('now')
        """,
        (
            full_name,
            readme_bytes,
            readme_excerpt,
            1 if has_stdio else 0,
            1 if has_http else 0,
            transport_signal,
            1 if manifest_flags["package.json"] else 0,
            1 if manifest_flags["pyproject.toml"] else 0,
            1 if manifest_flags["requirements.txt"] else 0,
            1 if manifest_flags["Cargo.toml"] else 0,
            1 if manifest_flags["go.mod"] else 0,
        ),
    )
    conn.commit()
    return {"transport_signal": transport_signal, "manifest_flags": manifest_flags}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=0, help="Only analyze first N repos")
    parser.add_argument(
        "--only-active",
        action="store_true",
        help="Skip archived repos and forks",
    )
    parser.add_argument(
        "--skip-analyzed",
        action="store_true",
        help="Skip repos already in repo_analysis (default: re-analyze)",
    )
    args = parser.parse_args()

    conn = sqlite3.connect(DB_PATH)
    init_db(conn)

    # Order by stars desc — most-cited servers first.
    sql = "SELECT r.full_name FROM repos r"
    if args.skip_analyzed:
        sql += " LEFT JOIN repo_analysis a ON r.full_name=a.full_name"
    where = []
    if args.only_active:
        where.append("r.archived=0 AND r.fork=0")
    if args.skip_analyzed:
        where.append("a.full_name IS NULL")
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY r.stargazers_count DESC"
    if args.limit:
        sql += f" LIMIT {args.limit}"

    repos = [row[0] for row in conn.execute(sql)]
    print(f"analyzing {len(repos)} repos", flush=True)
    print(flush=True)

    for i, full_name in enumerate(repos, 1):
        try:
            signal = analyze_repo(conn, full_name)
            marker = signal["transport_signal"][:8]
        except Exception as e:
            marker = "ERROR"
            sys.stderr.write(f"  error on {full_name}: {e}\n")
        # Compact progress: print every 10 repos with a summary
        if i % 10 == 0 or i == len(repos):
            done = conn.execute("SELECT COUNT(*) FROM repo_analysis").fetchone()[0]
            print(f"  [{i:>4}/{len(repos)}] last={marker:<8} {full_name[:60]:<60} | analyzed_total={done}", flush=True)

    print()
    # Summary
    rows = conn.execute(
        """
        SELECT transport_signal, COUNT(*)
        FROM repo_analysis
        GROUP BY transport_signal
        ORDER BY 2 DESC
        """
    ).fetchall()
    print("=== transport breakdown ===")
    for sig, n in rows:
        print(f"  {sig:<10} {n}")

    conn.close()


if __name__ == "__main__":
    main()
