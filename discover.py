"""
Major Labs Sentinel · discovery pass

Pulls candidate MCP server repos from public sources:
  1. GitHub topic search: topic:mcp-server, topic:model-context-protocol
  2. GitHub org: modelcontextprotocol (reference implementations)
  3. GitHub search: repos with "mcp-server-" name prefix or "mcp" + "server" in description

Dedupes by canonical full_name (owner/repo). Writes to scans.db.

Run: python3 discover.py
"""

import json
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

DB_PATH = Path(__file__).parent / "scans.db"
GH_PER_PAGE = 100
GH_MAX_PAGES = 10  # 1,000 results max per query — GitHub search caps at 1,000

# Search queries, ordered by expected signal quality.
QUERIES = [
    ("topic:mcp-server", "topic-mcp-server"),
    ("topic:model-context-protocol", "topic-model-context-protocol"),
    ("topic:modelcontextprotocol", "topic-modelcontextprotocol"),
    ("org:modelcontextprotocol", "org-mcp-reference"),
    ("mcp server in:name,description fork:false", "name-desc-mcp-server"),
]


def gh(*args: str) -> dict:
    """Run a gh api call and return parsed JSON. Retries transient timeouts so an
    unattended run survives slow GitHub search responses (secondary rate limiting)."""
    import time
    cmd = ["gh", "api", "-H", "Accept: application/vnd.github+json", *args]
    for attempt in range(3):
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            break
        except subprocess.TimeoutExpired:
            sys.stderr.write(f"gh api timeout (attempt {attempt + 1}/3), backing off...\n")
            time.sleep(10 * (attempt + 1))
    else:
        sys.stderr.write("gh api timed out 3x; skipping this call\n")
        return {}
    if result.returncode != 0:
        sys.stderr.write(f"gh api failed: {result.stderr}\n")
        return {}
    try:
        return json.loads(result.stdout) if result.stdout.strip() else {}
    except json.JSONDecodeError:
        sys.stderr.write(f"non-JSON response: {result.stdout[:200]}\n")
        return {}


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS repos (
            full_name TEXT PRIMARY KEY,
            owner TEXT,
            name TEXT,
            description TEXT,
            html_url TEXT,
            clone_url TEXT,
            default_branch TEXT,
            language TEXT,
            stargazers_count INTEGER,
            watchers_count INTEGER,
            forks_count INTEGER,
            open_issues_count INTEGER,
            size_kb INTEGER,
            license TEXT,
            archived INTEGER,
            fork INTEGER,
            created_at TEXT,
            pushed_at TEXT,
            updated_at TEXT,
            topics TEXT,
            discovered_at TEXT DEFAULT (datetime('now')),
            sources TEXT
        );

        CREATE TABLE IF NOT EXISTS discovery_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            query TEXT,
            source_tag TEXT,
            total_count INTEGER,
            fetched_count INTEGER,
            started_at TEXT DEFAULT (datetime('now')),
            finished_at TEXT
        );
        """
    )


def upsert_repo(conn: sqlite3.Connection, item: dict, source_tag: str) -> None:
    full_name = item.get("full_name", "")
    if not full_name:
        return

    # Merge source tags so we know how many queries surfaced this repo.
    existing = conn.execute(
        "SELECT sources FROM repos WHERE full_name = ?", (full_name,)
    ).fetchone()
    if existing and existing[0]:
        sources = set(existing[0].split(",")) | {source_tag}
    else:
        sources = {source_tag}

    conn.execute(
        """
        INSERT INTO repos (
            full_name, owner, name, description, html_url, clone_url,
            default_branch, language, stargazers_count, watchers_count,
            forks_count, open_issues_count, size_kb, license, archived, fork,
            created_at, pushed_at, updated_at, topics, sources
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(full_name) DO UPDATE SET
            description=excluded.description,
            stargazers_count=excluded.stargazers_count,
            watchers_count=excluded.watchers_count,
            forks_count=excluded.forks_count,
            open_issues_count=excluded.open_issues_count,
            size_kb=excluded.size_kb,
            archived=excluded.archived,
            pushed_at=excluded.pushed_at,
            updated_at=excluded.updated_at,
            topics=excluded.topics,
            sources=excluded.sources
        """,
        (
            full_name,
            (item.get("owner") or {}).get("login"),
            item.get("name"),
            item.get("description"),
            item.get("html_url"),
            item.get("clone_url"),
            item.get("default_branch"),
            item.get("language"),
            item.get("stargazers_count"),
            item.get("watchers_count"),
            item.get("forks_count"),
            item.get("open_issues_count"),
            item.get("size"),
            (item.get("license") or {}).get("spdx_id"),
            1 if item.get("archived") else 0,
            1 if item.get("fork") else 0,
            item.get("created_at"),
            item.get("pushed_at"),
            item.get("updated_at"),
            ",".join(item.get("topics") or []),
            ",".join(sorted(sources)),
        ),
    )


def search_query(conn: sqlite3.Connection, query: str, tag: str) -> tuple[int, int]:
    """Run a paged GitHub search and upsert every result. Returns (reported_total, fetched)."""
    run_id = conn.execute(
        "INSERT INTO discovery_runs (query, source_tag) VALUES (?, ?)", (query, tag)
    ).lastrowid

    reported_total = 0
    fetched = 0

    for page in range(1, GH_MAX_PAGES + 1):
        endpoint = (
            f"/search/repositories?q={query}&per_page={GH_PER_PAGE}&page={page}"
        )
        data = gh(endpoint)
        if not data:
            break

        reported_total = data.get("total_count", reported_total)
        items = data.get("items") or []
        for item in items:
            upsert_repo(conn, item, tag)
            fetched += 1

        if len(items) < GH_PER_PAGE:
            break

        # Respect search rate limit (30 req/min for search even with auth).
        time.sleep(2.5)

    conn.execute(
        "UPDATE discovery_runs SET total_count=?, fetched_count=?, finished_at=datetime('now') WHERE id=?",
        (reported_total, fetched, run_id),
    )
    conn.commit()
    return reported_total, fetched


def fetch_org_repos(conn: sqlite3.Connection, org: str, tag: str) -> int:
    """Pull every public repo from a specific org. No 1,000-result search cap."""
    run_id = conn.execute(
        "INSERT INTO discovery_runs (query, source_tag) VALUES (?, ?)",
        (f"org:{org}", tag),
    ).lastrowid

    fetched = 0
    page = 1
    while True:
        data = gh(f"/orgs/{org}/repos?per_page={GH_PER_PAGE}&page={page}&type=public")
        if not isinstance(data, list) or not data:
            break
        for item in data:
            upsert_repo(conn, item, tag)
            fetched += 1
        if len(data) < GH_PER_PAGE:
            break
        page += 1
        time.sleep(1)

    conn.execute(
        "UPDATE discovery_runs SET total_count=?, fetched_count=?, finished_at=datetime('now') WHERE id=?",
        (fetched, fetched, run_id),
    )
    conn.commit()
    return fetched


def main():
    conn = sqlite3.connect(DB_PATH)
    init_db(conn)

    print(f"discovery target: {DB_PATH}")
    print(f"queries: {len(QUERIES)}")
    print()

    for query, tag in QUERIES:
        print(f"  [{tag}] q={query!r}")
        if query.startswith("org:"):
            fetched = fetch_org_repos(conn, query.split(":", 1)[1], tag)
            print(f"           fetched={fetched}")
        else:
            total, fetched = search_query(conn, query, tag)
            print(f"           reported_total={total}  fetched={fetched}")

    total = conn.execute("SELECT COUNT(*) FROM repos").fetchone()[0]
    distinct_owners = conn.execute("SELECT COUNT(DISTINCT owner) FROM repos").fetchone()[0]
    archived = conn.execute("SELECT COUNT(*) FROM repos WHERE archived=1").fetchone()[0]
    forks = conn.execute("SELECT COUNT(*) FROM repos WHERE fork=1").fetchone()[0]

    print()
    print("=== discovery summary ===")
    print(f"  distinct repos:      {total}")
    print(f"  distinct owners:     {distinct_owners}")
    print(f"  archived:            {archived}")
    print(f"  forks:               {forks}")
    print(f"  active (non-fork):   {total - forks - archived}")

    conn.close()


if __name__ == "__main__":
    main()
