"""
Export the public dataset from scans.db.

Ships the structured facts behind the State of MCP reports — repo metadata,
maintenance signals, transport classification, and manifest-presence flags — and
deliberately DROPS the raw third-party text bodies (README and manifest excerpts).
Those carry no analytical value for the reports and are the only place author
emails or example credentials from other people's repos could appear, so leaving
them out keeps the published dataset free of third-party PII.

Re-run discover.py + analyze.py to rebuild scans.db (with excerpts) locally.

Run: python3 export_dataset.py
"""

import csv
import re
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "scans.db"
OUT_DIR = Path(__file__).parent / "dataset"

_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")


def _clean(value):
    """Belt-and-suspenders: redact any stray email from short metadata fields."""
    if isinstance(value, str):
        return _EMAIL.sub("[email]", value)
    return value


REPO_FIELDS = [
    "full_name", "owner", "name", "description", "html_url", "language",
    "stargazers_count", "forks_count", "open_issues_count", "size_kb",
    "license", "archived", "fork", "created_at", "pushed_at", "updated_at",
    "topics", "sources",
]
ANALYSIS_FIELDS = [
    "transport_signal", "transport_stdio", "transport_http", "readme_bytes",
    "has_package_json", "has_pyproject", "has_requirements", "has_cargo", "has_go_mod",
]


def main():
    OUT_DIR.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    # One row per repo: public metadata + analysis signals. No excerpt bodies.
    rows = conn.execute(
        """
        SELECT r.*, a.transport_signal, a.transport_stdio, a.transport_http,
               a.readme_bytes, a.has_package_json, a.has_pyproject,
               a.has_requirements, a.has_cargo, a.has_go_mod
        FROM repos r LEFT JOIN repo_analysis a ON r.full_name = a.full_name
        ORDER BY r.stargazers_count DESC
        """
    ).fetchall()

    cols = REPO_FIELDS + ANALYSIS_FIELDS
    servers_path = OUT_DIR / "mcp-servers.csv"
    with open(servers_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(cols)
        for row in rows:
            w.writerow([_clean(row[c]) if c in row.keys() else "" for c in cols])

    # Query provenance, for methodology transparency.
    runs = conn.execute(
        "SELECT query, source_tag, total_count, fetched_count, started_at, finished_at "
        "FROM discovery_runs ORDER BY started_at"
    ).fetchall()
    runs_path = OUT_DIR / "discovery-runs.csv"
    with open(runs_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["query", "source_tag", "total_count", "fetched_count", "started_at", "finished_at"])
        for r in runs:
            w.writerow(list(r))

    conn.close()
    print(f"wrote {len(rows)} repos -> {servers_path} ({servers_path.stat().st_size/1024:.0f} KB)")
    print(f"wrote {len(runs)} runs  -> {runs_path}")


if __name__ == "__main__":
    main()
