"""
Major Labs Sentinel · report pass

Generates summary statistics from the scan database. Writes:
  - out/summary.md   — human-readable markdown
  - out/repos.csv    — flat CSV of all repos with signals
  - out/top50.md     — top 50 by stars with transport classification

Run: python3 report.py
"""

from __future__ import annotations
import csv
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(__file__).parent / "scans.db"
OUT_DIR = Path(__file__).parent / "out"


def days_since(iso_ts: str | None) -> int | None:
    if not iso_ts:
        return None
    try:
        dt = datetime.fromisoformat(iso_ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    now = datetime.now(timezone.utc)
    return (now - dt).days


def main():
    OUT_DIR.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH)

    total = conn.execute("SELECT COUNT(*) FROM repos").fetchone()[0]
    if total == 0:
        print("no repos in db — run discover.py first")
        return

    analyzed = conn.execute("SELECT COUNT(*) FROM repo_analysis").fetchone()[0]
    archived = conn.execute("SELECT COUNT(*) FROM repos WHERE archived=1").fetchone()[0]
    forks = conn.execute("SELECT COUNT(*) FROM repos WHERE fork=1").fetchone()[0]
    active = total - archived - forks

    # Language distribution
    lang_rows = conn.execute(
        """
        SELECT COALESCE(NULLIF(language,''),'unknown'), COUNT(*)
        FROM repos
        WHERE archived=0 AND fork=0
        GROUP BY 1
        ORDER BY 2 DESC
        LIMIT 10
        """
    ).fetchall()

    # License distribution
    license_rows = conn.execute(
        """
        SELECT COALESCE(NULLIF(license,''),'none'), COUNT(*)
        FROM repos
        WHERE archived=0 AND fork=0
        GROUP BY 1
        ORDER BY 2 DESC
        LIMIT 10
        """
    ).fetchall()

    # Maintenance buckets (days since last push)
    repos = conn.execute(
        "SELECT pushed_at FROM repos WHERE archived=0 AND fork=0"
    ).fetchall()
    buckets = {"<7d": 0, "<30d": 0, "<90d": 0, "<180d": 0, "<365d": 0, ">=365d": 0, "unknown": 0}
    for (pushed,) in repos:
        d = days_since(pushed)
        if d is None:
            buckets["unknown"] += 1
        elif d < 7:
            buckets["<7d"] += 1
        elif d < 30:
            buckets["<30d"] += 1
        elif d < 90:
            buckets["<90d"] += 1
        elif d < 180:
            buckets["<180d"] += 1
        elif d < 365:
            buckets["<365d"] += 1
        else:
            buckets[">=365d"] += 1

    # Transport breakdown (only repos that have been analyzed)
    transport_rows = conn.execute(
        """
        SELECT COALESCE(transport_signal,'not_analyzed'), COUNT(*)
        FROM repo_analysis
        GROUP BY 1
        ORDER BY 2 DESC
        """
    ).fetchall()

    # Top 50 by stars
    top50 = conn.execute(
        """
        SELECT r.full_name, r.stargazers_count, r.language, r.pushed_at,
               COALESCE(a.transport_signal,'-') as transport
        FROM repos r
        LEFT JOIN repo_analysis a USING (full_name)
        WHERE r.archived=0 AND r.fork=0
        ORDER BY r.stargazers_count DESC
        LIMIT 50
        """
    ).fetchall()

    # Write summary markdown
    summary = OUT_DIR / "summary.md"
    with summary.open("w") as f:
        f.write("# State of MCP Servers · v0 scan\n\n")
        f.write(f"Scan completed {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}.\n\n")
        f.write("## Headline numbers\n\n")
        f.write(f"- **{total}** distinct MCP-related repos discovered\n")
        f.write(f"- **{active}** active (not archived, not forks)\n")
        f.write(f"- **{archived}** archived\n")
        f.write(f"- **{forks}** forks\n")
        f.write(f"- **{analyzed}** deep-analyzed (README + manifests)\n\n")

        f.write("## Maintenance freshness (active repos)\n\n")
        f.write("Days since last push:\n\n")
        for bucket, n in buckets.items():
            f.write(f"- `{bucket:<8}` — {n}\n")
        f.write("\n")

        f.write("## Top languages (active repos)\n\n")
        for lang, n in lang_rows:
            f.write(f"- {lang} — {n}\n")
        f.write("\n")

        f.write("## Licenses (active repos)\n\n")
        for lic, n in license_rows:
            f.write(f"- {lic} — {n}\n")
        f.write("\n")

        if transport_rows:
            f.write("## Transport signal (analyzed repos)\n\n")
            f.write("From README pattern matching:\n\n")
            for sig, n in transport_rows:
                f.write(f"- {sig} — {n}\n")
            f.write("\n")

        f.write("## Top 50 by stars\n\n")
        f.write("| Repo | Stars | Language | Last push | Transport |\n")
        f.write("|---|---:|---|---|---|\n")
        for full_name, stars, lang, pushed, transport in top50:
            d = days_since(pushed)
            pushed_str = f"{d}d ago" if d is not None else "—"
            f.write(f"| `{full_name}` | {stars or 0} | {lang or '-'} | {pushed_str} | {transport} |\n")
        f.write("\n")

    # Write CSV
    csv_path = OUT_DIR / "repos.csv"
    with csv_path.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "full_name", "owner", "stars", "language", "license",
            "created_at", "pushed_at", "days_since_push",
            "archived", "fork", "transport_signal",
            "has_package_json", "has_pyproject", "has_requirements",
            "topics", "description", "html_url",
        ])
        rows = conn.execute(
            """
            SELECT r.full_name, r.owner, r.stargazers_count, r.language, r.license,
                   r.created_at, r.pushed_at,
                   r.archived, r.fork, COALESCE(a.transport_signal,'-'),
                   COALESCE(a.has_package_json,0),
                   COALESCE(a.has_pyproject,0),
                   COALESCE(a.has_requirements,0),
                   r.topics, r.description, r.html_url
            FROM repos r
            LEFT JOIN repo_analysis a USING (full_name)
            ORDER BY r.stargazers_count DESC
            """
        ).fetchall()
        for row in rows:
            (full_name, owner, stars, lang, license_, created_at, pushed_at,
             archived, fork, transport, pkg, pyproj, req, topics, desc, url) = row
            writer.writerow([
                full_name, owner, stars or 0, lang or "", license_ or "",
                created_at or "", pushed_at or "", days_since(pushed_at) if pushed_at else "",
                archived, fork, transport,
                pkg, pyproj, req,
                topics or "", (desc or "")[:200], url,
            ])

    print(f"wrote {summary}")
    print(f"wrote {csv_path}")
    print()
    print(f"  total repos:    {total}")
    print(f"  active:         {active}")
    print(f"  analyzed:       {analyzed}")
    if transport_rows:
        print("  transport:")
        for sig, n in transport_rows:
            print(f"    {sig:<12} {n}")

    conn.close()


if __name__ == "__main__":
    main()
