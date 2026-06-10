# mcp-scanner · Sentinel (v0)

An open scan of the public **Model Context Protocol (MCP)** server ecosystem. It
pulls MCP server repositories from GitHub, captures observable signals (transport
mode, maintenance, language, license, manifest presence), and stores them in
SQLite. The resulting dataset is the factual basis for Major Labs' *State of MCP*
writeups.

> **v0 scope: discovery and metadata only.** Everything here is **read-only** and
> uses the public GitHub API (via the `gh` CLI). It does **not** connect to,
> probe, or send anything to any MCP server. Active vulnerability probing (SSRF,
> injection, etc.) is future work and is intentionally **not** in this repository.

## What it does

1. **`discover.py`** — finds candidate MCP server repos via GitHub topic/org/name
   search (`topic:mcp-server`, `topic:model-context-protocol`, the
   `modelcontextprotocol` org, etc.), deduped by `owner/repo`.
2. **`analyze.py`** — for each repo, reads the README and dependency manifests
   (package.json, pyproject.toml, requirements.txt, Cargo.toml, go.mod) via the
   GitHub API and classifies the likely transport mode (stdio / HTTP / both).
3. **`security.py`** — READ-ONLY static security sweep: fetches public source
   for catalogued repos via the GitHub API and flags security-relevant code
   patterns (command injection, SSRF surface, eval/exec, unsafe deserialization,
   hardcoded secrets). It never connects to, runs, or probes a server. Findings
   are heuristic static signals, tuned for precision. **Only aggregate statistics
   are published** (see majorlabs.co/security); per-repo findings stay in the
   local database for coordinated maintainer disclosure.
4. **`report.py`** — prints population, maintenance, transport, and licensing
   summaries.
5. **`export_dataset.py`** — writes the published dataset (see below).

## Run

```bash
gh auth login                 # uses your own GitHub token; nothing is embedded
python3 discover.py
python3 analyze.py
python3 report.py
python3 export_dataset.py      # writes dataset/*.csv
```

Output: `scans.db` (local SQLite, gitignored) and `dataset/*.csv`.

## The dataset (`dataset/`)

- **`mcp-servers.csv`** — one row per repo: name, owner, description, stars,
  forks, language, license, archived/fork flags, created/pushed/updated dates,
  topics, the transport classification, and which dependency manifests are
  present.
- **`discovery-runs.csv`** — the exact search queries and result counts, for
  methodology transparency.

**Deliberately excluded:** the raw README and manifest *text bodies* that
`analyze.py` stores locally in `scans.db`. They carry no analytical value for the
reports and are the only place where author emails or example credentials from
other people's repositories could appear, so the published dataset omits them.
Re-run `discover.py` + `analyze.py` to rebuild the full local database yourself.

## Methodology and limitations

This is a best-effort, reproducible scan, not a definitive census. Known caveats:

- **Transport classification is heuristic** (regex over README phrasing), so
  "stdio / HTTP / both / unclear" is a signal, not ground truth.
- **Discovery is search-driven**, so repos that are not tagged or named
  conventionally are missed. `discovery-runs.csv` records exactly what was
  queried.
- Counts reflect the GitHub state at scan time (`discovered_at` / `analyzed_at`).

## Ethics

- Public data only (GitHub API, public repositories). No authentication to,
  or probing of, third-party servers.
- Respects GitHub API rate limits.
- For any vulnerability later surfaced at a named maintainer's project, we follow
  coordinated disclosure (30 days before publication).

## License

MIT.
