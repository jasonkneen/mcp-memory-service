# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with this MCP Memory Service repository. It is written to be self-sufficient: a model should be able to work correctly here from this file alone, without filling gaps from prior knowledge.

> **Personal Customizations**: You can create `CLAUDE.local.md` (gitignored) for personal notes, custom workflows, or environment-specific instructions. This file contains shared project conventions.

> **Information Lookup**: Files first, memory second, user last. See [`.claude/directives/memory-first.md`](.claude/directives/memory-first.md) for strategy. Comprehensive project context is stored in the MCP Memory Server with tag `claude-code-reference`.

## Non-Negotiables (hard rules)

Quick reference; each rule is expanded in the sections below. Violations cause real incidents.

1. **This repo lives on Codeberg, not GitHub.** `origin` is `codeberg.org:doobidoo/mcp-memory-service`; CI is Forgejo Actions (`.forgejo/workflows/`). The `github` remote is a suspended mirror — do **not** use `gh` or `github.com` URLs for CI, releases, or issues.
2. **Never manually bump versions.** Follow the documented release workflow for every version bump and release.
3. **Run `bash scripts/pr/pre_pr_check.sh` before every PR.** It is the mandatory pre-PR gate and must pass.
4. **Use the project venv.** Run `.venv/bin/python` and `.venv/bin/pytest` (Python 3.11) — the system interpreters are not the project environment.
5. **Store context in the MCP Memory Server, tagged `mcp-memory-service` first.** Never write `MEMORY.md` or local memory files unless the user explicitly asks for file-based storage.
6. **Access `Memory` fields by attribute** (`memory.tags`), never via `memory.metadata.get('tags')`. This has caused 3 production bugs.
7. **Sanitize user-provided values in logs** with `_sanitize_log_value()` (from `mcp_memory_service.compat`).
8. **MCP server configs go in `.mcp.json`**, not `settings.json`.
9. **Update `site/index.html` version strings on every MINOR/MAJOR release** (a CI gate enforces this).
10. **Never click "Always allow" on heredoc commands** — it corrupts `.claude/settings.local.json`.
11. **Before any SSH/network task, verify `hostname` and connection direction** (source → target).
12. **Report outcomes faithfully.** "Tests pass" means you ran them and saw them pass; if a step was skipped or failed, say so with the output.
13. **Write in the maintainer's or contributor's own voice.** Commit messages, PR descriptions, CHANGELOG entries, issue/PR comments, and release notes read as authored by the maintainer or contributor.

## Critical Directives

**IMPORTANT**: Before working with this project, read:
- **`.claude/directives/memory-tagging.md`** - MANDATORY: Always tag memories with `mcp-memory-service` as first tag
- **`.claude/directives/README.md`** - Additional topic-specific directives

## Operational Rules

### Auto-Save Learnings
- **After completing tasks**: automatically save key learnings, decisions, and patterns to the MCP Memory Server without being asked
- Include relevant tags: `mcp-memory-service`, task-specific tags, and `learnings`

### Source Control & Hosting (Codeberg, not GitHub)
- CI runs as **Forgejo Actions** in `.forgejo/workflows/` (`ci.yml`, `release.yml`, `deploy-site.yml`, `cleanup-images.yml`). There is no `.github/workflows/` directory. Issues and PRs are on Codeberg.
- **GHSA identifiers** (e.g. `GHSA-2r68-g678-7qr3`) are just advisory IDs and remain valid references.
- **Authorship voice.** Commit messages, PR descriptions, CHANGELOG entries, issue/PR comments, and release notes are written in the maintainer's or contributor's own voice.

### Release Workflow Checklist
Before merging or releasing:
1. **Verify CI is green on the target branch** (Forgejo Actions on Codeberg). Check via the `tea` CLI (Forgejo/Gitea) if configured, otherwise the Actions tab at `https://codeberg.org/doobidoo/mcp-memory-service`.
2. **Update `site/index.html` version strings** whenever MAJOR.MINOR changes (i.e. every MINOR or MAJOR release — PATCH releases are exempt). The `version-drift-check` CI gate enforces this and will fail if skipped. Update ALL occurrences: `<title>`, `<meta og:title>`, hero badge, "What's New" section, release link `href`. Use `grep -n "v11\." site/index.html` to find them. This is MANDATORY — not optional for "incremental" releases. The site auto-deploys to Cloudflare Pages (mcpmemory.services) when the change lands on main (`.forgejo/workflows/deploy-site.yml`).
3. Clean up merged branches after release (`git branch -d`, `git push origin --delete`).
4. Follow the release workflow — never manually bump versions.

## Overview

MCP Memory Service is a semantic memory layer for AI applications, accessible via REST API and MCP transport. It provides persistent storage for 14+ AI clients including Claude Desktop, OpenCode, LangGraph, CrewAI, and any HTTP client. It uses vector embeddings for semantic search, supports multiple storage backends (SQLite-vec, Cloudflare, Hybrid), and includes advanced features like memory consolidation, quality scoring, and OAuth 2.1 team collaboration.

**Current Version:** v11.6.0 - MINOR release: migration script no longer drops the knowledge graph and derived beliefs when re-embedding (#189), locale-aware NER/NLI via YAML plugins (#54), Docker images ship the maintenance and migration scripts (#188), plus quality/ontology/harvest fixes (#178, #179, #176, #177, #170); see [CHANGELOG.md](CHANGELOG.md) for details. (Issue/PR numbers refer to Codeberg.)

> **History (v10.0.0):** The v10 API consolidation unified 34 tools into 12. The deprecated tool-name alias layer (`compat.DEPRECATED_TOOLS`) was later **removed in v11** (Issue #53) — old tool names no longer resolve. The registry has since grown to ~28 tools (see `src/mcp_memory_service/tools/registry.py`).

> **History (Feb 2026 roadmap review):** The Q1 2026 quarterly review delivered 6/9 high-priority items ahead of schedule (Python 3.14 support, backup scheduler fix, CI/CD stability). Current roadmap: the **Development Roadmap** page on the Codeberg wiki.

## Essential Commands

### Python Environment

This repo uses a project virtualenv at `.venv` (Python 3.11). The system `python`/`pytest` are **not** the project interpreter. Always use the venv binaries:

```bash
.venv/bin/python -m mcp_memory_service.server   # run a module
.venv/bin/pytest                                # run the test suite
.venv/bin/python -m pip install -e .            # editable install
```

The commands below are written as bare `python`/`pytest` for brevity — run them via `.venv/bin/...`. For `git commit`, the pre-commit hook uses **system** Python and will fail with "Package not installed"; prefix commits with `PATH=".venv/bin:$PATH"` (see Troubleshooting). `uv` is also used (`uv.lock` present); `uv pip install -e .` and `uv run memory ...` work too.

### Development Server

**Recommended (lifecycle CLI):**
```bash
# Start HTTP server in background with PID tracking, logs, health check
memory launch                              # Background (default)
memory launch --foreground                 # Foreground (same as server --http)
memory launch --storage-backend hybrid     # With specific backend
memory launch --debug                      # With debug logging

# Check if server is running
memory info

# Stop server
memory stop

# Restart (preserves --storage-backend and --debug from running server)
memory restart

# View logs
memory logs
memory logs -n 50
```

**Legacy entry points (still available, but the CLI is preferred):**
```bash
# MCP server (for Claude Desktop integration)
python -m mcp_memory_service.server

# HTTP API server (dashboard + REST API)
python scripts/server/run_http_server.py

# Quick update after git pull (installs deps, restarts server)
./scripts/update_and_restart.sh
```

> **Note:** The `memory launch/stop/restart/info/logs` CLI commands are the
> preferred way to manage the server going forward. The legacy scripts
> (`scripts/server/run_http_server.py`, `scripts/update_and_restart.sh`) still
> work but may be deprecated in a future release. For new deployments, use the CLI.

### Testing
```bash
# Run all tests (~2,400+ tests across ~216 files)
# Exact count: .venv/bin/pytest --collect-only -q | tail -1
pytest

# Run specific test file
pytest tests/storage/test_sqlite_vec.py

# Run with markers
pytest -m unit           # Fast unit tests only
pytest -m integration    # Integration tests (require storage)
pytest -m performance    # Performance benchmarks

# Run with coverage
pytest --cov=src/mcp_memory_service --cov-report=html

# Pre-PR validation (MANDATORY before submitting PR)
bash scripts/pr/pre_pr_check.sh
```

### Building & Installation
```bash
# Install in editable mode (development)
pip install -e .

# Install with optional dependencies
pip install -e ".[full]"      # All features
pip install -e ".[sqlite]"    # SQLite with ONNX only
pip install -e ".[ml]"        # Full ML capabilities

# Build package
python -m build
```

### Health Checks
```bash
# Quick health check
curl http://127.0.0.1:8000/api/health

# Comprehensive validation
python scripts/validation/validate_configuration_complete.py

# Backend configuration diagnostics
python scripts/validation/diagnose_backend_config.py
```

**Full command reference:** [scripts/README.md](scripts/README.md)

## Code Architecture

Package layout: `ls src/mcp_memory_service/`. Non-obvious entry points:

- `server_impl.py` - the `MemoryServer` class. `list_tools()` builds the tool list from the declarative registry, `call_tool()` dispatches through the routing table, and the `handle_*` methods live here too.
- `tools/registry.py` - `TOOL_REGISTRY`, the declarative list of `ToolDef` objects, each mapping 1:1 to a `types.Tool`. Count: `grep -c 'ToolDef(' src/mcp_memory_service/tools/registry.py`.
- `tools/routing.py` - `ROUTING_TABLE` (name -> handler) plus `resolve_handler(name)` with lazy import.
- `server/handlers/*.py` - request handlers, signature `async def handle_X(server, arguments) -> List[types.TextContent]`.
- `compat.py` - compatibility shims and `_sanitize_log_value()`.
- `consolidation/` - dream-inspired memory maintenance, not a data-consolidation layer.

Global singleton caching in `server/cache_manager.py` prevents redundant storage
initialization across MCP tool calls. Do not instantiate storage per call.

### Storage backends (`storage/`)

Strategy Pattern over `BaseStorage` (`base.py`), three implementations:

| Backend | File | Performance | Use case |
|---------|------|-------------|----------|
| SQLite-Vec | `sqlite_vec.py` | 5ms reads | Development, single-user |
| Cloudflare | `cloudflare.py` | Network-dependent | Cloud-only, edge |
| Hybrid | `hybrid.py` | 5ms local plus cloud sync | **Production (recommended)** |

SQLite-Vec uses the sqlite-vec extension for KNN search, Cloudflare uses D1 plus
Vectorize, Hybrid reads locally and syncs to Cloudflare in the background. Graph
storage sits in `graph.py`. Embeddings: ONNX, `sentence-transformers/all-MiniLM-L6-v2`.

### Web layer (`web/`)

FastAPI dashboard plus REST API. Two things that are not visible from the file names:

- `api/mcp.py` is a thin MCP-over-HTTP protocol shim. Its tool surface and dispatch
  are inherited from the shared `MemoryServer`, so tools are not defined twice.
- Tools that read caller-supplied filesystem paths are filtered out of the remote
  transport by `local_only_tools()` in `server_impl.py`. This is the confused-deputy
  guard, not an optimization.

### Quality system (`quality/`)

Three tiers, local first:

| Tier | Provider | Latency | Cost | Role |
|------|----------|---------|------|------|
| 1 | Local ONNX | 80-150ms | 0 | Default |
| 2 | Groq / Llama 3 | 500-800ms | 0.0015 | Fallback if local fails |
| 3 | Gemini 1.5 Flash | 1-2s | 0.01 | High-accuracy scoring |

Scores are 0.0 to 1.0 and feed quality-boosted search and retention policy.

### Consolidation (`consolidation/`)

Runs via the HTTP API, not the MCP tools (roughly 90 percent fewer tokens), scheduled
with APScheduler. Retention by quality tier: high 365d, medium 180d, low 30-90d
(`forgetting.py`). Relationship inference classifies associations as causes, fixes,
contradicts, supports, follows or related, with a default confidence threshold of 0.6.
For existing associations, backfill with
`scripts/maintenance/update_graph_relationship_types.py`.

### Document ingestion (`ingestion/`)

Registry pattern, loaders selected by file extension. Chunker defaults: 1000 chars
with 200 overlap. `semtools_loader.py` is optional and adds LlamaParse for PDF, DOCX
and PPTX.

## Test Architecture

About 2,400 tests across roughly 216 files. `tests/` mirrors `src/`.

### Test safety (critical, PR #438)

On Feb 8, 2026 a test cleanup deleted 8,663 production memories. Recovery ran off an
emergency backup. Three guards now stand between the suite and a production database,
all in `conftest.py`:

1. An isolated temp directory with prefix `mcp-test-` is created at module import time.
2. `pytest_sessionstart` aborts the run if a production path is detected.
3. `pytest_sessionfinish` validates temp location, absence of production indicators,
   and presence of test markers before deleting anything.

Tests force `MCP_MEMORY_STORAGE_BACKEND=sqlite_vec` unless
`MCP_TEST_ALLOW_CLOUD_BACKEND=true`. Do not weaken any of this to make a test pass.

### Fixtures and conventions (`conftest.py`)

`temp_db_path` gives an auto-cleaned temp directory, `unique_content` generates
non-duplicate test content, and `test_store` auto-tags everything with
`TEST_MEMORY_TAG = "__test__"`, which is reserved for automatic cleanup. Never use
that tag for real data.

Markers in `pytest.ini`: `unit`, `integration` (needs storage), `performance`,
`asyncio` (auto-detected).

## Configuration

Full variable list: `.env.example`. Precedence: environment variables, then `.env`,
then global Claude config, then defaults. After changing `.env`, restart with
`memory restart`.

Three settings that cause real incidents when wrong:

- `MCP_MEMORY_SQLITE_PRAGMAS` must include `journal_mode=WAL`. Without it, concurrent
  reads and writes are disabled and the HTTP server plus MCP server running together
  produce "database is locked". Working value:
  `journal_mode=WAL,busy_timeout=15000,cache_size=20000`.
- `MCP_HYBRID_SYNC_OWNER=http` for hybrid mode. Then only the HTTP server syncs to
  Cloudflare, the MCP server skips Cloudflare initialization entirely and talks to
  SQLite-Vec directly, and `claude_desktop_config.json` needs no Cloudflare
  credentials. Claude Desktop gets memory access, the HTTP server owns sync.
- `MCP_INIT_TIMEOUT` defaults to 30s on Windows and 15s elsewhere, auto-doubled on
  first run. Slow Windows machines need it raised.

### External embedding APIs

Only supported on the `sqlite_vec` backend, not on `hybrid` or `cloudflare`. Set
`MCP_EXTERNAL_EMBEDDING_URL` and `MCP_EXTERNAL_EMBEDDING_MODEL`, optionally
`MCP_EXTERNAL_EMBEDDING_API_KEY`. Works with vLLM, Ollama, TEI, OpenAI or any
OpenAI-compatible `/v1/embeddings` endpoint. Embedding dimensions must match the
database schema, and changing them requires re-embedding every memory. Details:
[`docs/deployment/external-embeddings.md`](docs/deployment/external-embeddings.md).

Claude Desktop wiring: see README.

## Development Guidelines

### Quality gates

Three layers: pre-commit (under 5s, Groq/Gemini complexity plus security, blocks on
complexity above 8 or a security finding), the PR gate
`bash scripts/pr/pre_pr_check.sh` (10-60s, blocks on security or health below 50), and
a weekly pyscn review with trend tracking. Health score below 50 blocks a release,
50-69 means refactor within two weeks, 70 and up is fine. Complexity target is grade
A-B, meaning 8 or lower.

### Log injection guard (v10.68.0, from CodeQL GHSA-84hp-mqvj-3p8h)

User-provided values in raw f-string log calls trigger CodeQL `py/log-injection`.
Wrap them:

```python
from mcp_memory_service.compat import _sanitize_log_value
logger.info(f"Stored: {_sanitize_log_value(content)}")
```

The helper strips newline, carriage return and escape characters, which prevents log
forging and ANSI injection. `pre_pr_check.sh` check 6.5 detects unwrapped f-string
logger calls. For paths, validate with `Path(user_input).resolve()` and verify the
result is under the expected base directory.

### Memory field access (cause of three production bugs)

`tags`, `memory_type`, `content_hash` and `created_at` are top-level attributes of the
`Memory` dataclass. `metadata` is a separate dict for custom key-value pairs only and
never holds standard fields.

```python
memory.tags               # correct
memory.memory_type or ''  # correct, with fallback

memory.metadata.get('tags', [])  # wrong, silently returns []
memory['tags']                   # wrong, raises AttributeError
```

The metadata form fails silently, which is why it reached production three times
(PRs #466, #467, #469 in v10.13.1): a broken REST filter returning zero results, tags
rendered character by character, and crashing prompt handlers. Flag any
`metadata.get('tags')` or `metadata.get('memory_type')` in review.

### External data parsers

Download and inspect a real sample before writing a parser or its tests. API docs and
project pages misdescribe structures often enough to matter, for example LoCoMo
observations are nested dicts rather than newline-separated strings.

### Directives to read before working

- [`.claude/directives/development-setup.md`](.claude/directives/development-setup.md) - editable install
- [`.claude/directives/pr-workflow.md`](.claude/directives/pr-workflow.md) - pre-PR checks
- [`.claude/directives/refactoring-checklist.md`](.claude/directives/refactoring-checklist.md) - refactoring safety
- [`.claude/directives/version-management.md`](.claude/directives/version-management.md) - release workflow (how)
- [`.claude/directives/release-cadence.md`](.claude/directives/release-cadence.md) - release batching (when)

Version bumps follow the documented release workflow, never by hand. It keeps
`pyproject.toml`, `_version.py`, CHANGELOG and the Codeberg release in sync and writes
the release notes.

### Gotchas when changing things

- Dashboard (`web/static/`): the JS has no automated coverage. Verify in a browser and
  attach manual testing evidence or screenshots to the PR.
- Removing a feature, port or command: run `grep -r "<term>" docs/ README.md` and clean
  up references in the same PR. `scripts/ci/check_dead_refs.sh` catches new dead refs
  in CI on docs changes.

### Adding a new MCP tool

Tools are declarative as of v11. The old inline `types.Tool(...)` list in `list_tools()`
and the `call_tool()` elif chain are both gone.

1. Add a `ToolDef(name, description, input_schema, annotations)` to `TOOL_REGISTRY` in
   `tools/registry.py`. Set `annotations={"readOnlyHint": True, ...}` for non-mutating
   tools: annotations drive OAuth scope, and without `readOnlyHint` the HTTP `/mcp`
   layer treats the tool as a write tool and demands the OAuth `write` scope
   (GHSA-2r68-g678-7qr3).
2. Implement `async def handle_X(server, arguments) -> List[types.TextContent]` in
   `server/handlers/*.py`.
3. Add `"<tool_name>": <handler>` to `ROUTING_TABLE` in `tools/routing.py`. Use a module
   function reference, or the `("__self__", "handle_X")` tuple to dispatch to a
   `MemoryServer` method.
4. If the tool reads a caller-supplied path (`project_path`, `file_path`,
   `directory_path`), add its name to `local_only_tools()` in `server_impl.py` so the
   HTTP shim will not expose it.
5. Add tests in `tests/server/test_handlers.py`.

Renaming a tool is a breaking change. The alias layer (`compat.DEPRECATED_TOOLS`) was
removed in v11 (Issue #53), so a rename drops the old name outright. Treat it as a major
version change and document the migration in `docs/MIGRATION.md`.

### Other extension points

New storage backend: implement `BaseStorage` (`storage/base.py`), add a factory method
in `storage/factory.py`, add `tests/storage/test_<backend>.py`. New document loader:
implement `DocumentLoader` (`ingestion/base.py`), register it in
`ingestion/registry.py`, add `tests/ingestion/test_<loader>.py`.

Maintenance scripts, all supporting `--dry-run`:
`scripts/maintenance/improve_memory_ontology.py` re-classifies memory types,
`update_graph_relationship_types.py` infers relationship types for existing
associations, `cleanup_memories.py` removes test memories and orphaned data.

## Definition of Done

Work is not "done" until the relevant checks below have been run and pass. Report results plainly — paste the command output; if a check was skipped or failed, say so rather than claiming success.

**Every code change:**
- [ ] Relevant tests pass: `.venv/bin/pytest tests/<area>` (or `.venv/bin/pytest -k <pattern>`); run the full suite before a release.
- [ ] `bash scripts/pr/pre_pr_check.sh` passes — the MANDATORY pre-PR gate (blocks on security findings and health score <50, includes the log-injection check).
- [ ] New code stays within the complexity budget (A-B grade, complexity ≤8).
- [ ] User-provided values in `logger.*` calls are wrapped with `_sanitize_log_value()`.
- [ ] `Memory` fields are accessed by attribute (`memory.tags`), never `memory.metadata.get('tags')`.
- [ ] If a feature/port/command was removed: `grep -r "<term>" docs/ README.md` and clean up references in the same change.

**Dashboard changes (`web/static/`):** verified in a browser (no automated JS coverage) — include a screenshot or a note of what was exercised.

**Before a release / version bump:**
- [ ] CI is green on the target branch (Forgejo Actions on Codeberg).
- [ ] Version bumped via the release workflow (never by hand) — keeps `pyproject.toml`, `_version.py`, CHANGELOG, and the Codeberg release in sync.
- [ ] `site/index.html` version strings updated if MAJOR.MINOR changed (see the Release Workflow Checklist).

**After finishing a task:** save key learnings/decisions to the MCP Memory Server, tagged `mcp-memory-service` first (per the Auto-Save rule).

## Troubleshooting

### Heredoc Permission Corruption

**NEVER click "Always allow" on heredoc/here-document commands** (e.g. `cat << 'EOF' > /tmp/report.md`). Claude Code stores the **entire command including multi-page content** as a Bash permission pattern in `.claude/settings.local.json`. This causes parsing errors on next startup (garbled tree-character artifacts, ":* pattern must be at the end" errors).

**Prevention:**
- Use single "Allow" (not "Always allow") for heredoc commands
- For report generation, prefer `tee`, `python -c`, or write files via the `Write` tool instead of shell heredocs
- Agents generating reports should write files directly, not via `cat << EOF`

**Recovery:** Remove the corrupted entries from the `.claude/settings.local.json` `permissions.allow` array. They are identifiable by their massive size (entire reports embedded as permission strings).

### Common Issues

| Issue | Quick Fix |
|-------|-----------|
| Wrong backend showing | `python scripts/validation/diagnose_backend_config.py` |
| Port mismatch (hooks timeout) | Verify same port in `~/.claude/hooks/config.json` and server (default: 8000) |
| Schema validation errors after PR merge | Run `/mcp` in Claude Code to reconnect with the new schema |
| Database lock errors | Add `journal_mode=WAL` to `MCP_MEMORY_SQLITE_PRAGMAS` in `.env`, restart servers |
| Tests failing after git pull | Run `memory restart` or `./scripts/update_and_restart.sh` (installs deps, restarts server) |
| MCP fails on every session (Windows) | Set `MCP_INIT_TIMEOUT=120` in your MCP server env config (issue #474) |
| Cloudflare 401 on MCP server startup (hybrid mode) | Set `MCP_HYBRID_SYNC_OWNER=http` in `.env` — the MCP server then uses SQLite-Vec only, no Cloudflare token needed in Claude Desktop config |
| Cloudflare 403 / sync not running (IPv6) | Python prefers IPv6 but the token IP allowlist may only have IPv4. Add your IPv6 /64 network to the token's Client IP Address Filtering, or remove IP filtering entirely |
| Strict stdio client times out during handshake (e.g. Codex, 10s budget) | Set `MCP_INIT_TIMEOUT=5` to force lazy loading — storage initializes on first tool call instead (issue #561) |
| uv.lock revision downgraded (revision=2 vs revision=3) | Local uv 0.7.16 silently downgrades the lockfile. Restore with `git checkout uv.lock` or upgrade uv. Don't include revision-only changes in PRs |
| Pre-commit hook fails "Package not installed" | The hook uses system Python, not the venv. Use `PATH=".venv/bin:$PATH" git commit -m "..."` for all commits |
| Editable install replaced PyPI version | `uv pip install -e .` replaces the PyPI package with local source. After commit, restore with `uv pip install mcp-memory-service==<version>` |
| Cloudflare 401 after upgrade/restart | First search Memory (`cloudflare 401`), then verify the `.env` token matches the Cloudflare Dashboard. Token rotation in the dashboard does NOT update local `.env` |
| zeroconf DLL load fails / Symantec flags it as a trojan (Windows) | False positive on the mDNS C extension. Set `MCP_MDNS_ENABLED=false` (core service works without mDNS). See [docs/troubleshooting/mdns-symantec-false-positive.md](docs/troubleshooting/mdns-symantec-false-positive.md) |

**Comprehensive troubleshooting:** [docs/troubleshooting/hooks-quick-reference.md](docs/troubleshooting/hooks-quick-reference.md)

**Configuration validation:**
```bash
python scripts/validation/validate_configuration_complete.py  # Comprehensive
python scripts/validation/diagnose_backend_config.py          # Backend-specific
```

## Key Design Patterns

1. **Strategy Pattern** - Storage backends, health checks, quality analytics
2. **Orchestrator Pattern** - Startup orchestrator, consolidation scheduler
3. **Processor Pattern** - Document ingestion, file processing
4. **Registry Pattern** - Document loaders, storage factory, declarative tool registry
5. **Singleton Pattern** - Global caching (storage, service instances)

## Performance Characteristics

**Key Metrics** (from production deployments):
- **5ms reads** - SQLite-Vec local storage
- **534,628x faster** - Global caching optimization (v8.26.0)
- **90% token reduction** - Consolidation via HTTP API vs MCP tools
- **85%+ trigger accuracy** - Natural memory triggers (v7.1.3+)
- **80-150ms** - Local ONNX quality scoring

## Documentation

**Where to find information:**
- **CLAUDE.md** (this file) - Development guide for Claude Code
- **README.md** - User-facing documentation, installation, features
- **CHANGELOG.md** - Version history, breaking changes, migrations
- **scripts/README.md** - Complete script reference
- **site/** - mcpmemory.services landing page + in-browser demo (Cloudflare Pages, auto-deployed)
- **docs/** - Guides, troubleshooting, architecture specs
- **Wiki** - Comprehensive documentation (https://codeberg.org/doobidoo/mcp-memory-service/wiki)
- **`.claude/directives/`** - Topic-specific directives for Claude Code

**When to update each:**
- **CLAUDE.md** - Architecture changes, new patterns, development workflows
- **README.md** - New features, installation changes, user-facing updates
- **CHANGELOG.md** - Every version bump (via the release workflow)
- **site/index.html** - Landing page: MINOR/MAJOR releases only (title, og:title, hero badge, "What's New" cards, test count, release link). No manual publish step: merging to main triggers `.forgejo/workflows/deploy-site.yml`, which deploys `site/` to Cloudflare Pages (mcpmemory.services). GitHub Pages and the here.now mirror are retired; `docs/index.html` is only a redirect stub — never put version strings or content there.
- **Wiki** - Detailed guides, troubleshooting, tutorials

## Additional Resources

- **Storage Backends:** [`.claude/directives/storage-backends.md`](.claude/directives/storage-backends.md)
- **Hooks Configuration:** [`.claude/directives/hooks-configuration.md`](.claude/directives/hooks-configuration.md)
- **Quality System:** [`.claude/directives/quality-system-details.md`](.claude/directives/quality-system-details.md)
- **Consolidation:** [`.claude/directives/consolidation-details.md`](.claude/directives/consolidation-details.md)
- **Code Quality:** [`.claude/directives/code-quality-workflow.md`](.claude/directives/code-quality-workflow.md)

---

**Quick Start Checklist for New Contributors:**
1. [ ] Read this file (CLAUDE.md), especially the Non-Negotiables
2. [ ] Read `.claude/directives/memory-tagging.md` (MANDATORY)
3. [ ] Run `pip install -e .` into `.venv` (editable install)
4. [ ] Run `.venv/bin/pytest` (verify tests pass)
5. [ ] Read the relevant directive files for your work area
6. [ ] Make changes and run `bash scripts/pr/pre_pr_check.sh` before a PR (see Definition of Done)

## Skill routing

When the user's request matches an available skill, invoke it via the Skill tool. When in doubt, invoke the skill.

Key routing rules:
- Product ideas/brainstorming → invoke /office-hours
- Strategy/scope → invoke /plan-ceo-review
- Architecture → invoke /plan-eng-review
- Design system/plan review → invoke /design-consultation or /plan-design-review
- Full review pipeline → invoke /autoplan
- Bugs/errors → invoke /investigate
- QA/testing site behavior → invoke /qa or /qa-only
- Code review/diff check → invoke /review
- Visual polish → invoke /design-review
- Ship/deploy/PR → invoke /ship or /land-and-deploy
- Save progress → invoke /context-save
- Resume context → invoke /context-restore

## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

Rules:
- For codebase questions, first run `graphify query "<question>"` when graphify-out/graph.json exists. Use `graphify path "<A>" "<B>"` for relationships and `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep output.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).
