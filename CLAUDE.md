# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with this MCP Memory Service repository. It is written to be self-sufficient: a model should be able to work correctly here from this file alone, without filling gaps from prior knowledge.

> **Personal Customizations**: You can create `CLAUDE.local.md` (gitignored) for personal notes, custom workflows, or environment-specific instructions. This file contains shared project conventions.

> **Information Lookup**: Files first, memory second, user last. See [`.claude/directives/memory-first.md`](.claude/directives/memory-first.md) for strategy. Comprehensive project context is stored in the MCP Memory Server with tag `claude-code-reference`.

## Non-Negotiables (hard rules)

Quick reference; each rule is expanded in the sections below. Violations cause real incidents.

1. **This repo lives on Codeberg, not GitHub.** `origin` is `codeberg.org:doobidoo/mcp-memory-service`; CI is Forgejo Actions (`.forgejo/workflows/`). The `github` remote is a suspended mirror — do **not** use `gh` or `github.com` URLs for CI, releases, or issues.
2. **Never manually bump versions.** Use the `codeberg-release-manager` agent for every version bump and release.
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

## Critical Directives

**IMPORTANT**: Before working with this project, read:
- **`.claude/directives/memory-tagging.md`** - MANDATORY: Always tag memories with `mcp-memory-service` as first tag
- **`.claude/directives/README.md`** - Additional topic-specific directives

## Operational Rules

**These rules apply to every session. Violations cause real incidents — follow them exactly.**

### Memory Storage
- **Always use the MCP Memory Server** (`mcp__memory__memory_store`) for storing context, learnings, and decisions
- **Never write to `MEMORY.md` or local memory files** unless the user explicitly asks for file-based storage
- Tag all memories with `mcp-memory-service` as the first tag (per `memory-tagging.md`)

### MCP Configuration
- **MCP server configs go in `.mcp.json`**, not in `settings.json`
- `settings.json` is for Claude Code settings (hooks, plugins, permissions) only

### SSH / Network Safety
- **Before any SSH or network task**: confirm machine identity with `hostname` and verify connection direction (source → target)
- **Never assume** which machine you're on or which direction a connection flows — always verify first
- This prevents accidental operations on production machines or reverse-direction tunnels

### Auto-Save Learnings
- **After completing tasks**: automatically save key learnings, decisions, and patterns to the MCP Memory Server without being asked
- Include relevant tags: `mcp-memory-service`, task-specific tags, and `learnings`

### Source Control & Hosting (Codeberg, not GitHub)
- **`origin` is Codeberg**: `git@codeberg.org:doobidoo/mcp-memory-service.git`. CI runs as **Forgejo Actions** in `.forgejo/workflows/` (`ci.yml`, `release.yml`, `deploy-site.yml`, `cleanup-images.yml`). There is no `.github/workflows/` directory.
- **The `github` remote is a suspended mirror.** Do not use `gh` CLI, `github.com` URLs, or GitHub Actions for CI/release/issue work. Issues and PRs are on Codeberg.
- **GHSA identifiers** (e.g. `GHSA-2r68-g678-7qr3`) are just advisory IDs and remain valid references.

### Release Workflow Checklist
Before merging or releasing:
1. **Verify CI is green on the target branch** (Forgejo Actions on Codeberg). Most convenient: let the `codeberg-release-manager` agent check and drive the release. Manual check: `tea` CLI (Forgejo/Gitea) if configured, otherwise the Actions tab at `https://codeberg.org/doobidoo/mcp-memory-service`.
2. **Update `site/index.html` version strings** whenever MAJOR.MINOR changes (i.e. every MINOR or MAJOR release — PATCH releases are exempt). The `version-drift-check` CI gate enforces this and will fail if skipped. Update ALL occurrences: `<title>`, `<meta og:title>`, hero badge, "What's New" section, release link `href`. Use `grep -n "v11\." site/index.html` to find them. This is MANDATORY — not optional for "incremental" releases. The site auto-deploys to Cloudflare Pages (mcpmemory.services) when the change lands on main (`.forgejo/workflows/deploy-site.yml`).
3. Clean up merged branches after release (`git branch -d`, `git push origin --delete`).
4. Use the `codeberg-release-manager` agent — never manually bump versions.

## Overview

MCP Memory Service is a semantic memory layer for AI applications, accessible via REST API and MCP transport. It provides persistent storage for 14+ AI clients including Claude Desktop, OpenCode, LangGraph, CrewAI, and any HTTP client. It uses vector embeddings for semantic search, supports multiple storage backends (SQLite-vec, Cloudflare, Hybrid), and includes advanced features like memory consolidation, quality scoring, and OAuth 2.1 team collaboration.

**Current Version:** v11.4.0 - MINOR release: memory merge action (#100, @filhocf), pluggable domain NER extractors (#54, @filhocf), mcpmemory.services landing page — see [CHANGELOG.md](CHANGELOG.md) for details. (Issue/PR numbers refer to Codeberg.)

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

### High-Level Structure

Principal packages under `src/mcp_memory_service/` (not exhaustive — run `ls src/mcp_memory_service/` for the full list):

```
src/mcp_memory_service/
├── server/           # MCP server layer (modular, cache-optimized) + handlers/
├── server_impl.py    # MemoryServer: list_tools()/call_tool() + tool-handler methods
├── mcp_server.py     # MCP server entry wiring
├── tools/            # Declarative tool registry (registry.py) + dispatch table (routing.py)
├── storage/          # Storage backends (Strategy Pattern) + graph.py
├── web/              # FastAPI dashboard + REST API + OAuth + MCP-over-HTTP
├── api/              # Shared API layer (compact types, operations)
├── services/         # Business logic (MemoryService orchestrator)
├── quality/          # AI quality scoring (multi-tier)
├── scoring/          # Scoring / ranking helpers
├── consolidation/    # Dream-inspired memory maintenance
├── reasoning/        # Relationship / inference logic
├── embeddings/       # ONNX embeddings (sentence-transformers)
├── ingestion/        # Document loaders (PDF, DOCX, TXT, JSON, CSV)
├── harvest/          # Memory harvesting
├── sync/             # Hybrid backend sync
├── discovery/        # mDNS / service discovery
├── backup/           # Backup scheduler
├── health/           # Health checks
├── cli/              # `memory` lifecycle CLI (launch/stop/restart/info/logs)
├── config/           # Configuration
├── plugins/          # Plugin hooks
├── models/           # Data models and schemas
├── compat.py         # Compatibility shims + _sanitize_log_value()
└── utils/            # Utilities (health checks, startup orchestrator)
```

### MCP Server Layer (`server/`)

**Evolution:** Extracted from a monolithic 5000+ line `server.py` to a modular architecture (v8.59.0). In v11 the tool definitions and dispatch were made fully declarative.

**Key Components:**
- **`server_impl.py`** - Main `MemoryServer` class. `list_tools()` builds the tool list from the declarative registry; `call_tool()` dispatches via the routing table. Also holds the `handle_*` tool-handler methods.
- **`tools/registry.py`** - `TOOL_REGISTRY`: the declarative list of `ToolDef` objects (28 tools as of v11.4.0). Each `ToolDef` maps 1:1 to a `types.Tool`. Count: `grep -c 'ToolDef(' src/mcp_memory_service/tools/registry.py`.
- **`tools/routing.py`** - `ROUTING_TABLE` (name → handler) + `resolve_handler(name)` (lazy import). Replaced the former ~59-branch elif chain in `call_tool()`.
- **`server/handlers/`** - Modular request handlers: `memory.py`, `quality.py`, `consolidation.py`, `graph.py`, `documents.py`, `mistake_notes.py`, `utility.py`. Signature: `async def handle_X(server, arguments) -> List[types.TextContent]`.
- **`cache_manager.py`** - Global caching for a large performance boost (see Performance Characteristics)
- **`client_detection.py`** - Adapts behavior for Claude Desktop vs LM Studio
- **`logging_config.py`** - Client-aware logging
- **`environment.py`** - Python path setup, version checks

**Pattern:** Global singleton caching prevents redundant storage initialization across MCP tool calls.

### Storage Backend Architecture (`storage/`)

**Strategy Pattern** with 3 implementations sharing the `BaseStorage` interface:

| Backend | File | Performance | Use Case |
|---------|------|-------------|----------|
| **SQLite-Vec** | `sqlite_vec.py` | 5ms reads | Development, single-user |
| **Cloudflare** | `cloudflare.py` | Network-dependent | Cloud-only, edge deployment |
| **Hybrid** | `hybrid.py` | 5ms local + cloud sync | **Production (RECOMMENDED)** |

**Key Features:**
- All implement `BaseStorage` interface (`base.py`)
- SQLite-Vec uses the sqlite-vec extension for KNN semantic search
- Cloudflare uses D1 (SQL) + Vectorize (vector index)
- Hybrid: Local SQLite-Vec for reads, background Cloudflare sync
- Graph storage in `graph.py` (v8.51.0) - 30x query performance

**Embeddings:** ONNX model (sentence-transformers/all-MiniLM-L6-v2) for lightweight vector generation

### Web Layer (`web/`)

**FastAPI-based REST API and dashboard:**
- **`app.py`** - Main FastAPI application
- **`api/`** - REST endpoints mirroring MCP tools
- **`api/mcp.py`** - MCP-over-HTTP transport
- **`oauth/`** - OAuth 2.1 Dynamic Client Registration (v7.0.0+)
- **`sse.py`** - Server-Sent Events for real-time updates
- **`static/`** - Single-page dashboard application

**Key Pattern:** The HTTP API provides the same functionality as the MCP tools for team collaboration. The MCP-over-HTTP endpoint is a thin protocol shim — its tool surface and dispatch logic are inherited from the shared `MemoryServer`. Tools that read caller-supplied filesystem paths are filtered out of the remote transport by `local_only_tools()` (confused-deputy guard).

### Quality System (`quality/`)

**Multi-tier AI quality scoring** (v8.45.0+):

| Tier | Provider | Latency | Cost | Use Case |
|------|----------|---------|------|----------|
| 1 | Local ONNX | 80-150ms | $0 | **DEFAULT** - Fast, private |
| 2 | Groq/Llama 3 | 500-800ms | $0.0015 | Fallback if local fails |
| 3 | Gemini 1.5 Flash | 1-2s | $0.01 | High-accuracy scoring |

**Files:**
- `onnx_ranker.py` - Local ML-based quality scoring
- `ai_evaluator.py` - Cloud LLM scoring (Groq, Gemini)
- `async_scorer.py` - Async quality evaluation orchestrator
- `implicit_signals.py` - Access count, recency signals

**Usage:** Quality scores (0.0-1.0) used in quality-boosted search and retention policies.

### Consolidation System (`consolidation/`)

**Dream-inspired memory maintenance** (v8.23.0+):

**Components:**
- `decay.py` - Exponential decay scoring (importance × recency)
- `association_discovery.py` - Find semantic relationships
- `relationship_inference.py` - Intelligent relationship type classification (v9.3.0+)
- `compression.py` - Semantic clustering and merging
- `forgetting.py` - Quality-based archival (High: 365d, Medium: 180d, Low: 30-90d)
- `scheduler.py` - Automatic consolidation scheduling (daily/weekly/monthly)

**Relationship Inference Engine (v9.3.0+):**
- Multi-factor analysis: memory type combinations, content semantics, temporal patterns, contradictions
- Automatic classification: causes, fixes, contradicts, supports, follows, related
- Confidence scoring (0.0-1.0) with default threshold of 0.6
- Integrated into association discovery - new associations automatically get inferred relationship types
- Retroactive updates: Use `scripts/maintenance/update_graph_relationship_types.py` for existing relationships

**Pattern:** Runs via HTTP API (90% token reduction vs MCP tools) with APScheduler.

### Document Ingestion (`ingestion/`)

**Pluggable loader architecture:**
- **`base.py`** - Abstract `DocumentLoader` interface
- **`registry.py`** - Automatic loader selection by file extension
- **Loaders:** `pdf_loader.py`, `text_loader.py`, `json_loader.py`, `csv_loader.py`
- **`semtools_loader.py`** - Optional LlamaParse integration (enhanced PDF/DOCX/PPTX)
- **`chunker.py`** - Intelligent text chunking (1000 chars, 200 overlap)

**Pattern:** Registry pattern allows easy addition of new document types.

## Test Architecture

### Structure (~2,400+ tests across ~216 files)

Illustrative layout (subdirectories mirror `src/`):
```
tests/
├── api/              # API layer tests (compact types, operations)
├── storage/          # Backend-specific tests (sqlite_vec, cloudflare, hybrid)
├── server/           # MCP server handler tests
├── consolidation/    # Memory maintenance tests
├── quality/          # Quality scoring tests
├── web/              # HTTP API and OAuth tests
├── conftest.py       # Shared fixtures
└── pytest.ini        # Test configuration
```

### Key Fixtures (`conftest.py`)
- **`temp_db_path`** - Temporary database directory (auto-cleanup)
- **`unique_content`** - Generate unique test content to avoid duplicates
- **`test_store`** - Auto-tags memories with `__test__` for cleanup
- **`TEST_MEMORY_TAG = "__test__"`** - Reserved tag for automatic test cleanup

### Test Safety (Critical - PR #438)
**Triple Safety System** prevents production database deletion:
1. **Forced Test Database Path**: `conftest.py` creates an isolated temp directory with `mcp-test-` prefix at module import time
2. **Pre-Test Verification**: `pytest_sessionstart` aborts the test run if a production path is detected
3. **Triple-Check Cleanup**: `pytest_sessionfinish` validates temp location + no production indicators + test markers present

**Backend Isolation**: Tests automatically override `MCP_MEMORY_STORAGE_BACKEND` to `sqlite_vec` unless `MCP_TEST_ALLOW_CLOUD_BACKEND=true`

**Incident History**: Feb 8, 2026 - Test cleanup deleted 8,663 production memories. Resolved via emergency backup recovery + comprehensive safeguards (PR #438).

### Test Markers (defined in `pytest.ini`)
```python
@pytest.mark.unit         # Fast unit tests
@pytest.mark.integration  # Integration tests (require storage)
@pytest.mark.performance  # Performance benchmarks
@pytest.mark.asyncio      # Async tests (auto-detected)
```

### Running Tests by Category
```bash
pytest -m unit           # Unit tests only
pytest -m integration    # Integration tests
pytest -m performance    # Performance benchmarks
pytest -k "test_store"   # Tests matching name pattern
```

## Configuration

### Environment Variables

**Quick Reference** (full list in `.env.example`):

```bash
# Storage Backend
export MCP_MEMORY_STORAGE_BACKEND=hybrid  # hybrid|cloudflare|sqlite_vec

# Cloudflare (required for hybrid/cloudflare)
export CLOUDFLARE_API_TOKEN="your-token"
export CLOUDFLARE_ACCOUNT_ID="your-account"
export CLOUDFLARE_D1_DATABASE_ID="your-db-id"
export CLOUDFLARE_VECTORIZE_INDEX="mcp-memory-index"

# HTTP Server
export MCP_HTTP_ENABLED=true
export MCP_HTTP_PORT=8000
export MCP_API_KEY="your-secure-key"

# OAuth (v9.0.6+)
export MCP_OAUTH_STORAGE_BACKEND=sqlite   # memory|sqlite
export MCP_OAUTH_SQLITE_PATH=./data/oauth.db

# Quality System (v8.45.0+)
export MCP_QUALITY_SYSTEM_ENABLED=true

# Consolidation (v8.23.0+)
export MCP_CONSOLIDATION_ENABLED=true

# SQLite Concurrent Access (CRITICAL for HTTP + MCP servers)
export MCP_MEMORY_SQLITE_PRAGMAS=journal_mode=WAL,busy_timeout=15000,cache_size=20000

# Initialization Timeout (Windows users may need to increase this)
# Default: 30s on Windows, 15s on Linux/macOS (auto-doubled on first run)
# export MCP_INIT_TIMEOUT=120        # Increase for slow Windows systems
```

**Configuration Precedence:** Environment variables > .env file > Global Claude Config > defaults

**Important:** After updating `.env`, always restart servers. Use `memory restart` (preferred CLI) or `./scripts/update_and_restart.sh` (legacy) for the automated workflow.

**CRITICAL:** `MCP_MEMORY_SQLITE_PRAGMAS` must include `journal_mode=WAL` for concurrent access. Omitting WAL disables concurrent reads/writes and causes "database is locked" errors when the HTTP server and MCP server run simultaneously.

**RECOMMENDED for Hybrid mode:** Set `MCP_HYBRID_SYNC_OWNER=http` so that only the HTTP server syncs to Cloudflare. With this setting the MCP server (Claude Desktop) skips Cloudflare initialization entirely and uses SQLite-Vec directly — no Cloudflare credentials needed in `claude_desktop_config.json`. The HTTP server (running `run_http_server.py` with `.env`) handles all background sync. This is the correct separation of concerns: Claude Desktop = memory access, HTTP server = sync infrastructure.

### External Embedding APIs

**Note:** Only supported with the `sqlite_vec` backend (not compatible with `hybrid` or `cloudflare`).

```bash
export MCP_EXTERNAL_EMBEDDING_URL=http://localhost:8890/v1/embeddings
export MCP_EXTERNAL_EMBEDDING_MODEL=nomic-embed-text
export MCP_EXTERNAL_EMBEDDING_API_KEY=sk-xxx  # Optional
```

**Supported backends:** vLLM, Ollama, Text Embeddings Inference (TEI), OpenAI, or any OpenAI-compatible `/v1/embeddings` endpoint.

**Important:** Embedding dimensions must match your database schema. Changing dimensions requires re-embedding all memories. See [`docs/deployment/external-embeddings.md`](docs/deployment/external-embeddings.md) for details.

### Claude Desktop Integration

**Recommended configuration** (`~/.claude/config.json`):

```json
{
  "mcpServers": {
    "memory": {
      "command": "python",
      "args": ["-m", "mcp_memory_service.server"],
      "env": {
        "MCP_MEMORY_STORAGE_BACKEND": "hybrid"
      }
    }
  }
}
```

**Alternative:** Use `uv run memory server` or a direct script path (see v6.17.0+ migration notes in README).

## Development Guidelines

### Code Quality Standards

**Three-layer quality strategy:**
1. **Pre-commit** (<5s) - Groq/Gemini complexity + security (blocks: complexity >8, security issues)
2. **PR Quality Gate** (10-60s) - `bash scripts/pr/pre_pr_check.sh` (blocks: security, health <50)
3. **Periodic Review** (weekly) - pyscn analysis + trend tracking

**Health Score Thresholds:**
- `<50`: Release blocker (cannot merge)
- `50-69`: Action required (refactor within 2 weeks)
- `70+`: Continue development

**Utility Modules Pattern** (v8.61.0 - Phase 3 Refactoring):
- Strategy Pattern: `utils/health_check.py` (5 strategies)
- Orchestrator Pattern: `utils/startup_orchestrator.py` (3 orchestrators)
- Processor Pattern: `utils/directory_ingestion.py` (3 processors)
- Analyzer Pattern: `utils/quality_analytics.py` (3 analyzers)

**Target:** All complexity A-B grade (complexity ≤8)

**Log Injection Guard** (added v10.68.0 — CodeQL GHSA-84hp-mqvj-3p8h lessons):
- **NEVER** log user-provided values in raw f-strings: `logger.info(f"Stored: {content}")` triggers CodeQL `py/log-injection`
- **ALWAYS** wrap with `_sanitize_log_value()` from `src/mcp_memory_service/compat.py`:
  ```python
  from mcp_memory_service.compat import _sanitize_log_value
  logger.info(f"Stored: {_sanitize_log_value(content)}")
  ```
- `_sanitize_log_value()` strips `\n`, `\r`, `\x1b` — prevents log-forging and ANSI injection
- `pre_pr_check.sh` now detects f-string logger calls without this wrapper (check 6.5)
- Path injection: always validate with `Path(user_input).resolve()` and check it is under the expected base dir

### External Data Parsers
- **Always inspect real data first**: Download and inspect a sample of the real data BEFORE writing parsers or tests. Never trust API docs or project pages alone — real JSON structures often differ from descriptions (e.g., LoCoMo observations are nested dicts, not newline-separated strings).

### Development Workflow

**Read first:**
- [`.claude/directives/development-setup.md`](.claude/directives/development-setup.md) - Editable install
- [`.claude/directives/pr-workflow.md`](.claude/directives/pr-workflow.md) - Pre-PR checks (MANDATORY)
- [`.claude/directives/refactoring-checklist.md`](.claude/directives/refactoring-checklist.md) - Refactoring safety
- [`.claude/directives/version-management.md`](.claude/directives/version-management.md) - Release workflow (HOW)
- [`.claude/directives/release-cadence.md`](.claude/directives/release-cadence.md) - Release batching (WHEN)

**Quick workflow:**
1. `pip install -e .` - Install in editable mode (via `.venv`)
2. Make changes
3. `pytest` - Run tests (`.venv/bin/pytest`)
4. `bash scripts/pr/pre_pr_check.sh` - Pre-PR validation (MANDATORY)
5. Create PR - **IMPORTANT: Use the `codeberg-release-manager` agent for ALL version bumps and releases**

**Release Protocol (MANDATORY)**:
- **NEVER manually bump versions** - always use the `codeberg-release-manager` agent
- The agent handles: version bump, CHANGELOG update, `_version.py` sync, PR creation, release notes
- Ensures consistency across `pyproject.toml`, `_version.py`, CHANGELOG, and the Codeberg release
- Example: After merging a feature PR, invoke the `codeberg-release-manager` agent to create the release

**Dashboard changes (`web/static/`):** Verify in a browser before merging. Dashboard JS lacks automated test coverage — PRs touching this area should include manual testing evidence or screenshots.

**Memory Tagging:** Always tag memories with `mcp-memory-service` as first tag (see `.claude/directives/memory-tagging.md`)

**Removing a feature:** When removing a feature or changing a port/command, run `grep -r "<term>" docs/ README.md` and clean up references in the same PR. CI catches new dead refs via `scripts/ci/check_dead_refs.sh` (also run as a Forgejo Actions workflow on docs changes).

### Common Development Tasks

**Add a new MCP tool:** Tools are declarative as of v11 — the old inline `types.Tool(...)` list in `list_tools()` and the `call_tool()` elif chain were **both removed**. The current flow:
1. **Define the tool:** add a `ToolDef(name, description, input_schema, annotations)` to `TOOL_REGISTRY` in `src/mcp_memory_service/tools/registry.py`. Each `ToolDef` maps 1:1 to a `types.Tool`. Set `annotations={"readOnlyHint": True, ...}` if the tool does not mutate state — annotations drive OAuth scope; without `readOnlyHint` the HTTP `/mcp` layer treats it as a write tool and requires the OAuth `write` scope (GHSA-2r68-g678-7qr3).
2. **Implement the handler** in `src/mcp_memory_service/server/handlers/*.py` with the shape `async def handle_X(server, arguments) -> List[types.TextContent]`.
3. **Route it:** add `"<tool_name>": <handler>` to `ROUTING_TABLE` in `src/mcp_memory_service/tools/routing.py`. Use a module-function reference for handler-module functions, or the `("__self__", "handle_X")` tuple to dispatch to a `MemoryServer` method. `call_tool()` resolves handlers via `resolve_handler(name)` (lazy import).
4. **If the tool reads a caller-supplied filesystem path** (`project_path`, `file_path`, `directory_path`), add its name to `local_only_tools()` in `server_impl.py` so the HTTP shim will not expose it (confused-deputy guard).
5. **Add tests** in `tests/server/test_handlers.py`.
6. **Renaming a tool is a breaking change.** The v11 alias layer (`compat.DEPRECATED_TOOLS`) was removed (Issue #53), so a rename drops the old name outright. Avoid renames; if unavoidable, treat it as a major-version change and document the migration in `docs/MIGRATION.md`.

**Add a new storage backend:**
1. Implement the `BaseStorage` interface from `src/mcp_memory_service/storage/base.py`
2. Add a factory method in `src/mcp_memory_service/storage/factory.py`
3. Add tests in `tests/storage/test_<backend>.py`
4. Update configuration options

**Add a new document loader:**
1. Implement the `DocumentLoader` interface from `src/mcp_memory_service/ingestion/base.py`
2. Register the loader in `src/mcp_memory_service/ingestion/registry.py`
3. Add tests in `tests/ingestion/test_<loader>.py`

**Improve memory ontology and relationship types:**
1. **Memory types:** Run `scripts/maintenance/improve_memory_ontology.py` to re-classify memory types using high-confidence patterns
2. **Relationship types:** Run `scripts/maintenance/update_graph_relationship_types.py` to infer relationship types for existing associations
3. **Test first:** Both scripts support `--dry-run` to preview changes before applying
4. **Cleanup:** Use `scripts/maintenance/cleanup_memories.py` to remove test memories and orphaned data

### Memory Field Access Pattern (CRITICAL)

**ALWAYS use direct attribute access on Memory objects. NEVER access via the metadata dict.**

This anti-pattern has caused 3 production bugs (v10.13.1: PRs #466, #467, #469).

**Memory Dataclass Structure:**
```python
@dataclass
class Memory:
    content: str
    content_hash: str
    tags: List[str] = field(default_factory=list)      # TOP-LEVEL FIELD
    memory_type: Optional[str] = None                  # TOP-LEVEL FIELD
    metadata: Dict[str, Any] = field(default_factory=dict)  # SEPARATE - for custom data only
```

**WRONG - Common Anti-Patterns:**
```python
# WRONG - reads from metadata dict (returns default even if field exists)
memory.metadata.get('tags', [])           # Always returns []
memory.metadata.get('memory_type', '')    # Always returns ''

# WRONG - dict-style access (raises AttributeError)
memory['content_hash']
memory['tags']
```

**CORRECT - Direct Attribute Access:**
```python
# CORRECT - access top-level fields directly
memory.tags              # Returns actual tags list
memory.memory_type       # Returns actual memory type
memory.content_hash      # Returns hash string
memory.created_at        # Returns timestamp

# Safe with fallback
memory.tags or []
memory.memory_type or ''
```

**Production Bugs Caused by This Pattern:**
1. **PR #466 (CRITICAL)**: `retrieve_memories()` broke the REST API - all filtered queries returned 0 results
2. **PR #467 (HIGH)**: Tags displayed as individual characters ("python" -> "p,y,t,h,o,n")
3. **PR #469 (HIGH)**: Prompt handlers crashed with AttributeError

**Key Insight:** `Memory.metadata` is for **custom key-value pairs only**, NOT standard fields (tags, memory_type, etc.). Standard fields are top-level dataclass attributes.

**Prevention:**
- Use type hints to catch dict-style access
- Code review: Flag any `metadata.get('tags')` or `metadata.get('memory_type')` patterns
- Add a linting rule to detect this anti-pattern

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
- [ ] Version bumped via the `codeberg-release-manager` agent (never by hand) — keeps `pyproject.toml`, `_version.py`, CHANGELOG, and the Codeberg release in sync.
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

## Agent Integrations

**Workflow automation:**
- **codeberg-release-manager** - Complete release workflow (version bump, CHANGELOG, `_version.py` sync, PR creation, release notes). Use for ALL releases.
- **changelog-archival** - Maintains a lean CHANGELOG by archiving older versions
- **amp-automation** - Coding tasks + PR quality analysis with Amp CLI
- **code-quality-guard** - Quality analysis before commits
- **gemini-pr-automator** - Automated PR reviews and fixes

**Usage:** See [`.claude/directives/agents.md`](.claude/directives/agents.md) for complete workflows.

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
- **CHANGELOG.md** - Every version bump (use the `codeberg-release-manager` agent)
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

# context-mode — MANDATORY routing rules

You have context-mode MCP tools available. These rules are NOT optional — they protect your context window from flooding. A single unrouted command can dump 56 KB into context and waste the entire session.

## BLOCKED commands — do NOT attempt these

### curl / wget — BLOCKED
Any Bash command containing `curl` or `wget` is intercepted and replaced with an error message. Do NOT retry.
Instead use:
- `ctx_fetch_and_index(url, source)` to fetch and index web pages
- `ctx_execute(language: "javascript", code: "const r = await fetch(...)")` to run HTTP calls in sandbox

### Inline HTTP — BLOCKED
Any Bash command containing `fetch('http`, `requests.get(`, `requests.post(`, `http.get(`, or `http.request(` is intercepted and replaced with an error message. Do NOT retry with Bash.
Instead use:
- `ctx_execute(language, code)` to run HTTP calls in sandbox — only stdout enters context

### WebFetch — BLOCKED
WebFetch calls are denied entirely. The URL is extracted and you are told to use `ctx_fetch_and_index` instead.
Instead use:
- `ctx_fetch_and_index(url, source)` then `ctx_search(queries)` to query the indexed content

## REDIRECTED tools — use sandbox equivalents

### Bash (>20 lines output)
Bash is ONLY for: `git`, `mkdir`, `rm`, `mv`, `cd`, `ls`, `npm install`, `pip install`, and other short-output commands.
For everything else, use:
- `ctx_batch_execute(commands, queries)` — run multiple commands + search in ONE call
- `ctx_execute(language: "shell", code: "...")` — run in sandbox, only stdout enters context

### Read (for analysis)
If you are reading a file to **Edit** it → Read is correct (Edit needs content in context).
If you are reading to **analyze, explore, or summarize** → use `ctx_execute_file(path, language, code)` instead. Only your printed summary enters context. The raw file content stays in the sandbox.

### Grep (large results)
Grep results can flood context. Use `ctx_execute(language: "shell", code: "grep ...")` to run searches in sandbox. Only your printed summary enters context.

## Tool selection hierarchy

1. **GATHER**: `ctx_batch_execute(commands, queries)` — Primary tool. Runs all commands, auto-indexes output, returns search results. ONE call replaces 30+ individual calls.
2. **FOLLOW-UP**: `ctx_search(queries: ["q1", "q2", ...])` — Query indexed content. Pass ALL questions as array in ONE call.
3. **PROCESSING**: `ctx_execute(language, code)` | `ctx_execute_file(path, language, code)` — Sandbox execution. Only stdout enters context.
4. **WEB**: `ctx_fetch_and_index(url, source)` then `ctx_search(queries)` — Fetch, chunk, index, query. Raw HTML never enters context.
5. **INDEX**: `ctx_index(content, source)` — Store content in FTS5 knowledge base for later search.

## Subagent routing

When spawning subagents (Agent/Task tool), the routing block is automatically injected into their prompt. Bash-type subagents are upgraded to general-purpose so they have access to MCP tools. You do NOT need to manually instruct subagents about context-mode.

## Output constraints

- Keep responses under 500 words.
- Write artifacts (code, configs, PRDs) to FILES — never return them as inline text. Return only: file path + 1-line description.
- When indexing content, use descriptive source labels so others can `ctx_search(source: "label")` later.

## ctx commands

| Command | Action |
|---------|--------|
| `ctx stats` | Call the `ctx_stats` MCP tool and display the full output verbatim |
| `ctx doctor` | Call the `ctx_doctor` MCP tool, run the returned shell command, display as checklist |
| `ctx upgrade` | Call the `ctx_upgrade` MCP tool, run the returned shell command, display as checklist |

## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

Rules:
- For codebase questions, first run `graphify query "<question>"` when graphify-out/graph.json exists. Use `graphify path "<A>" "<B>"` for relationships and `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep output.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).
