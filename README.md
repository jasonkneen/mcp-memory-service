# mcp-memory-service

## Persistent Shared Memory for AI Agent Pipelines

Open-source memory backend for AI agents — **REST API, MCP, OAuth, CLI, dashboard**. One self-hosted service, every transport.
Agents store decisions, share causal knowledge graphs, and retrieve
context in 5ms — without cloud lock-in or API costs.

**Works with LangGraph · CrewAI · AutoGen · any HTTP client · Claude Desktop · OpenCode**

---

[![Website](https://img.shields.io/badge/Website-mcpmemory.services-00e5ff?logo=cloudflare&logoColor=white)](https://mcpmemory.services)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![PyPI version](https://img.shields.io/pypi/v/mcp-memory-service?color=blue&logo=pypi&logoColor=white)](https://pypi.org/project/mcp-memory-service/)
[![Python](https://img.shields.io/pypi/pyversions/mcp-memory-service?logo=python&logoColor=white)](https://pypi.org/project/mcp-memory-service/)
[![Codeberg stars](https://img.shields.io/gitea/stars/doobidoo/mcp-memory-service?gitea_url=https%3A%2F%2Fcodeberg.org&logo=codeberg&label=stars)](https://codeberg.org/doobidoo/mcp-memory-service)
[![Works with LangGraph](https://img.shields.io/badge/Works%20with-LangGraph-green)](https://github.com/langchain-ai/langgraph)
[![Works with CrewAI](https://img.shields.io/badge/Works%20with-CrewAI-orange)](https://crewai.com)
[![Works with AutoGen](https://img.shields.io/badge/Works%20with-AutoGen-purple)](https://github.com/microsoft/autogen)
[![Works with Claude](https://img.shields.io/badge/Works%20with-Claude-blue)](https://claude.ai)
[![Works with Cursor](https://img.shields.io/badge/Works%20with-Cursor-orange)](https://cursor.sh)
[![Remote MCP](https://img.shields.io/badge/MCP-Remote%20Support-blue?logo=anthropic)](docs/remote-mcp-setup.md)
[![claude.ai Browser Compatible](https://img.shields.io/badge/claude.ai-Browser%20Compatible-orange?logo=anthropic)](docs/remote-mcp-setup.md)
[![OAuth 2.0](https://img.shields.io/badge/Auth-OAuth%202.0%20%2B%20DCR-green)](docs/oauth-setup.md)

---

<div align="center">
  <video src="https://mcpmemory.services/assets/videos/knowledge-graph-3d.mp4" poster="https://mcpmemory.services/assets/images/knowledge-graph-3d-poster.png" width="820" autoplay loop muted playsinline controls>
    <a href="https://mcpmemory.services/"><img src="docs/assets/images/knowledge-graph-3d.png" alt="3D knowledge graph — memories as a glowing, interactive galaxy" width="820"></a>
  </video>
  <p><em>▶ <a href="https://mcpmemory.services/">The 3D knowledge graph in motion</a></em> — every memory a glowing node, every relationship a curved edge. <sub>(Video not playing? <a href="https://mcpmemory.services/">See it live at mcpmemory.services</a>.)</sub></p>
</div>

---

## 🎬 See It in Action

[![Watch the Dashboard Walkthrough](https://img.youtube.com/vi/W34r8VFoSdQ/maxresdefault.jpg)](https://youtu.be/W34r8VFoSdQ)

**[Watch the Web Dashboard Walkthrough on YouTube](https://youtu.be/W34r8VFoSdQ)** — Semantic search, tag browser, document ingestion, analytics, quality scoring, and API docs in under 2 minutes.

---

## 📰 In the Media

**[Agents Overdrawn at the Memory Bank](https://www.linkedin.com/pulse/humans-loop-deep-dive-agents-overdrawn-rbrcc/)** — Heavybit's *Humans in the Loop* deep dive talks to maintainer Heinrich Krupp about agent amnesia, why persistent memory is the missing infrastructure layer for agentic systems, and how mcp-memory-service closes the gap with local vector storage, ONNX embeddings, and typed knowledge graphs.

> "Your project has inspired me in many ways. In my view, it's the best implementation of MCP memory I've found so far."
> — **Michał Zubkowicz**

**[AI Tinkerers Zürich Talk](https://zurich.aitinkerers.org/talks/rsvp_DuHc2MBp1uo)** ([full video](https://drive.google.com/file/d/1NJDLetJ5CE7Jiek9OtyXCrt-zm768YB6/view)) — Maintainer Heinrich Krupp presents mcp-memory-service to the AI Tinkerers Zürich meetup, covering persistent memory architecture, semantic search, and multi-agent memory sharing.

---

## 🌐 Works with claude.ai (Browser)

Unlike desktop-only MCP servers, **mcp-memory-service supports Remote MCP** for native claude.ai integration.

**What this means:**
- ✅ Use persistent memory directly in your browser (no Claude Desktop required)
- ✅ Works on any device (laptop, tablet, phone)
- ✅ Enterprise-ready (OAuth 2.0 + HTTPS + CORS)
- ✅ Self-hosted OR cloud-hosted (your choice)

**5-Minute Setup:**

```bash
# 1. Start server with Remote MCP enabled
MCP_STREAMABLE_HTTP_MODE=1 \
MCP_SSE_HOST=0.0.0.0 \
MCP_SSE_PORT=8765 \
MCP_OAUTH_ENABLED=true \
python -m mcp_memory_service.server

# 2. Expose via Cloudflare Tunnel (or your own HTTPS setup)
cloudflared tunnel --url http://localhost:8765
# → Outputs: https://random-name.trycloudflare.com

# 3. In claude.ai: Settings → Connectors → Add Connector
# Paste the URL: https://random-name.trycloudflare.com/mcp
# OAuth flow will handle authentication automatically
```

**Production Setup:** See [Remote MCP Setup Guide](docs/remote-mcp-setup.md) for Let's Encrypt, nginx, and firewall configuration.
**Step-by-Step Tutorial:** [Blog: 5-Minute claude.ai Setup](https://mcpmemory.services/blog/remote-mcp-tutorial.html) | [Wiki Guide](https://codeberg.org/doobidoo/mcp-memory-service/wiki/Claude-AI-Remote-MCP-Integration)

---

## Why Agents Need This

| Without mcp-memory-service | With mcp-memory-service |
|---|---|
| Each agent run starts from zero | Agents retrieve prior decisions in 5ms |
| Memory is local to one graph/run | Memory is shared across all agents and runs |
| You manage Redis + Pinecone + glue code | One self-hosted service, zero cloud cost |
| No causal relationships between facts | Knowledge graph with typed edges (causes, fixes, contradicts) |
| Context window limits create amnesia | Autonomous consolidation compresses old memories |

**Key capabilities for agent pipelines:**
- **Framework-agnostic REST API** — 76 endpoints, no MCP client library needed
- **Knowledge graph** — agents share causal chains, not just facts
- **`X-Agent-ID` header** — auto-tag memories by agent identity for scoped retrieval
- **`conversation_id`** — bypass deduplication for incremental conversation storage
- **SSE events** — real-time notifications when any agent stores or deletes a memory
- **Embeddings run locally via ONNX** — memory never leaves your infrastructure

## Agent Quick Start

```bash
pip install mcp-memory-service
MCP_ALLOW_ANONYMOUS_ACCESS=true memory server --http
# REST API running at http://localhost:8000
```

```python
import asyncio
import httpx

BASE_URL = "http://localhost:8000"


async def main():
    async with httpx.AsyncClient() as client:
        # Store — auto-tag with X-Agent-ID header
        await client.post(f"{BASE_URL}/api/memories", json={
            "content": "API rate limit is 100 req/min",
            "tags": ["api", "limits"],
        }, headers={"X-Agent-ID": "researcher"})
        # Stored with tags: ["api", "limits", "agent:researcher"]

        # Search — scope to a specific agent
        results = await client.post(f"{BASE_URL}/api/memories/search", json={
            "query": "API rate limits",
            "tags": ["agent:researcher"],
        })
        print(results.json()["memories"])


asyncio.run(main())
```

**Framework-specific guides:** [docs/agents/](docs/agents/)

### Real-World: Multi-Agent Cluster with Shared Memory

> *"After I work with one of the cluster agents on something I want my local agent to know about, the cluster agent adds a special tag to the memory entry that my local agent recognizes as a message from a cluster agent. So they end up using it as a comms bridge — and it's pretty delightful."*
> — [@jeremykoerber](https://github.com/jeremykoerber) (originally GitHub issue #591)

A 5-agent openclaw cluster uses mcp-memory-service as shared state **and** as an inter-agent messaging bus — without any custom protocol. Cluster agents tag memories with a sentinel like `msg:cluster`, and the local agent filters on that tag to receive cross-cluster signals. The memory service becomes the coordination layer with zero additional infrastructure.

```python
# Cluster agent stores a learning and flags it for the local agent
await client.post(f"{BASE_URL}/api/memories", json={
    "content": "Rate limit on provider X is 50 RPM — switch to provider Y after 40",
    "tags": ["api", "limits", "msg:cluster"],       # sentinel tag
}, headers={"X-Agent-ID": "cluster-agent-3"})

# Local agent polls for cluster messages
results = await client.post(f"{BASE_URL}/api/memories/search", json={
    "query": "messages from cluster",
    "tags": ["msg:cluster"],
})
```

This pattern — **tags as inter-agent signals** — emerges naturally from the tagging system and requires no additional infrastructure.

### Real-World: Self-Hosted Docker Stack with Cloudflare Tunnel

> *"The quality of life that session-independent memory adds to AI workflows is immense. File-based memory demands constant discipline. Semantic recall from a live database doesn't. Storing data on my own hardware while making it remotely accessible across platforms turned out to be a feature I didn't know I needed."*
> — [@PL-Peter](https://github.com/PL-Peter) (originally GitHub discussion #602)

A production-tested self-hosted deployment using Docker containers behind a Cloudflare tunnel, with [AuthMCP Gateway](https://github.com/loglux/authmcp-gateway) handling authentication:

| Layer | Role |
|-------|------|
| **Cloudflare Tunnel** | Name-based routing, subnet-based access control, authentication before hitting self-hosted resources |
| **AuthMCP Gateway** | Auth/aggregation with locally managed users, admin UI, per-user MCP server access control, bearer token auth |
| **mcp-memory-service** | Two Docker containers sharing one SQLite backend — one for MCP, one for the web UI (document ingestion) |

**Security best practices for this setup:**
- Use Cloudflare ZeroTrust with subnet-based access control (e.g., allow Anthropic subnets + your own IPs)
- Add **Client IP Address Filtering** to all Cloudflare API tokens (Dashboard → My Profile → API Tokens → Edit → Client IP Address Filtering) to limit abuse if a token leaks
- If using IPv6, include your IPv6 /64 network in the allowlist (Python prefers IPv6 by default)
- For long-running browser sessions, request the `offline_access` scope during authorization to receive a rotating `refresh_token` (lifetime via `MCP_OAUTH_REFRESH_TOKEN_EXPIRE_DAYS`, default 30 days). Without this scope, access tokens are the only credential — extend `MCP_OAUTH_ACCESS_TOKEN_EXPIRE_MINUTES` up to `1440` (24h) if you need longer single-shot sessions.
- Consider an auth proxy like [AuthMCP](https://github.com/loglux/authmcp-gateway) or [mcp-auth-proxy](https://github.com/sigbit/mcp-auth-proxy) for robust session management

## Comparison with Alternatives

### vs. Commercial Memory APIs

| | Mem0 | Zep | DIY Redis+Pinecone | **mcp-memory-service** |
|---|---|---|---|---|
| License | Proprietary | Enterprise | — | **Apache 2.0** |
| Cost | Per-call API | Enterprise | Infra costs | **$0** |
| **🌐 claude.ai Browser** | ❌ Desktop only | ❌ Desktop only | ❌ | **✅ Remote MCP** |
| **OAuth 2.0 + DCR** | ❓ Unknown | ❓ Unknown | ❌ | **✅ Enterprise-ready** |
| **Streamable HTTP** | ❌ | ❌ | ❌ | **✅ (SSE also supported)** |
| Framework integration | SDK | SDK | Manual | **REST API (any HTTP client)** |
| Knowledge graph | No | Limited | No | **Yes (typed edges)** |
| Auto consolidation | No | No | No | **Yes (decay + compression)** |
| On-premise embeddings | No | No | Manual | **Yes (ONNX, local)** |
| Privacy | Cloud | Cloud | Partial | **100% local** |
| Hybrid search | No | Yes | Manual | **Yes (BM25 + vector)** |
| MCP protocol | No | No | No | **Yes** |
| REST API | Yes | Yes | Manual | **Yes (76 endpoints)** |

### vs. MCP-Native Alternatives

[MemPalace](https://github.com/MemPalace/mempalace) is an MCP-native alternative that went viral in April 2026 with strong LongMemEval claims. A [community code review (Issue #27)](https://github.com/MemPalace/mempalace/issues/27) subsequently showed that the headline numbers reflect the underlying vector store rather than the advertised Palace architecture, and the maintainers acknowledged most points. We keep the comparison here for transparency, but readers should interpret the scores with that context in mind.

| | **MemPalace** | **mcp-memory-service** |
|---|---|---|
| LongMemEval R@5 (raw ChromaDB, zero LLM) | 96.6%¹ | 86.0% (session) / 80.4% (turn) |
| LongMemEval R@5 (with reranking) | 100%² | — |
| Storage granularity | Session-level | **Turn-level + session-level** |
| Team / multi-device sync | ❌ Local only | **✅ Cloudflare sync** |
| REST API / Web dashboard | ❌ | **✅** |
| OAuth 2.1 + multi-user | ❌ | **✅** |
| Knowledge graph | ❌ | **✅ (typed edges)** |
| Auto consolidation | ❌ | **✅ (decay + compression)** |
| Compatible AI tools | Claude-focused | **25+ tools** |
| License | MIT | **Apache 2.0** |

**Why the benchmark gap?** Two independent factors:

1. **Ingestion granularity.** MemPalace stores each conversation as a single unit (session-level). LongMemEval asks "which session contains the answer?" — a question that session-level storage answers structurally. mcp-memory-service defaults to turn-level storage (one entry per message), which enables fine-grained retrieval ("what exactly did the user say about X?") but spreads a session's signal across many entries. Using `memory_store_session` (added in v10.35.0) brings our score to **86.0% R@5**.
2. **What the 96.6% actually measures.** Per Issue #27, MemPalace's headline number is produced in "raw mode" — plain text stored in ChromaDB with default embeddings. The Palace architecture (Wings, Rooms, Halls) is **not active** in that configuration; "Halls" exist only as metadata strings with no effect on ranking. The 96.6% is therefore a ChromaDB + default-embedding baseline, not a measurement of MemPalace's structural retrieval features. A direct "apples-to-apples" architectural comparison is not possible with the published numbers.

> ¹ Measured in MemPalace "raw mode" (plain text in ChromaDB with default embeddings). Per [Issue #27](https://github.com/MemPalace/mempalace/issues/27), the Palace structural features are bypassed in this configuration.
>
> ² 100% result uses optional LLM reranking (~500 API calls) on a partially tuned test set. Clean held-out score (as reported by the maintainers): **98.4% R@5**.

---

## Stop Re-Explaining Your Project to AI Every Session

<p align="center">
  <img width="240" alt="MCP Memory Service" src="https://github.com/user-attachments/assets/eab1f341-ca54-445c-905e-273cd9e89555" />
</p>

Your AI assistant forgets everything when you start a new chat. After 50 tool uses, context explodes to 500k+ tokens—Claude slows down, you restart, and now it remembers nothing. You spend 10 minutes re-explaining your architecture. **Again.**

**MCP Memory Service solves this.**

It automatically captures your project context, architecture decisions, and code patterns. When you start fresh sessions, your AI already knows everything—no re-explaining, no context loss, no wasted time.

## 🎥 2-Minute Video Demo

<div align="center">
  <a href="https://www.youtube.com/watch?v=veJME5qVu-A">
    <img src="https://img.youtube.com/vi/veJME5qVu-A/maxresdefault.jpg" alt="MCP Memory Service Demo" width="700">
  </a>
  <p><em>Technical showcase: Performance, Architecture, AI/ML Intelligence & Developer Experience</em></p>
</div>

### ⚡ Works With Your Favorite AI Tools

#### 🤖 Agent Frameworks (REST API)
**LangGraph** · **CrewAI** · **AutoGen** · **Any HTTP Client** · **OpenClaw/Nanobot** · **Custom Pipelines**

#### 🖥️ CLI & Terminal AI (MCP)
**Claude Code** · **Gemini CLI** · **Gemini Code Assist** · **OpenCode** · **Codex CLI** · **Goose** · **Aider** · **GitHub Copilot CLI** · **Amp** · **Continue** · **Zed** · **Cody**

#### 🎨 Desktop & IDE (MCP)
**Claude Desktop** · **VS Code** · **Cursor** · **Windsurf** · **Kilo Code** · **Raycast** · **JetBrains** · **Replit** · **Sourcegraph** · **Qodo**

#### 💬 Chat Interfaces (MCP)
**ChatGPT** (Developer Mode) · **claude.ai** (Remote MCP via HTTPS)

**Works seamlessly with any MCP-compatible client or HTTP client** - whether you're building agent pipelines, coding in the terminal, IDE, or browser.

> **💡 NEW**: ChatGPT now supports MCP! Enable Developer Mode to connect your memory service directly. [See setup guide →](docs/remote-mcp-setup.md)

---

## 🚀 Get Started in 60 Seconds

> Not sure which setup fits your needs? See the **[Setup Guide](docs/setup-guide.md)** — a decision tree walks you to the right path in under a minute.

**1. Install:**

```bash
pip install mcp-memory-service
```

**2. Configure your AI client:**

<details open>
<summary><strong>Claude Desktop</strong></summary>

Add to your config file:
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "memory": {
      "command": "memory",
      "args": ["server"]
    }
  }
}
```

Restart Claude Desktop. Your AI now remembers everything across sessions.

</details>

<details>
<summary><strong>Claude Code</strong></summary>

```bash
claude mcp add memory -- memory server
```

Restart Claude Code. Memory tools will appear automatically.

</details>

<details>
<summary><strong>OpenCode</strong></summary>

Start the HTTP API:

```bash
MCP_ALLOW_ANONYMOUS_ACCESS=true memory server --http
```

Install the local plugin:

```bash
git clone https://codeberg.org/doobidoo/mcp-memory-service.git
cd mcp-memory-service
mkdir -p ~/.config/opencode/plugins
cp opencode/memory-plugin.js ~/.config/opencode/plugins/
cp opencode/memory-plugin.config.example.json ~/.config/opencode/memory-plugin.json
```

OpenCode automatically loads local plugins from `~/.config/opencode/plugins/` and `.opencode/plugins/`.

Optional: register the `/memory` slash command in `~/.config/opencode/opencode.json` to query status, search, and health from inside the TUI:

```json
{
  "command": {
    "memory": {
      "description": "Show MCP Memory Service status. Usage: /memory, /memory search <query>, /memory health",
      "template": ""
    }
  }
}
```

See [OpenCode integration guide](opencode/README.md) for configuration, project-local installs, slash command details, TUI toasts, and current limitations.

> The current OpenCode integration ships as repository files for the local plugin directory. If you installed only the PyPI package, clone the repository once to copy the plugin files.
>
> The plugin defaults to `http://127.0.0.1:8000`, but `memoryService.endpoint` and `OPENCODE_MEMORY_ENDPOINT` let you target any reachable HTTP deployment.

</details>

<details>
<summary><strong>🌐 claude.ai (Browser — Remote MCP)</strong></summary>

No local installation required on the client — works directly in your browser:

```bash
# 1. Start server with Remote MCP
MCP_STREAMABLE_HTTP_MODE=1 \
MCP_SSE_HOST=0.0.0.0 \
MCP_OAUTH_ENABLED=true \
python -m mcp_memory_service.server

# 2. Expose publicly (Cloudflare Tunnel)
cloudflared tunnel --url http://localhost:8765

# 3. Add connector in claude.ai Settings → Connectors with the tunnel URL
```

See [Remote MCP Setup Guide](docs/remote-mcp-setup.md) for production deployment with Let's Encrypt, nginx, and Docker.

</details>

<details>
<summary><strong>🔧 Advanced: Custom Backends & Team Setup</strong></summary>

For production deployments, team collaboration, or cloud sync:

```bash
git clone https://codeberg.org/doobidoo/mcp-memory-service.git
cd mcp-memory-service
python scripts/installation/install.py
```

Choose from:
- **SQLite** (local, fast, single-user)
- **Cloudflare** (cloud, multi-device sync)
- **Hybrid** (best of both: 5ms local + background cloud sync)
- **Milvus** (dedicated vector DB — Milvus Lite file, self-hosted, or Zilliz Cloud)

> ℹ️ For long-lived services (MCP servers, web backends, notebook sessions), prefer Docker Milvus or Zilliz Cloud over Milvus Lite. See [docs/milvus-backend.md](docs/milvus-backend.md#which-uri-to-use) for why.

</details>

---

## 🛠️ CLI Server Lifecycle Commands

In addition to `memory server --http` (foreground mode), the CLI now includes
server lifecycle commands for background HTTP management:

```bash
# Start HTTP server in background (default host=127.0.0.1, port=8000)
memory launch

# Start on a custom port
memory launch --port 8192

# Check status and health
memory info --port 8192
memory health --port 8192

# View recent logs and stop server
memory logs --lines 50
memory stop --port 8192
```

These commands are optimized for fast startup and avoid loading heavy ML
dependencies unless needed.

⚠️  **Security Note**: By default, the server binds to `127.0.0.1` (localhost only).
To expose the server on your network or allow remote access, you can use
`--host 0.0.0.0` or set `MCP_HTTP_HOST=0.0.0.0`. However, **this exposes the
API to your network** and should be done only in trusted environments with
proper authentication and firewall rules in production. For untrusted networks,
use TLS termination (reverse proxy with HTTPS) or VPN overlays.

---

## 💡 Why You Need This

### Embedding Model Selection

The default model (`all-MiniLM-L6-v2`) works well for **English-only** content. If you store memories in other languages, switch to a multilingual model:

| Model | Languages | Dimensions | Use case |
|-------|-----------|-----------|----------|
| `all-MiniLM-L6-v2` (default) | English only | 384 | Fastest, English-only deployments |
| `paraphrase-multilingual-MiniLM-L12-v2` | 50+ languages | 384 | Mixed-language or non-English content |

**Configuration:**

```bash
export MCP_EMBEDDING_MODEL=paraphrase-multilingual-MiniLM-L12-v2
```

> ⚠️ **Switching models requires re-embedding existing memories.** Memories embedded with the old model will have degraded search quality (cross-language cosine drops from ~0.95 to ~0.10).

**Re-embedding after model change:**

```bash
# Stop the service
memory stop  # or: systemctl --user stop memory-service

# Regenerate all embeddings with the new model
CUDA_VISIBLE_DEVICES="" MCP_EMBEDDING_MODEL=paraphrase-multilingual-MiniLM-L12-v2 \
  python scripts/maintenance/regenerate_embeddings.py

# Restart
memory launch  # or: systemctl --user start memory-service
```

### The Problem

| Session 1 | Session 2 (Fresh Start) |
|-----------|-------------------------|
| You: "We're building a Next.js app with Prisma and tRPC" | AI: "What's your tech stack?" ❌ |
| AI: "Got it, I see you're using App Router" | You: *Explains architecture again for 10 minutes* 😤 |
| You: "Add authentication with NextAuth" | AI: "Should I use Pages Router or App Router?" ❌ |

### The Solution

| Session 1 | Session 2 (Fresh Start) |
|-----------|-------------------------|
| You: "We're building a Next.js app with Prisma and tRPC" | AI: "I remember—Next.js App Router with Prisma and tRPC. What should we build?" ✅ |
| AI: "Got it, I see you're using App Router" | You: "Add OAuth login" |
| You: "Add authentication with NextAuth" | AI: "I'll integrate NextAuth with your existing Prisma setup." ✅ |

**Result:** Zero re-explaining. Zero context loss. Just continuous, intelligent collaboration.

---

## 🌐 SHODH Ecosystem Compatibility

MCP Memory Service is **fully compatible** with the [SHODH Unified Memory API Specification v1.0.0](https://github.com/varun29ankuS/shodh-memory/blob/main/specs/openapi.yaml), enabling seamless interoperability across the SHODH ecosystem.

### Compatible Implementations

| Implementation | Backend | Embeddings | Use Case |
|----------------|---------|------------|----------|
| **[shodh-memory](https://github.com/varun29ankuS/shodh-memory)** | RocksDB | MiniLM-L6-v2 (ONNX) | Reference implementation |
| **shodh-cloudflare** | Cloudflare Workers + Vectorize | Workers AI (bge-small) | Edge deployment, multi-device sync |
| **mcp-memory-service** (this) | SQLite-vec / Hybrid | MiniLM-L6-v2 (ONNX) | Desktop AI assistants (MCP) |

### Unified Schema Support

All SHODH implementations share the same memory schema:
- ✅ **Emotional Metadata**: `emotion`, `emotional_valence`, `emotional_arousal`
- ✅ **Episodic Memory**: `episode_id`, `sequence_number`, `preceding_memory_id`
- ✅ **Source Tracking**: `source_type`, `credibility`
- ✅ **Quality Scoring**: `quality_score`, `access_count`, `last_accessed_at`

**Interoperability Example:**
Export memories from mcp-memory-service → Import to shodh-cloudflare → Sync across devices → Full fidelity preservation of emotional_valence, episode_id, and all spec fields.

---

## ✨ Quick Start Features

🧠 **Persistent Memory** – Context survives across sessions with semantic search
🔍 **Smart Retrieval** – Finds relevant context automatically using AI embeddings
⚡ **5ms Speed** – Instant context injection, no latency
🔄 **Multi-Client** – Works across 25+ AI applications
☁️ **Cloud Sync** – Optional Cloudflare backend for team collaboration
🔒 **Privacy-First** – Local-first, you control your data
📊 **Web Dashboard** – Visualize and manage memories at `http://localhost:8000`
🧬 **Knowledge Graph** – Interactive D3.js visualization of memory relationships
🏠 **Homelab Quality Scoring** – Point scoring at any OpenAI-compatible endpoint (Ollama, LiteLLM, vLLM)
🔗 **Entity Extraction** – Auto-links @mentions, #tags, URLs, and file paths from memory content to a queryable entity graph
💡 **Insight Cards** – Consolidation detects patterns, trends, and knowledge gaps across your memory corpus and surfaces them as structured insights
🏷️ **Tag Match Filtering** – `tag_match=AND/OR` on `memory_search` for precise multi-tag queries

**Homelab / self-hosted quality scoring** (v10.45.0+): set `MCP_QUALITY_AI_PROVIDER=openai-compatible` to score memories with your local LLM instead of ONNX or a cloud API:

```bash
MCP_QUALITY_AI_PROVIDER=openai-compatible
MCP_QUALITY_AI_BASE_URL=http://localhost:11434/v1   # Ollama
MCP_QUALITY_AI_MODEL=qwen2.5:7b-instruct
# MCP_QUALITY_AI_API_KEY=ollama                     # optional
```

Recommended models: `qwen2.5:7b-instruct` (Ollama), `mlx-community/Qwen2.5-7B-Instruct-4bit` (MLX), or any instruct model via LiteLLM proxy. On endpoint failure, scoring falls back to implicit signals automatically.

**Docker `:quality-cpu` tag** — for users who want the built-in local ONNX quality scoring (`ms-marco-MiniLM-L-6-v2` and `nvidia-quality-classifier-deberta`) without managing the one-time ONNX export themselves, and without shipping `torch`/`transformers` in their container:

```bash
docker pull doobidoo/mcp-memory-service:quality-cpu
```

The `:quality-cpu` image pre-exports both models at build time and ships only `onnxruntime` at runtime — no PyTorch dependency at deploy time. See [`tools/docker/README.md`](tools/docker/README.md) for details.

### 🖥️ Dashboard Preview

<p align="center">
  <img src="https://codeberg.org/doobidoo/mcp-memory-service/wiki/raw/images/dashboard/mcp-memory-dashboard-v9.3.0-tour.gif" alt="MCP Memory Dashboard Tour" width="800"/>
</p>

**8 Dashboard Tabs:** Dashboard • Search • Browse • Documents • Manage • Analytics • Quality • API Docs

📖 See [Web Dashboard Guide](https://codeberg.org/doobidoo/mcp-memory-service/wiki/Web-Dashboard-Guide) for complete documentation.

---


## Latest Release: **v11.5.0** (July 10, 2026)

**MINOR: conditional temporal decay + functional belief derivation + consolidation clustering fix + bootstrap belief injection**

**What's New:**
- Conditional temporal decay for search relevance (#123, @filhocf): opt-in via `MEMORY_DECAY_WINDOW_DAYS` (default `0` = disabled, zero behavior change for existing users). Recent memories rank above older ones with equivalent similarity.
- Belief pipeline is now functional (#124, @filhocf): semantic grouping + noise filter replace the exact-content-equality grouping that produced zero belief promotions ever on real data (resolves #121 patches 1+2).
- Consolidation clustering fix (#126, @filhocf): restores `include_embeddings=True` at the three `_get_memories_for_horizon()` call sites, fixing a regression from #985 that caused zero clusters and zero associations on real databases.
- Bootstrap profile now injects derived beliefs and supports task-aware retrieval (#127, @filhocf): new `task_summary` and `budget_tokens` params on `get_bootstrap_profile`, gated behind `MCP_BELIEFS_ENABLED` (default `false`). Resolves #120 and #121 patch 4.

---

**Previous Releases** (v11 series — full history for all earlier versions in [CHANGELOG.md](CHANGELOG.md)):
- **v11.4.0** - MINOR: memory merge action + pluggable domain NER extractors + mcpmemory.services landing page (#100, #54, @filhocf) (July 4, 2026)
- **v11.3.3** - PATCH: fix(cli): memory CLI commands respect MCP_HTTPS_ENABLED (fixes silent failures when TLS is enabled) (July 1, 2026)
- **v11.3.2** - PATCH: declare numpy>=1.24.0 as core dependency (fixes uvx bare install crash, closes #98) (June 30, 2026)
- **v11.3.1** - PATCH: claude-hooks noise reduction - auto-capture moved to Stop event and gated on substantive content (June 22, 2026)
- **v11.3.0** - MINOR: Interactive 3D knowledge graph visualization (Orrery-inspired), node cap 100→1000/max 500→10000 (June 21, 2026)
- **v11.2.0** - MINOR: OAuth security hardening (#91), sqlite-vec rowid collision fix (#90), composite graph scoring (#55/#77, @filhocf), OpenCode XDG state dir fix (#84) (June 20, 2026)
- **v11.1.0** - MINOR: two-phase query API aggregation + maintenance script hardening (PR #78, @filhocf) (June 18, 2026)
- **v11.0.0** - MAJOR: legacy tool-name alias removal + optional ML dependencies / ONNX-first fallback (PR #72, #49, #71) (June 13, 2026)

**Full version history**: [CHANGELOG.md](CHANGELOG.md) | [Older versions (v10.36.3 and earlier)](docs/archive/CHANGELOG-HISTORIC.md) | [All Releases](https://codeberg.org/doobidoo/mcp-memory-service/releases)

---

## 📊 Retrieval Benchmarks

Three benchmarks measure retrieval quality (all-MiniLM-L6-v2, 384d embeddings, zero LLM API calls):

**LongMemEval** ([500 questions](https://huggingface.co/datasets/xiaowu0162/longmemeval-cleaned), ~45–62 distractor sessions per question):

| Question Type | R@5 | R@10 | NDCG@10 | MRR |
|---------------|-----|------|---------|-----|
| **Overall** | **80.4%** | **90.4%** | **82.2%** | **89.1%** |
| single-session-assistant | 100.0% | 100.0% | 99.3% | 99.1% |
| knowledge-update | 84.6% | 96.8% | 86.2% | 95.5% |
| single-session-user | 91.4% | 92.9% | 86.0% | 83.8% |
| temporal-reasoning | 72.0% | 84.1% | 75.1% | 85.7% |
| multi-session | 70.7% | 86.0% | 77.6% | 89.4% |

**DevBench** (practical developer workflow queries):

| Category | Recall@5 | MRR |
|----------|----------|-----|
| **Overall** | **91.1%** | **0.861** |
| exact | 100% | 1.000 |
| semantic | 80.0% | 0.700 |
| cross-type | 90.0% | 0.867 |

**LoCoMo** ([ACL 2024](https://github.com/snap-research/locomo) long-term conversational memory):

| Category | Recall@5 | MRR |
|----------|----------|-----|
| **Overall** | **49.7%** | **0.414** |
| multi-hop | 72.0% | 0.600 |
| temporal | 33.5% | 0.274 |

Run benchmarks: `python scripts/benchmarks/benchmark_longmemeval.py`, `python scripts/benchmarks/benchmark_devbench.py`, `python scripts/benchmarks/benchmark_locomo.py`

---

<details>
<summary><strong>Migration to v9.0.0</strong> (upgrading from v8.x)</summary>

**⚡ TL;DR**: No manual migration needed - upgrades happen automatically!

**Breaking Changes:**
- **Memory Type Ontology**: Legacy types auto-migrate to new taxonomy (task→observation, note→observation)
- **Asymmetric Relationships**: Directed edges only (no longer bidirectional)

**Migration Process:**
1. Stop your MCP server
2. Update to latest version (`git pull` or `pip install --upgrade mcp-memory-service`)
3. Restart server - automatic migrations run on startup:
   - Database schema migrations (009, 010)
   - Memory type soft-validation (legacy types → observation)
   - No tag migration needed (backward compatible)

**Safety**: Migrations are idempotent and safe to re-run

#### Breaking Change 1: Memory Type Ontology

- Legacy memory types (task, note, standard) are deprecated
- New formal taxonomy: 5 base types (observation, decision, learning, error, pattern) with 21 subtypes
- Migration is **automatic** on server restart — no manual action required

#### Breaking Change 2: Asymmetric Relationships

- Asymmetric relationships (causes, fixes, supports, follows) now store only directed edges
- Symmetric relationships (related, contradicts) continue storing bidirectional edges
- Database migration (010) runs automatically on startup

If your code expects bidirectional storage for asymmetric relationships:

```python
# OLD behavior (no longer applies):
result = storage.find_connected(memory_id, relationship_type="causes")

# NEW: use direction parameter explicitly
result = storage.find_connected(
    memory_id,
    relationship_type="causes",
    direction="both"
)
```

If you encounter issues: [Troubleshooting Guide](docs/troubleshooting/) · [CHANGELOG.md](CHANGELOG.md) · [Open an issue](https://codeberg.org/doobidoo/mcp-memory-service/issues)

</details>

---

## 📚 Documentation & Resources

- **[Agent Integration Guides](docs/agents/)** 🆕 – LangGraph, CrewAI, AutoGen, HTTP generic
- **[OpenCode Integration](opencode/README.md)** 🆕 – Local plugin for memory retrieval and context injection
- **[Remote MCP Setup (claude.ai)](docs/remote-mcp-setup.md)** 🆕 – Browser integration via HTTPS + OAuth
- **[Setup Guide](docs/setup-guide.md)** – Decision tree + step-by-step paths for all use cases
- **[Configuration Guide](docs/mastery/configuration-guide.md)** – Backend options and customization
- **[Architecture Overview](docs/architecture.md)** – How it works under the hood
- **[Team Setup Guide](docs/setup-guide.md#path-4-full-stack)** – OAuth and cloud collaboration
- **[Knowledge Graph Dashboard](docs/features/knowledge-graph-dashboard.md)** 🆕 – Interactive graph visualization guide
- **[Memory Type Ontology](docs/memory-ontology.md)** 🆕 – Built-in taxonomy and `MCP_CUSTOM_MEMORY_TYPES` env var
- **[Troubleshooting](docs/troubleshooting/)** – Common issues and solutions
- **[API Reference](https://codeberg.org/doobidoo/mcp-memory-service/wiki)** – Programmatic usage
- **[Wiki](https://codeberg.org/doobidoo/mcp-memory-service/wiki)** – Complete documentation
- [![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/doobidoo/mcp-memory-service) – AI-powered documentation assistant
- **[MCP Starter Kit](https://kruppster57.gumroad.com/l/glbhd)** – Build your own MCP server using the patterns from this project

---

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Quick Development Setup:**
```bash
git clone https://codeberg.org/doobidoo/mcp-memory-service.git
cd mcp-memory-service
pip install -e .  # Editable install
pytest tests/      # Run test suite
```

---
