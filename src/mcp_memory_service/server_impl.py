# Copyright 2024 Heinrich Krupp
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
MCP Memory Service
Copyright (c) 2024 Heinrich Krupp
Licensed under the MIT License. See LICENSE file in the project root for full license text.
"""
# Standard library imports
import sys
import os
import re
import time
import asyncio
import traceback
import json
import platform
import logging
from collections import deque
from typing import List, Dict, Any, Optional
from datetime import datetime


# CLI clients (Claude Code, opencode, Codex CLI) sometimes invoke MCP prompts
# via slash-command preview / tab-completion with literal positional
# placeholders like "$1", "$2" when the user has not bound argument values.
# Prompt handlers must NOT persist memories with these placeholders as
# content — see issue #998.
_PROMPT_PLACEHOLDER_RE = re.compile(r"^\$\d+$")


def _is_unresolved_prompt_placeholder(value) -> bool:
    """Return True if `value` is an unresolved CLI positional placeholder.

    Examples that match: "$1", "$2", " $10 ", "$99".
    Examples that don't: "", "General", "$1 real value", "$abc", None.
    """
    return isinstance(value, str) and bool(_PROMPT_PLACEHOLDER_RE.match(value.strip()))


def _sanitize_log_value(value: object) -> str:
    """Sanitize a user-provided value for safe inclusion in log messages."""
    return str(value).replace("\n", "\\n").replace("\r", "\\r").replace("\x1b", "\\x1b")


# Import from server package modules
from .server import (
    # Client Detection
    MCP_CLIENT,
    # Logging
    logger,
    # Cache
    _STORAGE_CACHE,
    _MEMORY_SERVICE_CACHE,
    _CACHE_STATS,
    _get_cache_lock,
    _get_or_create_memory_service,
    _log_cache_performance
)

# MCP protocol imports
import mcp.types as types
from mcp.server import NotificationOptions, Server
from mcp.types import Resource

# Version import with fallback for testing scenarios
try:
    from . import __version__
except (ImportError, AttributeError):
    try:
        from importlib.metadata import version
        __version__ = version("mcp-memory-service")
    except Exception:
        __version__ = "0.0.0-dev"

# Package imports
from .dependency_check import get_recommended_timeout
from .compat import is_deprecated, transform_deprecated_call
from .utils.hashing import generate_content_hash
from .config import (
    BACKUPS_PATH,
    SERVER_NAME,
    STORAGE_BACKEND,
    EMBEDDING_MODEL_NAME,
    SQLITE_VEC_PATH,
    CONSOLIDATION_ENABLED,
    CONSOLIDATION_CONFIG,
    CONSOLIDATION_SCHEDULE,
    # Cloudflare configuration
    CLOUDFLARE_API_TOKEN,
    CLOUDFLARE_ACCOUNT_ID,
    CLOUDFLARE_VECTORIZE_INDEX,
    CLOUDFLARE_D1_DATABASE_ID,
    CLOUDFLARE_R2_BUCKET,
    CLOUDFLARE_EMBEDDING_MODEL,
    CLOUDFLARE_LARGE_CONTENT_THRESHOLD,
    CLOUDFLARE_MAX_RETRIES,
    CLOUDFLARE_BASE_DELAY,
    # Hybrid backend configuration
    HYBRID_SYNC_INTERVAL,
    HYBRID_BATCH_SIZE,
    # Milvus backend configuration
    MILVUS_URI,
    MILVUS_TOKEN,
    MILVUS_COLLECTION_NAME,
    # Integrity monitoring
    INTEGRITY_CHECK_ENABLED,
)
# Storage imports will be done conditionally in the server class
from .models.memory import Memory
from .utils.system_detection import (
    get_system_info,
)
from .services.memory_service import MemoryService

# Consolidation system imports (conditional)
if CONSOLIDATION_ENABLED:
    from .consolidation.base import ConsolidationConfig
    from .consolidation.consolidator import DreamInspiredConsolidator
    from .consolidation.scheduler import ConsolidationScheduler

# Note: Logging is already configured in server.logging_config module

# Configure performance-critical module logging
if not os.getenv('DEBUG_MODE'):
    # Set higher log levels for performance-critical modules
    for module_name in ['sentence_transformers', 'transformers', 'torch', 'numpy']:
        logging.getLogger(module_name).setLevel(logging.WARNING)


def _get_onboarding_guide(client_type: str = "generic") -> str:
    """Return integration guide for a specific client type."""

    # Shared sections reused across client types
    _DURING_SESSION = """\
### During session:
- `memory_store`: save decisions, observations, references. Include ≥2 tags and a
  memory_type (decision, observation, note, reference). Use `conversation_id` for
  multiple checkpoints in the same session (bypasses dedup).
- `mistake_note_add`: record error patterns with {pattern, context, wrong, right}.
- `memory_search(mode="ranked")`: default search — ranks by recency + access + quality.
  Use `mode="hybrid"` when you need pure semantic + quality boost.
- `memory_quality(action="rate", content_hash, rating=1|-1)`: rate memories after use.
  Aim for ≥3 ratings per session. This drives the ranking system.
"""

    _SERVER_DOES = """\
### What the server does automatically:
- **Post-commit learning**: after `commit_session_legacy`, the server runs
  harvest + distill in background (~8s). No action needed from you.
- **Scheduled distill**: every 6h, undistilled memories are batch-processed via LLM.
- **Bootstrap refresh**: `get_bootstrap_profile` always returns the latest profile.
- **Frustration tracking**: errors weigh 3× more than successes. High-frustration
  patterns are promoted to AVOID rules in your bootstrap profile.
- **Threshold trigger**: if >20 new observations accumulate without distill, it runs
  automatically on the next store call.
"""

    guides = {
        "kiro": f"""## Integration Guide: mcp-memory-service → Kiro CLI

### On session start (REQUIRED):
1. `get_bootstrap_profile(agent_ids=["kiro"])` — returns behavioral rules
   (avoidances, conventions, preferences). Follow them.
2. `mistake_note_search(query="<current task context>")` — check known pitfalls
   before starting work.

### On session end (REQUIRED):
1. `commit_session_legacy` with: session_id, agent_id, task_summary, outcome,
   decisions (what+why), errors (tool+message+count+severity), user_corrections.
   This triggers server-side learning automatically.
2. `memory_harvest(sessions=1, dry_run=false)` — extracts insights from the
   current session JSONL via LLM. Fallback if commit_session_legacy is unavailable.
3. Rate memories consulted during the session (≥3 ratings).

{_DURING_SESSION}
### Advanced tools:
- `memory_harvest(sessions=N, use_llm=true)`: batch-extract insights from N sessions.
- `memory_distill(batch_size=20)`: extract insights from existing long memories via LLM.
- `get_bootstrap_profile(agent_ids=["kiro"])`: re-fetch profile mid-session if needed.
- `memory_quality(action="maintain")`: run maintenance cycle (decay, stale, entities).

{_SERVER_DOES}""",

        "claude-code": f"""## Integration Guide: mcp-memory-service → Claude Code

### On session start (REQUIRED):
1. `get_bootstrap_profile(agent_ids=["claude-code"])` — incorporate returned rules.
2. `mistake_note_search(query="<task context>")` — check known pitfalls.

### On session end (REQUIRED):
1. `commit_session_legacy` with session summary, decisions, errors, corrections.
   Server runs learning pipeline automatically after this call.
2. Rate memories used during the session.

{_DURING_SESSION}
{_SERVER_DOES}""",
    }

    guide = guides.get(client_type)
    if not guide:
        guide = f"""## Integration Guide: mcp-memory-service

### On session start (REQUIRED):
1. `get_bootstrap_profile(agent_ids=["your_agent_id"])` — follow returned rules.
2. `mistake_note_search(query="<task context>")` — check known pitfalls.

### On session end (REQUIRED):
1. `commit_session_legacy` with: session_id, agent_id, task_summary, outcome,
   decisions, errors, user_corrections. Triggers server-side learning.
2. Rate memories consulted (≥3 ratings per session).

{_DURING_SESSION}
{_SERVER_DOES}"""
    return guide

class MemoryServer:
    def __init__(
        self,
        storage=None,
        consolidator=None,
        consolidation_scheduler=None,
    ):
        """Initialize the server with hardware-aware configuration.

        All keyword arguments are optional dependency-injection slots for
        an outer host (e.g. the HTTP transport in `web/api/mcp.py`) that
        has already built these objects and wants the MemoryServer to
        share them rather than bootstrap a second set. Passing `storage`
        skips the lazy storage-init path and treats the server as fully
        initialized from construction. The stdio entry point
        (`async_main`) calls `MemoryServer()` with no args and gets the
        existing lazy-init behavior.
        """
        self.server = Server(SERVER_NAME)
        self.system_info = get_system_info()

        # Initialize query time tracking
        self.query_times = deque(maxlen=50)  # Keep last 50 query times for averaging

        # Initialize progress tracking
        self.current_progress = {}  # Track ongoing operations

        # Initialize integrity monitor (if enabled)
        self.integrity_monitor = None

        # Initialize consolidation system. Caller-provided instances win;
        # otherwise the lazy path inside `_ensure_storage_initialized`
        # builds them (only when CONSOLIDATION_ENABLED).
        self.consolidator = consolidator
        self.consolidation_scheduler = consolidation_scheduler
        self._harvest_lock = asyncio.Lock()  # C2: prevent concurrent harvest race condition
        self._background_tasks: set = set()  # Track background tasks to prevent GC
        if CONSOLIDATION_ENABLED and self.consolidator is None:
            try:
                logger.info("Consolidation system will be initialized after storage")
            except Exception as e:
                logger.error(f"Failed to initialize consolidation config: {e}")

        try:
            # Initialize paths
            logger.info(f"Creating directories if they don't exist...")
            os.makedirs(BACKUPS_PATH, exist_ok=True)

            # Log system diagnostics
            logger.info(f"Initializing on {platform.system()} {platform.machine()} with Python {platform.python_version()}")
            logger.info(f"Using accelerator: {self.system_info.accelerator}")

            if storage is not None:
                # Caller injected an already-initialized storage; adopt it
                # directly and skip the deferred-init path entirely.
                self.storage = storage
                self.memory_service = MemoryService(storage)
                self._storage_initialized = True
                logger.info(
                    f"Using caller-provided {storage.__class__.__name__} storage; "
                    f"deferred init skipped"
                )
            else:
                # DEFER STORAGE INITIALIZATION - Initialize storage lazily when needed
                # This prevents hanging during server startup due to embedding model loading
                logger.info(f"Deferring {STORAGE_BACKEND} storage initialization to prevent hanging")
                if MCP_CLIENT == 'lm_studio':
                    print(f"Deferring {STORAGE_BACKEND} storage initialization to prevent startup hanging", file=sys.stdout, flush=True)
                self.storage = None
                self.memory_service = None
                self._storage_initialized = False

        except Exception as e:
            logger.error(f"Initialization error: {str(e)}")
            logger.error(traceback.format_exc())

            # Set storage to None to prevent any hanging
            self.storage = None
            self.memory_service = None
            self._storage_initialized = False
        
        # Register handlers
        self.register_handlers()
        logger.info("Server initialization complete")
        
        # Test handler registration with proper arguments
        try:
            logger.info("Testing handler registration...")
            capabilities = self.server.get_capabilities(
                notification_options=NotificationOptions(),
                experimental_capabilities={}
            )
            logger.info(f"Server capabilities: {capabilities}")
            if MCP_CLIENT == 'lm_studio':
                print(f"Server capabilities registered successfully!", file=sys.stdout, flush=True)
        except Exception as e:
            logger.error(f"Handler registration test failed: {str(e)}")
            print(f"Handler registration issue: {str(e)}", file=sys.stderr, flush=True)
    
    def record_query_time(self, query_time_ms: float):
        """Record a query time for averaging."""
        self.query_times.append(query_time_ms)
        logger.debug(f"Recorded query time: {query_time_ms:.2f}ms")
    
    def get_average_query_time(self) -> float:
        """Get the average query time from recent operations."""
        if not self.query_times:
            return 0.0
        
        avg = sum(self.query_times) / len(self.query_times)
        logger.debug(f"Average query time: {avg:.2f}ms (from {len(self.query_times)} samples)")
        return round(avg, 2)
    
    async def send_progress_notification(self, operation_id: str, progress: float, message: str = None):
        """Send a progress notification for a long-running operation."""
        try:
            # Store progress for potential querying
            self.current_progress[operation_id] = {
                "progress": progress,
                "message": message or f"Operation {operation_id}: {progress:.0f}% complete",
                "timestamp": datetime.now().isoformat()
            }
            
            # Send notification if server supports it
            if hasattr(self.server, 'send_progress_notification'):
                await self.server.send_progress_notification(
                    progress=progress,
                    progress_token=operation_id,
                    message=message
                )
            
            logger.debug("Progress %s: %.0f%% - %s", _sanitize_log_value(operation_id), progress, _sanitize_log_value(message))
            
            # Clean up completed operations
            if progress >= 100:
                self.current_progress.pop(operation_id, None)
                
        except Exception as e:
            logger.debug(f"Could not send progress notification: {e}")
    
    def get_operation_progress(self, operation_id: str) -> Optional[Dict[str, Any]]:
        """Get the current progress of an operation."""
        return self.current_progress.get(operation_id)
    
    async def _initialize_storage_with_timeout(self):
        """Initialize storage with timeout and caching optimization."""
        global _STORAGE_CACHE, _MEMORY_SERVICE_CACHE, _CACHE_STATS

        # Track call statistics
        _CACHE_STATS["total_calls"] += 1
        start_time = time.time()

        logger.info(f"🚀 EAGER INIT Call #{_CACHE_STATS['total_calls']}: Checking global cache...")

        # Acquire lock for thread-safe cache access
        cache_lock = _get_cache_lock()
        async with cache_lock:
            # Generate cache key for storage backend
            cache_key = f"{STORAGE_BACKEND}:{SQLITE_VEC_PATH}"

            # Check storage cache
            if cache_key in _STORAGE_CACHE:
                self.storage = _STORAGE_CACHE[cache_key]
                _CACHE_STATS["storage_hits"] += 1
                logger.info(f"✅ Storage Cache HIT - Reusing {STORAGE_BACKEND} instance (key: {cache_key})")
                self._storage_initialized = True

                # Check memory service cache and log performance
                self.memory_service = _get_or_create_memory_service(self.storage)
                _log_cache_performance(start_time)

                return True  # Cached initialization succeeded

        # Cache miss - proceed with initialization
        _CACHE_STATS["storage_misses"] += 1
        logger.info(f"❌ Storage Cache MISS - Initializing {STORAGE_BACKEND} instance...")

        try:
            logger.info(f"🚀 EAGER INIT: Starting {STORAGE_BACKEND} storage initialization...")
            logger.info(f"🔧 EAGER INIT: Environment check - STORAGE_BACKEND={STORAGE_BACKEND}")
            
            # Log all Cloudflare config values for debugging
            if STORAGE_BACKEND == 'cloudflare':
                logger.info(f"🔧 EAGER INIT: Cloudflare config validation:")
                logger.info(f"   API_TOKEN: {'SET' if CLOUDFLARE_API_TOKEN else 'NOT SET'}")
                logger.info(f"   ACCOUNT_ID: {CLOUDFLARE_ACCOUNT_ID}")
                logger.info(f"   VECTORIZE_INDEX: {CLOUDFLARE_VECTORIZE_INDEX}")
                logger.info(f"   D1_DATABASE_ID: {CLOUDFLARE_D1_DATABASE_ID}")
                logger.info(f"   R2_BUCKET: {CLOUDFLARE_R2_BUCKET}")
                logger.info(f"   EMBEDDING_MODEL: {CLOUDFLARE_EMBEDDING_MODEL}")
            
            if STORAGE_BACKEND == 'sqlite_vec':
                # Check for multi-client coordination mode
                from .utils.port_detection import ServerCoordinator
                coordinator = ServerCoordinator()
                coordination_mode = await coordinator.detect_mode()
                
                logger.info(f"🔧 EAGER INIT: SQLite-vec - detected coordination mode: {coordination_mode}")
                
                if coordination_mode == "http_client":
                    # Use HTTP client to connect to existing server
                    from .storage.http_client import HTTPClientStorage
                    self.storage = HTTPClientStorage()
                    logger.info(f"✅ EAGER INIT: Using HTTP client storage")
                elif coordination_mode == "http_server":
                    # Try to auto-start HTTP server for coordination
                    from .utils.http_server_manager import auto_start_http_server_if_needed
                    server_started = await auto_start_http_server_if_needed()
                    
                    if server_started:
                        # Wait a moment for the server to be ready, then use HTTP client
                        await asyncio.sleep(2)
                        from .storage.http_client import HTTPClientStorage
                        self.storage = HTTPClientStorage()
                        logger.info(f"✅ EAGER INIT: Started HTTP server and using HTTP client storage")
                    else:
                        # Fall back to direct SQLite-vec storage
                        from . import storage
                        import importlib
                        storage_module = importlib.import_module('mcp_memory_service.storage.sqlite_vec')
                        SqliteVecMemoryStorage = storage_module.SqliteVecMemoryStorage
                        self.storage = SqliteVecMemoryStorage(SQLITE_VEC_PATH, embedding_model=EMBEDDING_MODEL_NAME)
                        logger.info(f"✅ EAGER INIT: HTTP server auto-start failed, using direct SQLite-vec storage")
                else:
                    # Import sqlite-vec storage module (supports dynamic class replacement)
                    from . import storage
                    import importlib
                    storage_module = importlib.import_module('mcp_memory_service.storage.sqlite_vec')
                    SqliteVecMemoryStorage = storage_module.SqliteVecMemoryStorage
                    self.storage = SqliteVecMemoryStorage(SQLITE_VEC_PATH, embedding_model=EMBEDDING_MODEL_NAME)
                    logger.info(f"✅ EAGER INIT: Using direct SQLite-vec storage at {SQLITE_VEC_PATH}")
            elif STORAGE_BACKEND == 'cloudflare':
                # Initialize Cloudflare storage
                logger.info(f"☁️  EAGER INIT: Importing CloudflareStorage...")
                from .storage.cloudflare import CloudflareStorage
                logger.info(f"☁️  EAGER INIT: Creating CloudflareStorage instance...")
                self.storage = CloudflareStorage(
                    api_token=CLOUDFLARE_API_TOKEN,
                    account_id=CLOUDFLARE_ACCOUNT_ID,
                    vectorize_index=CLOUDFLARE_VECTORIZE_INDEX,
                    d1_database_id=CLOUDFLARE_D1_DATABASE_ID,
                    r2_bucket=CLOUDFLARE_R2_BUCKET,
                    embedding_model=CLOUDFLARE_EMBEDDING_MODEL,
                    large_content_threshold=CLOUDFLARE_LARGE_CONTENT_THRESHOLD,
                    max_retries=CLOUDFLARE_MAX_RETRIES,
                    base_delay=CLOUDFLARE_BASE_DELAY
                )
                logger.info(f"✅ EAGER INIT: CloudflareStorage instance created with index: {CLOUDFLARE_VECTORIZE_INDEX}")
            elif STORAGE_BACKEND == 'hybrid':
                # Initialize Hybrid storage (SQLite-vec + Cloudflare)
                logger.info(f"🔄 EAGER INIT: Using Hybrid storage...")
                from .storage.hybrid import HybridMemoryStorage

                # Prepare Cloudflare configuration dict
                cloudflare_config = None
                if all([CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID, CLOUDFLARE_VECTORIZE_INDEX, CLOUDFLARE_D1_DATABASE_ID]):
                    cloudflare_config = {
                        'api_token': CLOUDFLARE_API_TOKEN,
                        'account_id': CLOUDFLARE_ACCOUNT_ID,
                        'vectorize_index': CLOUDFLARE_VECTORIZE_INDEX,
                        'd1_database_id': CLOUDFLARE_D1_DATABASE_ID,
                        'r2_bucket': CLOUDFLARE_R2_BUCKET,
                        'embedding_model': CLOUDFLARE_EMBEDDING_MODEL,
                        'large_content_threshold': CLOUDFLARE_LARGE_CONTENT_THRESHOLD,
                        'max_retries': CLOUDFLARE_MAX_RETRIES,
                        'base_delay': CLOUDFLARE_BASE_DELAY
                    }
                    logger.info(f"🔄 EAGER INIT: Cloudflare config prepared for hybrid storage")
                else:
                    logger.warning("🔄 EAGER INIT: Incomplete Cloudflare config, hybrid will run in SQLite-only mode")

                self.storage = HybridMemoryStorage(
                    sqlite_db_path=SQLITE_VEC_PATH,
                    embedding_model=EMBEDDING_MODEL_NAME,
                    cloudflare_config=cloudflare_config,
                    sync_interval=HYBRID_SYNC_INTERVAL or 300,
                    batch_size=HYBRID_BATCH_SIZE or 50
                )
                logger.info(f"✅ EAGER INIT: HybridMemoryStorage instance created")
            elif STORAGE_BACKEND == 'milvus':
                # Initialize Milvus storage (Milvus Lite / server / Zilliz Cloud)
                logger.info(f"🧬 EAGER INIT: Importing MilvusMemoryStorage...")
                from .storage.milvus import MilvusMemoryStorage
                logger.info(
                    f"🧬 EAGER INIT: Creating MilvusMemoryStorage (uri={MILVUS_URI}, "
                    f"collection={MILVUS_COLLECTION_NAME}, auth={'yes' if MILVUS_TOKEN else 'no'})"
                )
                self.storage = MilvusMemoryStorage(
                    uri=MILVUS_URI,
                    token=MILVUS_TOKEN,
                    collection_name=MILVUS_COLLECTION_NAME,
                    embedding_model=EMBEDDING_MODEL_NAME,
                )
                logger.info(f"✅ EAGER INIT: MilvusMemoryStorage instance created")
            else:
                # Unknown backend - should not reach here due to factory validation
                logger.error(f"❌ EAGER INIT: Unknown storage backend: {STORAGE_BACKEND}")
                raise ValueError(f"Unsupported storage backend: {STORAGE_BACKEND}")

            # Initialize the storage backend
            logger.info(f"🔧 EAGER INIT: Calling storage.initialize()...")
            await self.storage.initialize()
            logger.info(f"✅ EAGER INIT: storage.initialize() completed successfully")
            
            self._storage_initialized = True
            logger.info(f"🎉 EAGER INIT: {STORAGE_BACKEND} storage initialization successful")

            # Cache the newly initialized storage instance
            async with cache_lock:
                _STORAGE_CACHE[cache_key] = self.storage
                init_time = (time.time() - start_time) * 1000
                _CACHE_STATS["initialization_times"].append(init_time)
                logger.info(f"💾 Cached storage instance (key: {cache_key}, init_time: {init_time:.1f}ms)")

                # Initialize and cache MemoryService
                _CACHE_STATS["service_misses"] += 1
                self.memory_service = MemoryService(self.storage)
                storage_id = id(self.storage)
                _MEMORY_SERVICE_CACHE[storage_id] = self.memory_service
                logger.info(f"💾 Cached MemoryService instance (storage_id: {storage_id})")

            # Verify storage type
            storage_type = self.storage.__class__.__name__
            logger.info(f"🔍 EAGER INIT: Final storage type verification: {storage_type}")

            # Initialize consolidation system after storage is ready
            await self._initialize_consolidation()

            # Initialize integrity monitoring for SQLite backends
            await self._initialize_integrity_monitor()

            return True
        except Exception as e:
            logger.error(f"❌ EAGER INIT: Storage initialization failed: {str(e)}")
            logger.error(f"📋 EAGER INIT: Full traceback:")
            logger.error(traceback.format_exc())
            return False

    async def _ensure_storage_initialized(self):
        """Lazily initialize storage backend when needed with global caching."""
        if not self._storage_initialized:
            global _STORAGE_CACHE, _MEMORY_SERVICE_CACHE, _CACHE_STATS

            # Track call statistics
            _CACHE_STATS["total_calls"] += 1
            start_time = time.time()

            logger.info(f"🔄 LAZY INIT Call #{_CACHE_STATS['total_calls']}: Checking global cache...")

            # Acquire lock for thread-safe cache access
            cache_lock = _get_cache_lock()
            async with cache_lock:
                # Generate cache key for storage backend
                cache_key = f"{STORAGE_BACKEND}:{SQLITE_VEC_PATH}"

                # Check storage cache
                if cache_key in _STORAGE_CACHE:
                    self.storage = _STORAGE_CACHE[cache_key]
                    _CACHE_STATS["storage_hits"] += 1
                    logger.info(f"✅ Storage Cache HIT - Reusing {STORAGE_BACKEND} instance (key: {cache_key})")
                    self._storage_initialized = True

                    # Check memory service cache and log performance
                    self.memory_service = _get_or_create_memory_service(self.storage)
                    _log_cache_performance(start_time)

                    return self.storage

            # Cache miss - proceed with initialization
            _CACHE_STATS["storage_misses"] += 1
            logger.info(f"❌ Storage Cache MISS - Initializing {STORAGE_BACKEND} instance...")

            try:
                logger.info(f"🔄 LAZY INIT: Starting {STORAGE_BACKEND} storage initialization...")
                logger.info(f"🔧 LAZY INIT: Environment check - STORAGE_BACKEND={STORAGE_BACKEND}")
                
                # Log all Cloudflare config values for debugging
                if STORAGE_BACKEND == 'cloudflare':
                    logger.info(f"🔧 LAZY INIT: Cloudflare config validation:")
                    logger.info(f"   API_TOKEN: {'SET' if CLOUDFLARE_API_TOKEN else 'NOT SET'}")
                    logger.info(f"   ACCOUNT_ID: {CLOUDFLARE_ACCOUNT_ID}")
                    logger.info(f"   VECTORIZE_INDEX: {CLOUDFLARE_VECTORIZE_INDEX}")
                    logger.info(f"   D1_DATABASE_ID: {CLOUDFLARE_D1_DATABASE_ID}")
                    logger.info(f"   R2_BUCKET: {CLOUDFLARE_R2_BUCKET}")
                    logger.info(f"   EMBEDDING_MODEL: {CLOUDFLARE_EMBEDDING_MODEL}")
                
                if STORAGE_BACKEND == 'sqlite_vec':
                    # Check for multi-client coordination mode
                    from .utils.port_detection import ServerCoordinator
                    coordinator = ServerCoordinator()
                    coordination_mode = await coordinator.detect_mode()
                    
                    logger.info(f"🔧 LAZY INIT: SQLite-vec - detected coordination mode: {coordination_mode}")
                    
                    if coordination_mode == "http_client":
                        # Use HTTP client to connect to existing server
                        from .storage.http_client import HTTPClientStorage
                        self.storage = HTTPClientStorage()
                        logger.info(f"✅ LAZY INIT: Using HTTP client storage")
                    elif coordination_mode == "http_server":
                        # Try to auto-start HTTP server for coordination
                        from .utils.http_server_manager import auto_start_http_server_if_needed
                        server_started = await auto_start_http_server_if_needed()
                        
                        if server_started:
                            # Wait a moment for the server to be ready, then use HTTP client
                            await asyncio.sleep(2)
                            from .storage.http_client import HTTPClientStorage
                            self.storage = HTTPClientStorage()
                            logger.info(f"✅ LAZY INIT: Started HTTP server and using HTTP client storage")
                        else:
                            # Fall back to direct SQLite-vec storage
                            import importlib
                            storage_module = importlib.import_module('mcp_memory_service.storage.sqlite_vec')
                            SqliteVecMemoryStorage = storage_module.SqliteVecMemoryStorage
                            self.storage = SqliteVecMemoryStorage(SQLITE_VEC_PATH, embedding_model=EMBEDDING_MODEL_NAME)
                            logger.info(f"✅ LAZY INIT: HTTP server auto-start failed, using direct SQLite-vec storage at: {SQLITE_VEC_PATH}")
                    else:
                        # Use direct SQLite-vec storage (with WAL mode for concurrent access)
                        import importlib
                        storage_module = importlib.import_module('mcp_memory_service.storage.sqlite_vec')
                        SqliteVecMemoryStorage = storage_module.SqliteVecMemoryStorage
                        self.storage = SqliteVecMemoryStorage(SQLITE_VEC_PATH, embedding_model=EMBEDDING_MODEL_NAME)
                        logger.info(f"✅ LAZY INIT: Created SQLite-vec storage at: {SQLITE_VEC_PATH}")
                elif STORAGE_BACKEND == 'cloudflare':
                    # Cloudflare backend using Vectorize, D1, and R2
                    logger.info(f"☁️  LAZY INIT: Importing CloudflareStorage...")
                    from .storage.cloudflare import CloudflareStorage
                    logger.info(f"☁️  LAZY INIT: Creating CloudflareStorage instance...")
                    self.storage = CloudflareStorage(
                        api_token=CLOUDFLARE_API_TOKEN,
                        account_id=CLOUDFLARE_ACCOUNT_ID,
                        vectorize_index=CLOUDFLARE_VECTORIZE_INDEX,
                        d1_database_id=CLOUDFLARE_D1_DATABASE_ID,
                        r2_bucket=CLOUDFLARE_R2_BUCKET,
                        embedding_model=CLOUDFLARE_EMBEDDING_MODEL,
                        large_content_threshold=CLOUDFLARE_LARGE_CONTENT_THRESHOLD,
                        max_retries=CLOUDFLARE_MAX_RETRIES,
                        base_delay=CLOUDFLARE_BASE_DELAY
                    )
                    logger.info(f"✅ LAZY INIT: Created Cloudflare storage with Vectorize index: {CLOUDFLARE_VECTORIZE_INDEX}")
                elif STORAGE_BACKEND == 'hybrid':
                    # Hybrid backend using SQLite-vec as primary and Cloudflare as secondary
                    logger.info(f"🔄 LAZY INIT: Importing HybridMemoryStorage...")
                    from .storage.hybrid import HybridMemoryStorage

                    # Prepare Cloudflare configuration dict
                    cloudflare_config = None
                    if all([CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID, CLOUDFLARE_VECTORIZE_INDEX, CLOUDFLARE_D1_DATABASE_ID]):
                        cloudflare_config = {
                            'api_token': CLOUDFLARE_API_TOKEN,
                            'account_id': CLOUDFLARE_ACCOUNT_ID,
                            'vectorize_index': CLOUDFLARE_VECTORIZE_INDEX,
                            'd1_database_id': CLOUDFLARE_D1_DATABASE_ID,
                            'r2_bucket': CLOUDFLARE_R2_BUCKET,
                            'embedding_model': CLOUDFLARE_EMBEDDING_MODEL,
                            'large_content_threshold': CLOUDFLARE_LARGE_CONTENT_THRESHOLD,
                            'max_retries': CLOUDFLARE_MAX_RETRIES,
                            'base_delay': CLOUDFLARE_BASE_DELAY
                        }
                        logger.info(f"🔄 LAZY INIT: Cloudflare config prepared for hybrid storage")
                    else:
                        logger.warning("🔄 LAZY INIT: Incomplete Cloudflare config, hybrid will run in SQLite-only mode")

                    logger.info(f"🔄 LAZY INIT: Creating HybridMemoryStorage instance...")
                    self.storage = HybridMemoryStorage(
                        sqlite_db_path=SQLITE_VEC_PATH,
                        embedding_model=EMBEDDING_MODEL_NAME,
                        cloudflare_config=cloudflare_config,
                        sync_interval=HYBRID_SYNC_INTERVAL or 300,
                        batch_size=HYBRID_BATCH_SIZE or 50
                    )
                    logger.info(f"✅ LAZY INIT: Created Hybrid storage at: {SQLITE_VEC_PATH} with Cloudflare sync")
                elif STORAGE_BACKEND == 'milvus':
                    # Milvus backend — Milvus Lite (file) / self-hosted server / Zilliz Cloud
                    logger.info(f"🧬 LAZY INIT: Importing MilvusMemoryStorage...")
                    from .storage.milvus import MilvusMemoryStorage
                    logger.info(
                        f"🧬 LAZY INIT: Creating MilvusMemoryStorage (uri={MILVUS_URI}, "
                        f"collection={MILVUS_COLLECTION_NAME}, auth={'yes' if MILVUS_TOKEN else 'no'})"
                    )
                    self.storage = MilvusMemoryStorage(
                        uri=MILVUS_URI,
                        token=MILVUS_TOKEN,
                        collection_name=MILVUS_COLLECTION_NAME,
                        embedding_model=EMBEDDING_MODEL_NAME,
                    )
                    logger.info(f"✅ LAZY INIT: MilvusMemoryStorage instance created")
                else:
                    # Unknown/unsupported backend
                    logger.error("=" * 70)
                    logger.error(f"❌ LAZY INIT: Unsupported storage backend: {STORAGE_BACKEND}")
                    logger.error("")
                    logger.error("Supported backends:")
                    logger.error("  - sqlite_vec (recommended for single-device use)")
                    logger.error("  - cloudflare (cloud storage)")
                    logger.error("  - hybrid (recommended for multi-device use)")
                    logger.error("  - milvus (Milvus Lite / self-hosted / Zilliz Cloud)")
                    logger.error("=" * 70)
                    raise ValueError(
                        f"Unsupported storage backend: {STORAGE_BACKEND}. "
                        "Use 'sqlite_vec', 'cloudflare', 'hybrid', or 'milvus'."
                    )
                
                # Initialize the storage backend
                logger.info(f"🔧 LAZY INIT: Calling storage.initialize()...")
                await self.storage.initialize()
                logger.info(f"✅ LAZY INIT: storage.initialize() completed successfully")
                
                # Verify the storage is properly initialized
                if hasattr(self.storage, 'is_initialized') and not self.storage.is_initialized():
                    # Get detailed status for debugging
                    if hasattr(self.storage, 'get_initialization_status'):
                        status = self.storage.get_initialization_status()
                        logger.error(f"❌ LAZY INIT: Storage initialization incomplete: {status}")
                    raise RuntimeError("Storage initialization incomplete")
                
                self._storage_initialized = True
                storage_type = self.storage.__class__.__name__
                logger.info(f"🎉 LAZY INIT: Storage backend ({STORAGE_BACKEND}) initialization successful")
                logger.info(f"🔍 LAZY INIT: Final storage type verification: {storage_type}")

                # Cache the newly initialized storage instance
                async with cache_lock:
                    _STORAGE_CACHE[cache_key] = self.storage
                    init_time = (time.time() - start_time) * 1000
                    _CACHE_STATS["initialization_times"].append(init_time)
                    logger.info(f"💾 Cached storage instance (key: {cache_key}, init_time: {init_time:.1f}ms)")

                    # Initialize and cache MemoryService
                    _CACHE_STATS["service_misses"] += 1
                    self.memory_service = MemoryService(self.storage)
                    storage_id = id(self.storage)
                    _MEMORY_SERVICE_CACHE[storage_id] = self.memory_service
                    logger.info(f"💾 Cached MemoryService instance (storage_id: {storage_id})")

                # Initialize consolidation system after storage is ready
                await self._initialize_consolidation()

            except Exception as e:
                logger.error(f"❌ LAZY INIT: Failed to initialize {STORAGE_BACKEND} storage: {str(e)}")
                logger.error(f"📋 LAZY INIT: Full traceback:")
                logger.error(traceback.format_exc())
                # Set storage to None to indicate failure
                self.storage = None
                self._storage_initialized = False
                raise
        return self.storage

    async def initialize(self):
        """Async initialization method with eager storage initialization and timeout."""
        try:
            # Run any async initialization tasks here
            logger.info("🚀 SERVER INIT: Starting async initialization...")
            
            # Print system diagnostics only for LM Studio (avoid JSON parsing errors in Claude Desktop)
            if MCP_CLIENT == 'lm_studio':
                print("\n=== System Diagnostics ===", file=sys.stdout, flush=True)
                print(f"OS: {self.system_info.os_name} {self.system_info.os_version}", file=sys.stdout, flush=True)
                print(f"Architecture: {self.system_info.architecture}", file=sys.stdout, flush=True)
                print(f"Memory: {self.system_info.memory_gb:.2f} GB", file=sys.stdout, flush=True)
                print(f"Accelerator: {self.system_info.accelerator}", file=sys.stdout, flush=True)
                print(f"Python: {platform.python_version()}", file=sys.stdout, flush=True)
            
            # Log environment info
            logger.info(f"🔧 SERVER INIT: Environment - STORAGE_BACKEND={STORAGE_BACKEND}")
            
            # Attempt eager storage initialization with timeout
            # Get dynamic timeout based on system and dependency status
            timeout_seconds = get_recommended_timeout()
            logger.info(f"⏱️  SERVER INIT: Attempting eager storage initialization (timeout: {timeout_seconds}s)...")
            if MCP_CLIENT == 'lm_studio':
                print(f"Attempting eager storage initialization (timeout: {timeout_seconds}s)...", file=sys.stdout, flush=True)
            try:
                init_task = asyncio.create_task(self._initialize_storage_with_timeout())
                success = await asyncio.wait_for(init_task, timeout=timeout_seconds)
                if success:
                    if MCP_CLIENT == 'lm_studio':
                        print("[OK] Eager storage initialization successful", file=sys.stdout, flush=True)
                    logger.info("✅ SERVER INIT: Eager storage initialization completed successfully")
                    
                    # Verify storage type after successful eager init
                    if hasattr(self, 'storage') and self.storage:
                        storage_type = self.storage.__class__.__name__
                        logger.info(f"🔍 SERVER INIT: Eager init resulted in storage type: {storage_type}")
                else:
                    if MCP_CLIENT == 'lm_studio':
                        print("[WARNING] Eager storage initialization failed, will use lazy loading", file=sys.stdout, flush=True)
                    logger.warning("⚠️  SERVER INIT: Eager initialization failed, falling back to lazy loading")
                    # Reset state for lazy loading
                    self.storage = None
                    self._storage_initialized = False
            except asyncio.TimeoutError:
                if MCP_CLIENT == 'lm_studio':
                    print("[TIMEOUT] Eager storage initialization timed out, will use lazy loading", file=sys.stdout, flush=True)
                logger.warning(f"⏱️  SERVER INIT: Storage initialization timed out after {timeout_seconds}s, falling back to lazy loading")
                # Reset state for lazy loading
                self.storage = None
                self._storage_initialized = False
            except Exception as e:
                if MCP_CLIENT == 'lm_studio':
                    print(f"[WARNING] Eager initialization error: {str(e)}, will use lazy loading", file=sys.stdout, flush=True)
                logger.warning(f"⚠️  SERVER INIT: Eager initialization error: {str(e)}, falling back to lazy loading")
                logger.warning(f"📋 SERVER INIT: Eager init error traceback:")
                logger.warning(traceback.format_exc())
                # Reset state for lazy loading
                self.storage = None
                self._storage_initialized = False
            
            # Add explicit console output for Smithery to see (only for LM Studio)
            if MCP_CLIENT == 'lm_studio':
                print("MCP Memory Service initialization completed", file=sys.stdout, flush=True)
            
            logger.info("🎉 SERVER INIT: Async initialization completed")
            return True
        except Exception as e:
            logger.error(f"❌ SERVER INIT: Async initialization error: {str(e)}")
            logger.error(f"📋 SERVER INIT: Full traceback:")
            logger.error(traceback.format_exc())
            # Add explicit console error output for Smithery to see
            print(f"Initialization error: {str(e)}", file=sys.stderr, flush=True)
            # Don't raise the exception, just return False
            return False

    async def validate_database_health(self):
        """Validate database health during initialization."""
        from .utils.db_utils import validate_database, repair_database
        
        try:
            # Check database health
            is_valid, message = await validate_database(self.storage)
            if not is_valid:
                logger.warning(f"Database validation failed: {message}")
                
                # Attempt repair
                logger.info("Attempting database repair...")
                repair_success, repair_message = await repair_database(self.storage)
                
                if not repair_success:
                    logger.error(f"Database repair failed: {repair_message}")
                    return False
                else:
                    logger.info(f"Database repair successful: {repair_message}")
                    return True
            else:
                logger.info(f"Database validation successful: {message}")
                return True
        except Exception as e:
            logger.error(f"Database validation error: {str(e)}")
            return False

    async def _initialize_consolidation(self):
        """Initialize the consolidation system after storage is ready."""
        if not CONSOLIDATION_ENABLED or not self._storage_initialized:
            return
        
        try:
            if self.consolidator is None:
                # Create consolidation config
                config = ConsolidationConfig(**CONSOLIDATION_CONFIG)
                
                # Initialize the consolidator with storage
                self.consolidator = DreamInspiredConsolidator(self.storage, config)
                if hasattr(self, 'memory_service'):
                    self.consolidator.plugin_registry = self.memory_service._plugin_registry
                logger.info("Dream-inspired consolidator initialized")
                
                # Initialize the scheduler if not disabled
                if any(schedule != 'disabled' for schedule in CONSOLIDATION_SCHEDULE.values()):
                    self.consolidation_scheduler = ConsolidationScheduler(
                        self.consolidator, 
                        CONSOLIDATION_SCHEDULE, 
                        enabled=True
                    )
                    
                    # Start the scheduler
                    if await self.consolidation_scheduler.start():
                        logger.info("Consolidation scheduler started successfully")
                        # Add periodic distill job (every 6h, checks threshold)
                        try:
                            from apscheduler.triggers.interval import IntervalTrigger
                            self.consolidation_scheduler.scheduler.add_job(
                                self._scheduled_distill_check,
                                trigger=IntervalTrigger(hours=6),
                                id="distill_check",
                                replace_existing=True,
                            )
                            self.consolidation_scheduler.scheduler.add_job(
                                self._scheduled_contradiction_check,
                                trigger=IntervalTrigger(hours=6),
                                id="contradiction_check",
                                replace_existing=True,
                            )
                            logger.info("Scheduled distill_check + contradiction_check jobs (every 6h)")
                        except Exception as e:
                            logger.warning(f"Failed to add distill_check job: {e}")
                    else:
                        logger.warning("Failed to start consolidation scheduler")
                        self.consolidation_scheduler = None
                else:
                    logger.info("Consolidation scheduler disabled (all schedules set to 'disabled')")
                    # T5 Fix: Start independent distill scheduler even without consolidation
                    try:
                        from apscheduler.schedulers.asyncio import AsyncIOScheduler
                        from apscheduler.triggers.interval import IntervalTrigger
                        self._distill_scheduler = AsyncIOScheduler()
                        self._distill_scheduler.add_job(
                            self._scheduled_distill_check,
                            trigger=IntervalTrigger(hours=6),
                            id="distill_check",
                            replace_existing=True,
                        )
                        self._distill_scheduler.add_job(
                            self._scheduled_contradiction_check,
                            trigger=IntervalTrigger(hours=6),
                            id="contradiction_check",
                            replace_existing=True,
                        )
                        self._distill_scheduler.start()
                        logger.info("Independent distill + contradiction scheduler started (every 6h)")
                    except Exception as e:
                        logger.warning(f"Failed to start independent distill scheduler: {e}")
                
        except Exception as e:
            logger.error(f"Failed to initialize consolidation system: {e}")
            logger.error(traceback.format_exc())
            self.consolidator = None
            self.consolidation_scheduler = None

    async def _initialize_integrity_monitor(self):
        """Initialize database integrity monitoring for SQLite backends."""
        if not INTEGRITY_CHECK_ENABLED:
            logger.info("Integrity monitoring disabled")
            return

        # Only applicable to SQLite-based storage backends
        if STORAGE_BACKEND not in ('sqlite_vec', 'sqlite'):
            logger.info(f"Integrity monitoring not applicable for {STORAGE_BACKEND} backend")
            return

        try:
            from .health import IntegrityMonitor

            self.integrity_monitor = IntegrityMonitor(SQLITE_VEC_PATH)

            # Run startup check before accepting requests
            result = await self.integrity_monitor.startup_check()
            if not result["healthy"]:
                logger.warning(
                    "Database integrity issue detected at startup. "
                    "The service will continue but may encounter errors."
                )

            # Start periodic monitoring
            await self.integrity_monitor.start()

        except Exception as e:
            logger.error(f"Failed to initialize integrity monitor: {e}")
            logger.error(traceback.format_exc())
            self.integrity_monitor = None

    def handle_method_not_found(self, method: str) -> None:
        """Custom handler for unsupported methods.
        
        This logs the unsupported method request but doesn't raise an exception,
        allowing the MCP server to handle it with a standard JSON-RPC error response.
        """
        logger.warning(f"Unsupported method requested: {method}")
        # The MCP server will automatically respond with a Method not found error
        # We don't need to do anything else here
    
    def register_handlers(self):
        # Enhanced Resources implementation
        @self.server.list_resources()
        async def handle_list_resources() -> List[Resource]:
            """List available memory resources."""
            await self._ensure_storage_initialized()
            
            resources = [
                types.Resource(
                    uri="memory://stats",
                    name="Memory Statistics",
                    description="Current memory database statistics",
                    mimeType="application/json"
                ),
                types.Resource(
                    uri="memory://tags",
                    name="Available Tags",
                    description="List of all tags used in memories",
                    mimeType="application/json"
                ),
                types.Resource(
                    uri="memory://recent/10",
                    name="Recent Memories",
                    description="10 most recent memories",
                    mimeType="application/json"
                ),
                types.Resource(
                    uri="memory://onboarding/generic",
                    name="Client Onboarding Guide",
                    description="Integration guide — how to use this memory server optimally",
                    mimeType="text/markdown"
                ),
                types.Resource(
                    uri="memory://agent/default/bootstrap",
                    name="Agent Bootstrap Profile",
                    description="Confidence-weighted behavioral profile for agent startup injection",
                    mimeType="text/markdown"
                ),
            ]
            
            # Add tag-specific resources for existing tags
            try:
                all_tags = await self.storage.get_all_tags()
                for tag in all_tags[:5]:  # Limit to first 5 tags for resources
                    resources.append(types.Resource(
                        uri=f"memory://tag/{tag}",
                        name=f"Memories tagged '{tag}'",
                        description=f"All memories with tag '{tag}'",
                        mimeType="application/json"
                    ))
            except AttributeError:
                # get_all_tags method not available on this storage backend
                pass
            except Exception as e:
                logger.warning(f"Failed to load tag resources: {e}")
            
            return resources
        
        @self.server.read_resource()
        async def handle_read_resource(uri: str) -> str:
            """Read a specific memory resource."""
            await self._ensure_storage_initialized()

            from urllib.parse import unquote

            # Convert AnyUrl to string if necessary (fix for issue #254)
            # MCP SDK may pass Pydantic AnyUrl objects instead of plain strings
            if hasattr(uri, '__str__'):
                uri = str(uri)

            try:
                if uri == "memory://stats":
                    # Get memory statistics
                    stats = await self.storage.get_stats()
                    return json.dumps(stats, indent=2)
                    
                elif uri == "memory://tags":
                    # Get all available tags
                    tags = await self.storage.get_all_tags()
                    return json.dumps({"tags": tags, "count": len(tags)}, indent=2)
                    
                elif uri.startswith("memory://recent/"):
                    # Get recent memories
                    n = int(uri.split("/")[-1])
                    memories = await self.storage.get_recent_memories(n)
                    return json.dumps({
                        "memories": [m.to_dict() for m in memories],
                        "count": len(memories)
                    }, indent=2, default=str)
                    
                elif uri.startswith("memory://tag/"):
                    # Get memories by tag
                    tag = unquote(uri.split("/", 3)[-1])
                    memories = await self.storage.search_by_tag([tag])
                    return json.dumps({
                        "tag": tag,
                        "memories": [m.to_dict() for m in memories],
                        "count": len(memories)
                    }, indent=2, default=str)
                    
                elif uri.startswith("memory://search/"):
                    # Dynamic search
                    query = unquote(uri.split("/", 3)[-1])
                    results = await self.storage.search(query, n_results=10)
                    return json.dumps({
                        "query": query,
                        "results": [r.to_dict() for r in results],
                        "count": len(results)
                    }, indent=2, default=str)
                    
                elif uri.startswith("memory://onboarding"):
                    # Client onboarding guide
                    parts = uri.replace("memory://onboarding", "").strip("/")
                    client_type = parts if parts else "generic"
                    return _get_onboarding_guide(client_type)

                elif uri.startswith("memory://agent/") and uri.endswith("/bootstrap"):
                    # §7: Bootstrap profile as resource
                    agent_id = uri[len("memory://agent/"):-len("/bootstrap")]
                    return await self._read_bootstrap_resource(agent_id)

                else:
                    return json.dumps({"error": f"Resource not found: {uri}"}, indent=2)
                    
            except Exception as e:
                logger.error(f"Error reading resource {uri}: {e}")
                return json.dumps({"error": str(e)}, indent=2)
        
        @self.server.list_resource_templates()
        async def handle_list_resource_templates() -> List[types.ResourceTemplate]:
            """List resource templates for dynamic queries."""
            return [
                types.ResourceTemplate(
                    uriTemplate="memory://recent/{n}",
                    name="Recent Memories",
                    description="Get N most recent memories",
                    mimeType="application/json"
                ),
                types.ResourceTemplate(
                    uriTemplate="memory://tag/{tag}",
                    name="Memories by Tag",
                    description="Get all memories with a specific tag",
                    mimeType="application/json"
                ),
                types.ResourceTemplate(
                    uriTemplate="memory://search/{query}",
                    name="Search Memories",
                    description="Search memories by query",
                    mimeType="application/json"
                )
            ]
        
        @self.server.list_prompts()
        async def handle_list_prompts() -> List[types.Prompt]:
            """List available guided prompts for memory operations."""
            return [
                types.Prompt(
                    name="memory_review",
                    description="Review and organize memories from a specific time period",
                    arguments=[
                        types.PromptArgument(
                            name="time_period",
                            description="Time period to review (e.g., 'last week', 'yesterday', '2 days ago')",
                            required=True
                        ),
                        types.PromptArgument(
                            name="focus_area",
                            description="Optional area to focus on (e.g., 'work', 'personal', 'learning')",
                            required=False
                        )
                    ]
                ),
                types.Prompt(
                    name="memory_analysis",
                    description="Analyze patterns and themes in stored memories",
                    arguments=[
                        types.PromptArgument(
                            name="tags",
                            description="Tags to analyze (comma-separated)",
                            required=False
                        ),
                        types.PromptArgument(
                            name="time_range",
                            description="Time range to analyze (e.g., 'last month', 'all time')",
                            required=False
                        )
                    ]
                ),
                types.Prompt(
                    name="knowledge_export",
                    description="Export memories in a specific format",
                    arguments=[
                        types.PromptArgument(
                            name="format",
                            description="Export format (json, markdown, text)",
                            required=True
                        ),
                        types.PromptArgument(
                            name="filter",
                            description="Filter criteria (tags or search query)",
                            required=False
                        )
                    ]
                ),
                types.Prompt(
                    name="memory_cleanup",
                    description="Identify and remove duplicate or outdated memories",
                    arguments=[
                        types.PromptArgument(
                            name="older_than",
                            description="Remove memories older than (e.g., '6 months', '1 year')",
                            required=False
                        ),
                        types.PromptArgument(
                            name="similarity_threshold",
                            description="Similarity threshold for duplicates (0.0-1.0)",
                            required=False
                        )
                    ]
                ),
                types.Prompt(
                    name="learning_session",
                    description="Store structured learning notes from a study session",
                    arguments=[
                        types.PromptArgument(
                            name="topic",
                            description="Learning topic or subject",
                            required=True
                        ),
                        types.PromptArgument(
                            name="key_points",
                            description="Key points learned (comma-separated)",
                            required=True
                        ),
                        types.PromptArgument(
                            name="questions",
                            description="Questions or areas for further study",
                            required=False
                        )
                    ]
                )
            ]
        
        @self.server.get_prompt()
        async def handle_get_prompt(name: str, arguments: dict) -> types.GetPromptResult:
            """Handle prompt execution with provided arguments."""
            await self._ensure_storage_initialized()

            # Dispatch to specific prompt handler
            if name == "memory_review":
                messages = await _prompt_memory_review(self, arguments)
            elif name == "memory_analysis":
                messages = await _prompt_memory_analysis(self, arguments)
            elif name == "knowledge_export":
                messages = await _prompt_knowledge_export(self, arguments)
            elif name == "memory_cleanup":
                messages = await _prompt_memory_cleanup(self, arguments)
            elif name == "learning_session":
                messages = await _prompt_learning_session(self, arguments)
            else:
                messages = [
                    types.PromptMessage(
                        role="user",
                        content=types.TextContent(
                            type="text",
                            text=f"Unknown prompt: {name}"
                        )
                    )
                ]

            return types.GetPromptResult(
                description=f"Result of {name} prompt",
                messages=messages
            )
        
        # Helper methods for specific prompts
        async def _prompt_memory_review(self, arguments: dict) -> list:
            """Generate memory review prompt."""
            time_period = arguments.get("time_period", "last week")
            focus_area = arguments.get("focus_area", "")
            
            # Retrieve memories from the specified time period
            memories = await self.storage.recall_memory(time_period, n_results=20)
            
            prompt_text = f"Review of memories from {time_period}"
            if focus_area:
                prompt_text += f" (focusing on {focus_area})"
            prompt_text += ":\n\n"
            
            if memories:
                for mem in memories:
                    prompt_text += f"- {mem.content}\n"
                    if mem.tags:
                        prompt_text += f"  Tags: {', '.join(mem.tags)}\n"
            else:
                prompt_text += "No memories found for this time period."
            
            return [
                types.PromptMessage(
                    role="user",
                    content=types.TextContent(type="text", text=prompt_text)
                )
            ]
        
        async def _prompt_memory_analysis(self, arguments: dict) -> list:
            """Generate memory analysis prompt."""
            tags = arguments.get("tags", "").split(",") if arguments.get("tags") else []
            time_range = arguments.get("time_range", "all time")
            
            analysis_text = "Memory Analysis"
            if tags:
                analysis_text += f" for tags: {', '.join(tags)}"
            if time_range != "all time":
                analysis_text += f" from {time_range}"
            analysis_text += "\n\n"
            
            # Get relevant memories
            if tags:
                memories = await self.storage.search_by_tag(tags)
            else:
                memories = await self.storage.get_recent_memories(100)
            
            # Analyze patterns
            tag_counts = {}
            type_counts = {}
            for mem in memories:
                for tag in mem.tags:
                    tag_counts[tag] = tag_counts.get(tag, 0) + 1
                mem_type = mem.memory_type
                type_counts[mem_type] = type_counts.get(mem_type, 0) + 1
            
            analysis_text += f"Total memories analyzed: {len(memories)}\n\n"
            analysis_text += "Top tags:\n"
            for tag, count in sorted(tag_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
                analysis_text += f"  - {tag}: {count} occurrences\n"
            analysis_text += "\nMemory types:\n"
            for mem_type, count in type_counts.items():
                analysis_text += f"  - {mem_type}: {count} memories\n"
            
            return [
                types.PromptMessage(
                    role="user",
                    content=types.TextContent(type="text", text=analysis_text)
                )
            ]
        
        async def _prompt_knowledge_export(self, arguments: dict) -> list:
            """Generate knowledge export prompt."""
            format_type = arguments.get("format", "json")
            filter_criteria = arguments.get("filter", "")
            
            # Get memories based on filter
            if filter_criteria:
                if "," in filter_criteria:
                    # Assume tags
                    memories = await self.storage.search_by_tag(filter_criteria.split(","))
                else:
                    # Assume search query
                    memories = await self.storage.search(filter_criteria, n_results=100)
            else:
                memories = await self.storage.get_recent_memories(100)
            
            export_text = f"Exported {len(memories)} memories in {format_type} format:\n\n"
            
            if format_type == "markdown":
                for mem in memories:
                    export_text += f"## {mem.created_at_iso}\n"
                    export_text += f"{mem.content}\n"
                    if mem.tags:
                        export_text += f"*Tags: {', '.join(mem.tags)}*\n"
                    export_text += "\n"
            elif format_type == "text":
                for mem in memories:
                    export_text += f"[{mem.created_at_iso}] {mem.content}\n"
            else:  # json
                export_data = [m.to_dict() for m in memories]
                export_text += json.dumps(export_data, indent=2, default=str)
            
            return [
                types.PromptMessage(
                    role="user",
                    content=types.TextContent(type="text", text=export_text)
                )
            ]
        
        async def _prompt_memory_cleanup(self, arguments: dict) -> list:
            """Generate memory cleanup prompt."""
            older_than = arguments.get("older_than", "")

            cleanup_text = "Memory Cleanup Report:\n\n"
            
            # Find duplicates
            all_memories = await self.storage.get_recent_memories(1000)
            duplicates = []
            
            for i, mem1 in enumerate(all_memories):
                for mem2 in all_memories[i+1:]:
                    # Simple similarity check based on content length
                    if abs(len(mem1.content) - len(mem2.content)) < 10:
                        if mem1.content[:50] == mem2.content[:50]:
                            duplicates.append((mem1, mem2))
            
            cleanup_text += f"Found {len(duplicates)} potential duplicate pairs\n"
            
            if older_than:
                cleanup_text += f"\nMemories older than {older_than} can be archived\n"
            
            return [
                types.PromptMessage(
                    role="user",
                    content=types.TextContent(type="text", text=cleanup_text)
                )
            ]
        
        async def _prompt_learning_session(self, arguments: dict) -> list:
            """Generate learning session prompt."""
            topic_raw = arguments.get("topic", "General")
            keypoints_raw = arguments.get("key_points", "")
            questions_raw = arguments.get("questions", "")

            unresolved = [
                name for name, val in (
                    ("topic", topic_raw),
                    ("key_points", keypoints_raw),
                    ("questions", questions_raw),
                ) if _is_unresolved_prompt_placeholder(val)
            ]

            topic = topic_raw
            # Filter out empty / whitespace-only entries from comma-separated lists
            # so the rendered note doesn't get blank bullet points.
            key_points = [p.strip() for p in keypoints_raw.split(",") if p.strip()]
            questions = [q.strip() for q in questions_raw.split(",") if q.strip()]

            # Create structured learning note
            learning_note = f"# Learning Session: {topic}\n\n"
            learning_note += f"Date: {datetime.now().isoformat()}\n\n"
            learning_note += "## Key Points:\n"
            for point in key_points:
                learning_note += f"- {point}\n"

            if questions:
                learning_note += "\n## Questions for Further Study:\n"
                for question in questions:
                    learning_note += f"- {question}\n"

            if unresolved:
                # Preview-only path: do NOT persist when args are unresolved
                # CLI positional placeholders. Otherwise every slash-command
                # tab-completion preview pollutes the memory store (issue #998).
                response_text = (
                    "Preview only — not persisted. Unresolved CLI placeholder "
                    f"argument(s): {', '.join(unresolved)}. Provide real values "
                    "for those fields to save this learning session.\n\n"
                    f"{learning_note}"
                )
                return [
                    types.PromptMessage(
                        role="user",
                        content=types.TextContent(type="text", text=response_text)
                    )
                ]

            # Store the learning note
            content_hash = generate_content_hash(learning_note)
            memory = Memory(
                content=learning_note,
                content_hash=content_hash,
                tags=["learning", topic.lower().replace(" ", "_")],
                memory_type="learning"
            )
            success, message = await self.storage.store(memory)

            response_text = f"Learning session stored successfully!\n\n{learning_note}"
            if not success:
                response_text = f"Failed to store learning session: {message}"

            return [
                types.PromptMessage(
                    role="user",
                    content=types.TextContent(type="text", text=response_text)
                )
            ]
        
        # Add a custom error handler for unsupported methods
        self.server.on_method_not_found = self.handle_method_not_found
        
        @self.server.list_tools()
        async def handle_list_tools() -> List[types.Tool]:
            return await self.list_tools()
        
        @self.server.call_tool()
        async def handle_call_tool(name: str, arguments: dict | None) -> List[types.TextContent]:
            return await self.call_tool(name, arguments)


    def local_only_tools(self) -> frozenset:
        """Tool names that must not be exposed over remote transports.

        These tools take a caller-controlled filesystem path
        (`project_path`, `file_path`, `directory_path`) and read whatever
        files they find there. The handlers were designed for a local
        user who already has filesystem access on the host; exposing them
        through an authenticated remote transport turns the auth boundary
        into a confused-deputy primitive that can read any file the
        server process can read.

        The HTTP MCP shim filters these out of `tools/list` and rejects
        `tools/call` for them (including their deprecated aliases). Stdio
        keeps them since the caller already has the filesystem access the
        handler would otherwise grant.
        """
        return frozenset({"memory_harvest", "memory_ingest"})

    async def list_tools(self) -> List[types.Tool]:
        """Return the canonical MCP tool list.

        Both transports build their `tools/list` response from this method.
        The list only includes modern unified tools (18 total:
        memory_store, memory_store_session, memory_search, memory_list,
        memory_delete, memory_cleanup, memory_health, memory_stats,
        memory_update, memory_consolidate, memory_ingest, memory_harvest,
        memory_quality, memory_graph, memory_conflicts, memory_resolve,
        mistake_note_add, mistake_note_search). Deprecated tool names
        continue working through `compat.transform_deprecated_call` (see
        `call_tool`) but are not advertised here.

        Transport-specific filtering (see `local_only_tools`) is applied
        by individual transports — the canonical list itself is the same
        for both.
        """
        logger.info("=== HANDLING LIST_TOOLS REQUEST ===")
        try:
            tools = [
                types.Tool(
                    name="memory_store",
                    description="""Store new information with optional tags.

                    Accepts two tag formats in metadata:
                    - Array: ["tag1", "tag2"]
                    - String: "tag1,tag2"

                    Use `conversation_id` to bypass semantic deduplication when saving
                    incremental memories from the same conversation.

                   Examples:
                    # Using array format:
                    {
                        "content": "Memory content",
                        "metadata": {
                            "tags": ["important", "reference"],
                            "type": "note"
                        }
                    }

                    # Using string format(preferred):
                    {
                        "content": "Memory content",
                        "metadata": {
                            "tags": "important,reference",
                            "type": "note"
                        }
                    }

                    # Using conversation_id to save incremental notes:
                    {
                        "content": "User prefers dark mode",
                        "conversation_id": "conv_abc123",
                        "metadata": {
                            "tags": "preference,ui"
                        }
                    }""",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "content": {
                                "type": "string",
                                "description": "The memory content to store, such as a fact, note, or piece of information."
                            },
                            "conversation_id": {
                                "type": "string",
                                "description": "Optional conversation identifier. When provided, semantic deduplication is skipped, allowing multiple incremental memories from the same conversation to be stored even if their content is topically similar. Exact duplicate hashes are still rejected."
                            },
                            "metadata": {
                                "type": "object",
                                "description": "Optional metadata about the memory, including tags and type.",
                                "properties": {
                                    "tags": {
                                        "oneOf": [
                                            {
                                                "type": "array",
                                                "items": {"type": "string"},
                                                "description": "Tags as an array of strings"
                                            },
                                            {
                                                "type": "string",
                                                "description": "Tags as comma-separated string"
                                            }
                                        ],
                                        "description": "Tags to categorize the memory. Accepts either an array of strings or a comma-separated string.",
                                        "examples": [
                                            "tag1,tag2,tag3",
                                            ["tag1", "tag2", "tag3"]
                                        ]
                                    },
                                    "type": {
                                        "type": "string",
                                        "description": "Optional memory type. Validated against the built-in ontology. Common base types: observation, decision, learning, error, pattern, planning, ceremony, milestone, stakeholder, meeting, research, communication. Common subtypes: note, reference, code_edit, command, document, insight, gotcha, bug, action_item, finding. Unknown types are silently coerced to 'observation' and the response includes a warning. Register additional types via the MCP_CUSTOM_MEMORY_TYPES env var, e.g. '{\"foo\": [\"sub_a\", \"sub_b\"]}'. See docs/memory-ontology.md for the full taxonomy."
                                    }
                                }
                            }
                        },
                        "required": ["content"]
                    },
                    annotations=types.ToolAnnotations(
                        title="Store Memory",
                        destructiveHint=False,
                    ),
                ),
                types.Tool(
                    name="memory_store_session",
                    description="""Store a full conversation session as a single memory unit.

Use this instead of memory_store when you want to preserve the full context
of a multi-turn conversation. All turns are stored together, making session-level
retrieval more reliable than storing individual turns separately.

Example:
{
"turns": [
    {"role": "user", "content": "How do I configure Redis?"},
    {"role": "assistant", "content": "Set REDIS_URL in your .env file..."}
],
"session_id": "optional-stable-id",
"tags": "redis,configuration"
}""",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "turns": {
                                "type": "array",
                                "description": "Ordered list of conversation turns.",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "role": {"type": "string", "description": "Speaker role, e.g. 'user' or 'assistant'"},
                                        "content": {"type": "string", "description": "Turn content"}
                                    },
                                    "required": ["role", "content"]
                                },
                                "minItems": 1
                            },
                            "session_id": {
                                "type": "string",
                                "description": "Optional stable identifier for this session. Auto-generated UUID if omitted."
                            },
                            "tags": {
                                "oneOf": [
                                    {"type": "array", "items": {"type": "string"}},
                                    {"type": "string"}
                                ],
                                "description": "Additional tags (comma-separated string or array). 'session:<id>' is always added automatically."
                            },
                            "metadata": {
                                "type": "object",
                                "description": "Optional extra metadata."
                            }
                        },
                        "required": ["turns"]
                    },
                    annotations=types.ToolAnnotations(
                        title="Store Session",
                        destructiveHint=False,
                    ),
                ),
                types.Tool(
                    name="memory_search",
                    description="""Search memories with flexible modes and filters. Primary tool for finding stored information.

USE THIS WHEN:
- User asks "what do you remember about X", "recall", "find memories"
- Looking for past decisions, preferences, context from previous sessions
- Need semantic, exact, or time-based search
- User references "last time we discussed", "you should know"

MODES:
- semantic (default): Finds conceptually similar content even if exact words differ
- exact: Finds memories containing the exact query string
- hybrid: Combines semantic similarity with quality scoring

TIME FILTERS (can combine with other filters):
- time_expr: Natural language like "yesterday", "last week", "2 days ago", "last month"
- after/before: Explicit ISO dates (YYYY-MM-DD)

QUALITY BOOST (for semantic/hybrid modes):
- 0.0 = pure semantic ranking (default)
- 0.3 = 30% quality weight, 70% semantic (recommended for important lookups)
- 1.0 = pure quality ranking

TAG FILTER:
- Filter results to only memories with specific tags
- Useful for categorical searches ("find all 'reference' memories about databases")

DEBUG:
- include_debug=true adds timing, embedding info, filter details

Examples:
{"query": "python async patterns"}
{"query": "API endpoint", "mode": "exact"}
{"time_expr": "last week", "limit": 20}
{"query": "database config", "time_expr": "yesterday"}
{"query": "architecture decisions", "tags": ["important"], "quality_boost": 0.3}
{"after": "2024-01-01", "before": "2024-06-30", "limit": 50}
{"query": "error handling", "include_debug": true}""",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "Search query (required for semantic/exact modes, optional for time-only searches)"
                            },
                            "mode": {
                                "type": "string",
                                "enum": ["semantic", "exact", "hybrid", "ranked"],
                                "default": "semantic",
                                "description": "Search mode"
                            },
                            "time_expr": {
                                "type": "string",
                                "description": "Natural language time filter (e.g., 'last week', 'yesterday', '3 days ago')"
                            },
                            "after": {
                                "type": "string",
                                "description": "Return memories created after this date (ISO format: YYYY-MM-DD)"
                            },
                            "before": {
                                "type": "string",
                                "description": "Return memories created before this date (ISO format: YYYY-MM-DD)"
                            },
                            "tags": {
                                "oneOf": [
                                    {
                                        "type": "array",
                                        "items": {"type": "string"},
                                        "description": "Tags as an array of strings"
                                    },
                                    {
                                        "type": "string",
                                        "description": "Tags as comma-separated string"
                                    }
                                ],
                                "description": "Filter to memories with any of these tags"
                            },
                            "tag_match": {
                                "type": "string",
                                "enum": ["any", "all"],
                                "default": "any",
                                "description": "Match ANY tag (OR, default) or ALL tags (AND)"
                            },
                            "quality_boost": {
                                "type": "number",
                                "minimum": 0,
                                "maximum": 1,
                                "default": 0,
                                "description": "Quality weight for reranking (0.0-1.0)"
                            },
                            "ranking_weights": {
                                "type": "object",
                                "description": "Custom weights for ranked mode (keys: semantic, time_decay, access_frequency, quality). Values are normalized to sum=1.0.",
                                "properties": {
                                    "semantic": {"type": "number"},
                                    "time_decay": {"type": "number"},
                                    "access_frequency": {"type": "number"},
                                    "quality": {"type": "number"}
                                }
                            },
                            "limit": {
                                "type": "integer",
                                "default": 10,
                                "minimum": 1,
                                "maximum": 100,
                                "description": "Maximum results to return"
                            },
                            "include_debug": {
                                "type": "boolean",
                                "default": False,
                                "description": "Include debug information in response"
                            },
                            "max_response_chars": {
                                "type": "number",
                                "description": "Maximum response size in characters. Truncates at memory boundaries to prevent context overflow. Recommended: 30000-50000. Default: unlimited."
                            },
                            "include_superseded": {
                                "type": "boolean",
                                "default": False,
                                "description": "Include memories that have been superseded by newer contradicting memories. Default: false (superseded memories are hidden)."
                            },
                            "entity": {
                                "type": "string",
                                "description": "Filter by linked entity name. Returns only memories that have been linked to this entity via entity extraction. Use after running maintain to populate entity links."
                            },
                            "fallback": {
                                "type": "boolean",
                                "default": False,
                                "description": "Enable cascading fallback when semantic results are sparse. When true and fewer than 3 results are found with scores below 0.4, automatically attempts BM25 keyword match and tag intersection. Each result includes match_method field. Default: false."
                            },
                            "include_beliefs": {
                                "type": "boolean",
                                "default": False,
                                "description": "Include derived beliefs alongside memories. Beliefs are confidence-scored knowledge derived from observations. Each belief result includes result_type='belief' and confidence score."
                            }
                        }
                    },
                    annotations=types.ToolAnnotations(
                        title="Search Memories (Unified)",
                        readOnlyHint=True,
                    ),
                ),
                types.Tool(
                    name="memory_list",
                    description="""List and browse memories with pagination and optional filters.

USE THIS WHEN:
- User wants to browse all memories ("show me my memories", "list everything")
- Need to paginate through large result sets
- Filter by tag OR memory type for categorical browsing
- User asks "what do I have stored", "browse my memories"

Unlike memory_search (semantic search), this does categorical listing/filtering.

PAGINATION:
- page: 1-based page number (default: 1)
- page_size: Results per page (default: 20, max: 100)

FILTERS (combine with AND logic):
- tags: Filter to memories with matching tags
- tag_match: "any" (OR, default) or "all" (AND) — controls how multiple tags are matched
- memory_type: Filter by type (note, reference, decision, etc.)
- stale_days: Filter to memories not accessed in the last N days

Examples:
{}  // List first 20 memories
{"page": 2, "page_size": 50}
{"tags": ["python", "reference"]}
{"tags": ["python", "reference"], "tag_match": "all"}
{"memory_type": "decision", "page_size": 10}
{"tags": ["important"], "memory_type": "note"}
{"stale_days": 30}  // Memories not accessed in 30 days
{"stale_days": 7, "tags": ["archived"]}  // Stale archived memories
""",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "page": {
                                "type": "integer",
                                "default": 1,
                                "minimum": 1,
                                "description": "Page number (1-based)"
                            },
                            "page_size": {
                                "type": "integer",
                                "default": 20,
                                "minimum": 1,
                                "maximum": 100,
                                "description": "Results per page"
                            },
                            "tags": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Filter by tags (returns memories with ANY of these tags by default, use tag_match to control)"
                            },
                            "tag_match": {
                                "type": "string",
                                "default": "any",
                                "enum": ["any", "all"],
                                "description": "Match ANY tag (OR, default) or ALL tags (AND)"
                            },
                            "memory_type": {
                                "type": "string",
                                "description": "Filter by memory type"
                            },
                            "stale_days": {
                                "type": "integer",
                                "minimum": 1,
                                "description": "Filter to memories not accessed in the last N days. Uses COALESCE(last_accessed, created_at) for memories never read. Currently supported on sqlite-vec backend only."
                            }
                        }
                    },
                    annotations=types.ToolAnnotations(
                        title="List Memories",
                        readOnlyHint=True,
                    ),
                ),
                types.Tool(
                    name="memory_delete",
                    description="""Delete memories with flexible filtering. Combine filters for precise targeting.

USE THIS WHEN:
- User says "delete", "remove", "forget" specific memories
- Need to clean up by tag, time range, or specific hash
- Bulk deletion with safety preview (dry_run=true)

FILTER COMBINATIONS (AND logic when multiple specified):
- content_hash only: Delete single memory by hash
- tags only: Delete memories with matching tags
- before/after: Delete memories in time range
- tags + time: Delete tagged memories within time range

SAFETY FEATURES:
- dry_run=true: Preview what will be deleted without deleting
- Returns deleted_hashes for audit trail
- No filters = error (prevents accidental mass deletion)

Examples:
{"content_hash": "abc123def456"}
{"tags": ["temporary", "draft"], "tag_match": "any"}
{"tags": ["archived", "old"], "tag_match": "all"}
{"before": "2024-01-01"}
{"after": "2024-06-01", "before": "2024-12-31"}
{"tags": ["cleanup"], "before": "2024-01-01", "dry_run": true}""",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "content_hash": {
                                "type": "string",
                                "description": "Specific memory hash to delete (ignores other filters if provided)"
                            },
                            "tags": {
                                "oneOf": [
                                    {
                                        "type": "array",
                                        "items": {"type": "string"},
                                        "description": "Tags as an array of strings"
                                    },
                                    {
                                        "type": "string",
                                        "description": "Tags as comma-separated string"
                                    }
                                ],
                                "description": "Filter by these tags"
                            },
                            "tag_match": {
                                "type": "string",
                                "enum": ["any", "all"],
                                "default": "any",
                                "description": "Match ANY tag or ALL tags"
                            },
                            "before": {
                                "type": "string",
                                "description": "Delete memories created before this date (ISO format: YYYY-MM-DD)"
                            },
                            "after": {
                                "type": "string",
                                "description": "Delete memories created after this date (ISO format: YYYY-MM-DD)"
                            },
                            "dry_run": {
                                "type": "boolean",
                                "default": False,
                                "description": "Preview deletions without executing"
                            }
                        }
                    },
                    annotations=types.ToolAnnotations(
                        title="Delete Memories (Unified)",
                        destructiveHint=True,
                    ),
                ),
                types.Tool(
                    name="memory_cleanup",
                    description="Find and remove duplicate entries",
                    inputSchema={
                        "type": "object",
                        "properties": {}
                    },
                    annotations=types.ToolAnnotations(
                        title="Cleanup Duplicates",
                        destructiveHint=True,
                    ),
                ),
                types.Tool(
                    name="memory_health",
                    description="Check database health and get statistics",
                    inputSchema={
                        "type": "object",
                        "properties": {}
                    },
                    annotations=types.ToolAnnotations(
                        title="Check Database Health",
                        readOnlyHint=True,
                    ),
                ),
                types.Tool(
                    name="memory_stats",
                    description="""Get MCP server global cache statistics for performance monitoring.

                    Returns detailed metrics about storage and memory service caching,
                    including hit rates, initialization times, and cache sizes.

                    This tool is useful for:
                    - Monitoring cache effectiveness
                    - Debugging performance issues
                    - Verifying cache persistence across MCP tool calls

                    Returns cache statistics including total calls, hit rate percentage,
                    storage/service cache metrics, performance metrics, and backend info.""",
                    inputSchema={
                        "type": "object",
                        "properties": {}
                    },
                    annotations=types.ToolAnnotations(
                        title="Get Cache Stats",
                        readOnlyHint=True,
                    ),
                ),
                types.Tool(
                    name="memory_update",
                    description="""Update memory metadata without recreating the entire memory entry.
                    
                    This provides efficient metadata updates while preserving the original
                    memory content, embeddings, and optionally timestamps.
                    
                    Examples:
                    # Add tags to a memory
                    {
                        "content_hash": "abc123...",
                        "updates": {
                            "tags": ["important", "reference", "new-tag"]
                        }
                    }
                    
                    # Update memory type and custom metadata
                    {
                        "content_hash": "abc123...",
                        "updates": {
                            "memory_type": "reminder",
                            "metadata": {
                                "priority": "high",
                                "due_date": "2024-01-15"
                            }
                        }
                    }
                    
                    # Update custom fields directly
                    {
                        "content_hash": "abc123...",
                        "updates": {
                            "priority": "urgent",
                            "status": "active"
                        }
                    }""",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "content_hash": {
                                "type": "string",
                                "description": "The content hash of the memory to update."
                            },
                            "updates": {
                                "type": "object",
                                "description": "Dictionary of metadata fields to update.",
                                "properties": {
                                    "tags": {
                                        "oneOf": [
                                            {
                                                "type": "array",
                                                "items": {"type": "string"},
                                                "description": "Tags as an array of strings"
                                            },
                                            {
                                                "type": "string",
                                                "description": "Tags as comma-separated string"
                                            }
                                        ],
                                        "description": "Replace existing tags with this list. Accepts either an array of strings or a comma-separated string."
                                    },
                                    "memory_type": {
                                        "type": "string",
                                        "description": "Update the memory type (e.g., 'note', 'reminder', 'fact')."
                                    },
                                    "metadata": {
                                        "type": "object",
                                        "description": "Custom metadata fields to merge with existing metadata."
                                    }
                                }
                            },
                            "preserve_timestamps": {
                                "type": "boolean",
                                "default": True,
                                "description": "Whether to preserve the original created_at timestamp (default: true)."
                            },
                            "versioned": {
                                "type": "boolean",
                                "default": False,
                                "description": "When true, creates a new version instead of overwriting. The old memory is marked as superseded. Requires content in updates to create the new version. Creates a new memory version and marks the old one as superseded. Supported backends: sqlite_vec. Unsupported backends return an error."
                            }
                        },
                        "required": ["content_hash", "updates"]
                    },
                    annotations=types.ToolAnnotations(
                        title="Update Memory Metadata",
                        destructiveHint=True,
                    ),
                )
            ]
            
            # Add consolidation tools if enabled
            if CONSOLIDATION_ENABLED and self.consolidator:
                consolidation_tools = [
                    types.Tool(
                        name="memory_consolidate",
                        description="""Memory consolidation management - run, monitor, and control memory optimization.

USE THIS WHEN:
- User asks about memory optimization, cleanup, or consolidation
- Need to check consolidation system health
- Want to manually trigger or schedule consolidation
- Need to pause/resume consolidation jobs

ACTIONS:
- run: Execute consolidation for a time horizon (requires time_horizon)
  Performs dream-inspired memory consolidation:
  • Exponential decay scoring
  • Creative association discovery
  • Semantic clustering and compression
  • Controlled forgetting with archival

- status: Get consolidation system health and statistics

- recommend: Get optimization recommendations for a time horizon (requires time_horizon)
  Analyzes memory state and suggests whether consolidation is needed

- scheduler: View all scheduled consolidation jobs
  Shows next run times and execution statistics

- pause: Pause consolidation (all or specific horizon)
  Temporarily stops automatic consolidation jobs

- resume: Resume paused consolidation
  Re-enables previously paused consolidation jobs

TIME HORIZONS:
- daily: Consolidate last 24 hours
- weekly: Consolidate last 7 days
- monthly: Consolidate last 30 days
- quarterly: Consolidate last 90 days
- yearly: Consolidate last 365 days

Examples:
{"action": "status"}
{"action": "run", "time_horizon": "weekly"}
{"action": "run", "time_horizon": "daily", "immediate": true}
{"action": "recommend", "time_horizon": "monthly"}
{"action": "scheduler"}
{"action": "pause"}
{"action": "pause", "time_horizon": "daily"}
{"action": "resume", "time_horizon": "weekly"}""",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "action": {
                                    "type": "string",
                                    "enum": ["run", "status", "recommend", "scheduler", "pause", "resume"],
                                    "description": "Consolidation action to perform"
                                },
                                "time_horizon": {
                                    "type": "string",
                                    "enum": ["daily", "weekly", "monthly", "quarterly", "yearly"],
                                    "description": "Time horizon (required for run/recommend, optional for pause/resume)"
                                },
                                "immediate": {
                                    "type": "boolean",
                                    "default": True,
                                    "description": "For 'run' action: execute immediately vs schedule for later"
                                }
                            },
                            "required": ["action"]
                        },
                        annotations=types.ToolAnnotations(
                            title="Consolidate Memories (Unified)",
                            destructiveHint=True,
                        ),
                    )
                ]
                tools.extend(consolidation_tools)
                logger.info(f"Added {len(consolidation_tools)} consolidation tools")
            
            # Add document ingestion tools
            ingestion_tools = [
                types.Tool(
                    name="memory_ingest",
                    description="""Ingest documents or directories into memory database.

USE THIS WHEN:
- User wants to import a document (PDF, TXT, MD, JSON)
- Need to batch import a directory of documents
- Building knowledge base from existing files

SUPPORTED FORMATS:
- PDF files (.pdf)
- Text files (.txt, .md, .markdown, .rst)
- JSON files (.json)

MODE:
- file: Ingest single document (requires file_path)
- directory: Batch ingest all documents in directory (requires directory_path)

CHUNKING:
- Documents are split into chunks for better retrieval
- chunk_size: Target characters per chunk (default: 1000)
- chunk_overlap: Overlap between chunks (default: 200)

Examples:
{"file_path": "/path/to/document.pdf"}
{"file_path": "/path/to/notes.md", "tags": ["documentation"]}
{"directory_path": "/path/to/docs", "recursive": true}
{"directory_path": "/path/to/project", "file_extensions": ["md", "txt"], "tags": ["project-docs"]}
""",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "file_path": {
                                "type": "string",
                                "description": "Path to single document (for file mode)"
                            },
                            "directory_path": {
                                "type": "string",
                                "description": "Path to directory (for directory mode)"
                            },
                            "tags": {
                                "type": "array",
                                "items": {"type": "string"},
                                "default": [],
                                "description": "Tags to apply to all ingested memories"
                            },
                            "chunk_size": {
                                "type": "integer",
                                "default": 1000,
                                "description": "Target chunk size in characters"
                            },
                            "chunk_overlap": {
                                "type": "integer",
                                "default": 200,
                                "description": "Overlap between chunks"
                            },
                            "memory_type": {
                                "type": "string",
                                "default": "document",
                                "description": "Type label for created memories"
                            },
                            "recursive": {
                                "type": "boolean",
                                "default": True,
                                "description": "For directory mode: process subdirectories"
                            },
                            "file_extensions": {
                                "type": "array",
                                "items": {"type": "string"},
                                "default": ["pdf", "txt", "md", "json"],
                                "description": "For directory mode: file types to process"
                            },
                            "max_files": {
                                "type": "integer",
                                "default": 100,
                                "description": "For directory mode: maximum files to process"
                            }
                        }
                    },
                    annotations=types.ToolAnnotations(
                        title="Ingest Documents",
                        destructiveHint=False,
                    ),
                )
            ]
            tools.extend(ingestion_tools)
            logger.info(f"Added {len(ingestion_tools)} ingestion tools")

            # Session harvest tools
            harvest_tools = [
                types.Tool(
                    name="memory_harvest",
                    description="""Extract learnings from Claude Code session transcripts.

USE THIS WHEN:
- End of session — auto-capture decisions, bugs, conventions, learnings
- User asks to "harvest" or "extract learnings" from sessions
- Building knowledge base from past sessions

MODES:
- dry_run=true (DEFAULT): Preview candidates without storing
- dry_run=false: Store candidates as tagged memories

MEMORY TYPES EXTRACTED:
- decision: Architectural choices, tool selections
- bug: Issues encountered and root causes
- convention: Patterns/rules established
- learning: Insights, mistakes learned from
- context: Session state for continuity

LLM CLASSIFICATION (Phase 2):
- use_llm=true: Validate candidates with Groq LLM (higher precision, ~$0.001/candidate)
- Filters conversation fragments, deduplicates, refines content
- Requires GROQ_API_KEY environment variable

Examples:
{"sessions": 1, "dry_run": true}
{"sessions": 3, "types": ["decision", "bug"]}
{"session_ids": ["abc123"], "dry_run": false}
{"min_confidence": 0.7, "sessions": 1}
{"sessions": 1, "use_llm": true, "dry_run": true}
""",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "sessions": {
                                "type": "integer",
                                "default": 1,
                                "description": "Number of recent sessions to harvest"
                            },
                            "session_ids": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Specific session IDs to harvest"
                            },
                            "types": {
                                "type": "array",
                                "items": {"type": "string", "enum": ["decision", "bug", "convention", "learning", "context"]},
                                "description": "Filter by memory types (default: all)"
                            },
                            "min_confidence": {
                                "type": "number",
                                "default": 0.6,
                                "description": "Minimum confidence threshold (0.0-1.0)"
                            },
                            "dry_run": {
                                "type": "boolean",
                                "default": True,
                                "description": "Preview candidates without storing (default: true)"
                            },
                            "project_path": {
                                "type": "string",
                                "description": "Override Claude Code project directory path"
                            },
                            "use_llm": {
                                "type": "boolean",
                                "default": False,
                                "description": "Use LLM to validate and refine candidates (requires GROQ_API_KEY)"
                            },
                            "auto_commit": {
                                "type": "boolean",
                                "default": False,
                                "description": "Bridge harvested candidates to commit_session_legacy (feeds bootstrap profile)"
                            },
                            "agent_id": {
                                "type": "string",
                                "description": "Agent ID for auto_commit attribution (default: MCP_AGENT_ID env or 'unknown')"
                            }
                        }
                    },
                    annotations=types.ToolAnnotations(
                        title="Harvest Session Learnings",
                        destructiveHint=False,
                    ),
                )
            ]
            tools.extend(harvest_tools)
            logger.info(f"Added {len(harvest_tools)} harvest tools")

            # Quality system tools
            quality_tools = [
                types.Tool(
                    name="memory_quality",
                    description="""Memory quality management - rate, inspect, and analyze.

ACTIONS:
- rate: Manually rate a memory's quality (thumbs up/down)
- get: Get quality metrics for a specific memory
- analyze: Analyze quality distribution across all memories
- maintain: Run maintenance cycle (cleanup + conflicts + stale + quality)
- maintain_status: Get stats from last maintenance run

Examples:
{"action": "rate", "content_hash": "abc123", "rating": 1, "feedback": "Very useful"}
{"action": "get", "content_hash": "abc123"}
{"action": "analyze"}
{"action": "analyze", "min_quality": 0.5, "max_quality": 1.0}
{"action": "maintain"}
{"action": "maintain", "dry_run": false}
{"action": "maintain_status"}
""",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "action": {
                                "type": "string",
                                "enum": ["rate", "get", "analyze", "maintain", "maintain_status"],
                                "description": "Quality action to perform"
                            },
                            "content_hash": {
                                "type": "string",
                                "description": "Memory hash (required for rate/get)"
                            },
                            "rating": {
                                "type": "string",
                                "enum": ["-1", "0", "1"],
                                "description": "For 'rate': '-1' (thumbs down), '0' (neutral), '1' (thumbs up)"
                            },
                            "feedback": {
                                "type": "string",
                                "description": "For 'rate': Optional feedback text"
                            },
                            "min_quality": {
                                "type": "number",
                                "default": 0.0,
                                "description": "For 'analyze': minimum quality threshold"
                            },
                            "max_quality": {
                                "type": "number",
                                "default": 1.0,
                                "description": "For 'analyze': maximum quality threshold"
                            },
                            "dry_run": {
                                "type": "boolean",
                                "default": True,
                                "description": "For 'maintain': preview mode — no modifications (default: true)"
                            }
                        },
                        "required": ["action"]
                    },
                    annotations=types.ToolAnnotations(
                        title="Memory Quality",
                        destructiveHint=False,
                    ),
                )
            ]
            tools.extend(quality_tools)
            logger.info(f"Added {len(quality_tools)} quality system tools")

            # Graph traversal tools
            graph_tools = [
                types.Tool(
                    name="memory_graph",
                    description="""Memory association graph operations - explore connections between memories.

ACTIONS:
- connected: Find memories connected via associations (BFS traversal)
- path: Find shortest path between two memories
- subgraph: Get graph structure around a memory for visualization
- infer: Find transitive relationships (A→B→C implies A→C). Params: rel_type (string), max_hops (int, default 2)
- suggest: Suggest potential relationships for a memory based on shared neighbors. Params: hash (string)

Examples:
{"action": "connected", "hash": "abc123", "max_hops": 2}
{"action": "path", "hash1": "abc123", "hash2": "def456", "max_depth": 5}
{"action": "subgraph", "hash": "abc123", "radius": 2}
{"action": "infer", "rel_type": "causes", "max_hops": 2}
{"action": "suggest", "hash": "abc123"}
""",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "action": {
                                "type": "string",
                                "enum": ["connected", "path", "subgraph", "infer", "suggest"],
                                "description": "Graph operation to perform"
                            },
                            "hash": {
                                "type": "string",
                                "description": "Memory hash (for connected/subgraph)"
                            },
                            "hash1": {
                                "type": "string",
                                "description": "Start memory hash (for path)"
                            },
                            "hash2": {
                                "type": "string",
                                "description": "End memory hash (for path)"
                            },
                            "max_hops": {
                                "type": "integer",
                                "default": 2,
                                "description": "For 'connected': max traversal depth"
                            },
                            "max_depth": {
                                "type": "integer",
                                "default": 5,
                                "description": "For 'path': max path length"
                            },
                            "radius": {
                                "type": "integer",
                                "default": 2,
                                "description": "For 'subgraph': nodes to include"
                            },
                            "rel_type": {
                                "type": "string",
                                "description": "For 'infer': relationship type to traverse"
                            }
                        },
                        "required": ["action"]
                    },
                    annotations=types.ToolAnnotations(
                        title="Memory Graph",
                        readOnlyHint=True,
                    ),
                )
            ]
            tools.extend(graph_tools)
            logger.info(f"Added {len(graph_tools)} graph traversal tools")

            # Conflict detection tools
            conflict_tools = [
                types.Tool(
                    name="memory_conflicts",
                    description="List unresolved memory conflicts (contradictory memories detected by similarity analysis)",
                    inputSchema={"type": "object", "properties": {}, "required": []},
                    annotations=types.ToolAnnotations(
                        title="Memory Conflicts",
                        readOnlyHint=True,
                        destructiveHint=False,
                    ),
                ),
                types.Tool(
                    name="memory_resolve",
                    description="Resolve a memory conflict by choosing a winner",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "winner_hash": {"type": "string", "description": "Content hash of the correct memory"},
                            "loser_hash": {"type": "string", "description": "Content hash of the incorrect memory"},
                        },
                        "required": ["winner_hash", "loser_hash"],
                    },
                    annotations=types.ToolAnnotations(
                        title="Resolve Memory Conflict",
                        destructiveHint=True,
                    ),
                ),
            ]
            tools.extend(conflict_tools)
            logger.info(f"Added {len(conflict_tools)} conflict detection tools")

            # Mistake Notes tools
            mistake_tools = [
                types.Tool(
                    name="mistake_note_add",
                    description="Record a mistake pattern for error replay. Tracks what went wrong and the correct action. Auto-increments failure_count for repeated patterns.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "error_pattern": {"type": "string", "description": "The error pattern or message"},
                            "context_signature": {"type": "string", "description": "Context where the error occurred (file, function, task type)"},
                            "incorrect_action": {"type": "string", "description": "What was done incorrectly"},
                            "correct_action": {"type": "string", "description": "What should have been done instead"},
                        },
                        "required": ["error_pattern", "context_signature", "incorrect_action", "correct_action"],
                    },
                ),
                types.Tool(
                    name="mistake_note_search",
                    description="Search mistake notes by semantic similarity. Use before starting a task to check for known pitfalls and past errors.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "query": {"type": "string", "description": "Search query (error message, context, or task description)"},
                            "limit": {"type": "integer", "default": 5, "description": "Max results (default: 5)"},
                        },
                        "required": ["query"],
                    },
                    annotations=types.ToolAnnotations(
                        title="Search Mistake Notes",
                        readOnlyHint=True,
                    ),
                ),
                types.Tool(
                    name="mistake_note_update",
                    description="Update fields of an existing mistake note. Can update failure_count, error_pattern, context_signature, incorrect_action, or correct_action. Content changes create a new hash (delete + re-store).",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "content_hash": {"type": "string", "description": "Content hash of the mistake note to update"},
                            "failure_count": {"type": "integer", "description": "New failure count"},
                            "error_pattern": {"type": "string", "description": "Updated error pattern"},
                            "context_signature": {"type": "string", "description": "Updated context"},
                            "incorrect_action": {"type": "string", "description": "Updated incorrect action"},
                            "correct_action": {"type": "string", "description": "Updated correct action"},
                        },
                        "required": ["content_hash"],
                    },
                ),
                types.Tool(
                    name="mistake_note_delete",
                    description="Delete a mistake note by content hash. Only deletes memories with memory_type='mistake'.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "content_hash": {"type": "string", "description": "Content hash of the mistake note to delete"},
                        },
                        "required": ["content_hash"],
                    },
                ),
            ]
            tools.extend(mistake_tools)
            logger.info(f"Added {len(mistake_tools)} mistake note tools")

            # §6 Anti-Hallucination quarantine tools
            quarantine_tools = [
                types.Tool(
                    name="get_quarantined_memories",
                    description="List memories that have been quarantined due to contradicting active beliefs. Use to review flagged memories.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "limit": {"type": "integer", "default": 50, "description": "Maximum results to return"},
                        },
                    },
                    annotations=types.ToolAnnotations(
                        title="Get Quarantined Memories",
                        readOnlyHint=True,
                    ),
                ),
                types.Tool(
                    name="unquarantine_memory",
                    description="Release a memory from quarantine. Use when a quarantined memory is valid (e.g., the contradicted belief was wrong).",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "content_hash": {"type": "string", "description": "Content hash of the quarantined memory"},
                        },
                        "required": ["content_hash"],
                    },
                    annotations=types.ToolAnnotations(
                        title="Unquarantine Memory",
                        readOnlyHint=False,
                    ),
                ),
            ]
            tools.extend(quarantine_tools)
            logger.info(f"Added {len(quarantine_tools)} quarantine tools")

            # Session Legacy + Bootstrap Profile tools (RFC Self-Service Memory Intelligence)
            intelligence_tools = [
                types.Tool(
                    name="commit_session_legacy",
                    description="Record end-of-session learnings from an ephemeral agent. Stores decisions, errors, corrections as structured observations.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "session_id": {"type": "string", "description": "Unique session identifier"},
                            "agent_id": {"type": "string", "description": "Agent identifier"},
                            "task_summary": {"type": "string", "description": "Brief description of what was attempted"},
                            "outcome": {"type": "string", "enum": ["success", "partial", "failure"]},
                            "decisions": {"type": "array", "items": {"type": "object"}, "description": "Decisions made"},
                            "errors": {"type": "array", "items": {"type": "object"}, "description": "Errors encountered"},
                            "user_corrections": {"type": "array", "items": {"type": "object"}, "description": "User corrections"},
                            "belief_updates": {"type": "array", "items": {"type": "object"}, "description": "Belief updates"},
                        },
                        "required": ["session_id", "agent_id", "task_summary", "outcome"],
                    },
                ),
                types.Tool(
                    name="get_bootstrap_profile",
                    description="Generate a behavioral bootstrap profile for an ephemeral agent.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "agent_ids": {"type": "array", "items": {"type": "string"}, "minItems": 1, "description": "Agent identifiers"},
                            "project_id": {"type": "string", "description": "Optional project scope"},
                            "task_summary": {"type": "string", "description": "Optional task context"},
                            "max_tokens": {"type": "integer", "default": 2048, "description": "Token budget"},
                        },
                        "required": ["agent_ids"],
                    },
                ),
                types.Tool(
                    name="get_onboarding_guide",
                    description="Get integration guide for a specific client type. "
                                "Returns instructions on how to use this memory server optimally "
                                "(what to call on startup, shutdown, during session).",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "client_type": {"type": "string", "default": "generic", "description": "Client type (generic, kiro, claude-code)"},
                        },
                    },
                ),
                types.Tool(
                    name="memory_distill",
                    description="Extract insights from existing memories via LLM rewriter (batch mode). "
                                "Reprocesses long memories to extract actionable insights buried in verbose text. "
                                "Use dry_run=true to preview candidates without storing.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "batch_size": {"type": "integer", "default": 20, "description": "Max memories to process per run"},
                            "dry_run": {"type": "boolean", "default": True, "description": "Preview candidates without storing (default: true)"},
                            "memory_types": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Memory types to process (default: observation, decision, reference, learning)",
                            },
                        },
                    },
                    annotations=types.ToolAnnotations(
                        title="Distill Memory Insights",
                        destructiveHint=False,
                    ),
                ),
            ]
            tools.extend(intelligence_tools)
            logger.info(f"Added {len(intelligence_tools)} intelligence tools")

            logger.info(f"Returning {len(tools)} tools")
            return tools
        except Exception as e:
            logger.error(f"Error in handle_list_tools: {str(e)}")
            logger.error(traceback.format_exc())
            raise

    async def call_tool(self, name: str, arguments: dict | None) -> List[types.TextContent]:
        """Dispatch a tool call (shared by stdio and HTTP transports).

        Handles deprecated-name rewriting via `compat.transform_deprecated_call`
        and routes to the appropriate handler. Returns the tool's response
        content.
        """
        # Add immediate debugging to catch any protocol issues
        if MCP_CLIENT == 'lm_studio':
            print(f"TOOL CALL INTERCEPTED: {name}", file=sys.stdout, flush=True)
        logger.info("=== HANDLING TOOL CALL: %s ===", _sanitize_log_value(name))
        logger.info("Arguments: %s", _sanitize_log_value(arguments))

        try:
            # Ensure arguments is a dict
            if arguments is None:
                arguments = {}

            logger.info("Processing tool: %s", _sanitize_log_value(name))
            if MCP_CLIENT == 'lm_studio':
                print(f"Processing tool: {name}", file=sys.stdout, flush=True)

            # Handle deprecated tools using centralized compatibility layer
            if is_deprecated(name):
                name, arguments = transform_deprecated_call(name, arguments)
                logger.info(f"Transformed to: {name} with arguments: {arguments}")

            # Route to handler (using NEW tool names only)
            if name == "memory_store":
                return await self.handle_store_memory(arguments)
            elif name == "memory_observe":
                return await self.handle_memory_observe(arguments)
            elif name == "memory_store_session":
                return await self.handle_store_session(arguments)
            elif name == "memory_search":
                return await self.handle_memory_search(arguments)
            elif name == "memory_list":
                return await self.handle_memory_list(arguments)
            elif name == "memory_delete":
                return await self.handle_memory_delete(arguments)
            elif name == "memory_update":
                logger.info("Calling handle_update_memory_metadata")
                return await self.handle_update_memory_metadata(arguments)
            elif name == "memory_health":
                logger.info("Calling handle_check_database_health")
                return await self.handle_check_database_health(arguments)
            elif name == "memory_stats":
                logger.info("Calling handle_get_cache_stats")
                return await self.handle_get_cache_stats(arguments)
            elif name == "memory_consolidate":
                logger.info("Calling handle_memory_consolidate")
                return await self.handle_memory_consolidate(arguments)
            elif name == "memory_cleanup":
                return await self.handle_cleanup_duplicates(arguments)
            elif name == "memory_ingest":
                logger.info("Calling handle_memory_ingest")
                return await self.handle_memory_ingest(arguments)
            elif name == "memory_quality":
                logger.info("Calling handle_memory_quality")
                return await self.handle_memory_quality(arguments)
            elif name == "memory_graph":
                logger.info("Calling handle_memory_graph")
                return await self.handle_memory_graph(arguments)
            elif name == "memory_harvest":
                logger.info("Calling handle_memory_harvest")
                return await self.handle_memory_harvest(arguments)
            elif name == "memory_distill":
                logger.info("Calling handle_memory_distill")
                return await self.handle_memory_distill(arguments)
            elif name == "memory_conflicts":
                logger.info("Calling handle_memory_conflicts")
                from .server.handlers import quality as quality_handlers
                return await quality_handlers.handle_memory_conflicts(self, arguments)
            elif name == "memory_resolve":
                logger.info("Calling handle_memory_resolve")
                from .server.handlers import quality as quality_handlers
                return await quality_handlers.handle_memory_resolve(self, arguments)

            elif name == "mistake_note_add":
                logger.info("Calling handle_mistake_note_add")
                from .server.handlers import mistake_notes as mistake_handlers
                return await mistake_handlers.handle_mistake_note_add(self, arguments)
            elif name == "mistake_note_search":
                logger.info("Calling handle_mistake_note_search")
                from .server.handlers import mistake_notes as mistake_handlers
                return await mistake_handlers.handle_mistake_note_search(self, arguments)
            elif name == "mistake_note_update":
                logger.info("Calling handle_mistake_note_update")
                from .server.handlers import mistake_notes as mistake_handlers
                return await mistake_handlers.handle_mistake_note_update(self, arguments)
            elif name == "mistake_note_delete":
                logger.info("Calling handle_mistake_note_delete")
                from .server.handlers import mistake_notes as mistake_handlers
                return await mistake_handlers.handle_mistake_note_delete(self, arguments)
            elif name == "commit_session_legacy":
                logger.info("Calling handle_commit_session_legacy")
                return await self.handle_commit_session_legacy(arguments)
            elif name == "get_onboarding_guide":
                client_type = (arguments or {}).get("client_type", "generic")
                return [types.TextContent(type="text", text=_get_onboarding_guide(client_type))]
            elif name == "get_bootstrap_profile":
                logger.info("Calling handle_get_bootstrap_profile")
                return await self.handle_get_bootstrap_profile(arguments)

            # §6 Anti-Hallucination quarantine tools
            elif name == "get_quarantined_memories":
                from .consolidation.quarantine import get_quarantined_memories
                limit = (arguments or {}).get("limit", 50)
                results = await get_quarantined_memories(self.storage, limit=limit)
                return [types.TextContent(type="text", text=json.dumps({"quarantined": results, "count": len(results)}, indent=2))]
            elif name == "unquarantine_memory":
                from .consolidation.quarantine import unquarantine_memory as _unquarantine
                content_hash = (arguments or {}).get("content_hash", "")
                if not content_hash:
                    return [types.TextContent(type="text", text="Error: content_hash is required")]
                result = await _unquarantine(self.storage, content_hash)
                return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

            # Legacy handlers (for tools that haven't been fully migrated yet)
            # These will be removed once all old tool definitions are removed
            elif name == "retrieve_memory":
                return await self.handle_retrieve_memory(arguments)
            elif name == "retrieve_with_quality_boost":
                return await self.handle_retrieve_with_quality_boost(arguments)
            elif name == "recall_memory":
                return await self.handle_recall_memory(arguments)
            elif name == "search_by_tag":
                return await self.handle_search_by_tag(arguments)
            elif name == "delete_memory":
                return await self.handle_delete_memory(arguments)
            elif name == "delete_by_tag":
                return await self.handle_delete_by_tag(arguments)
            elif name == "delete_by_tags":
                return await self.handle_delete_by_tags(arguments)
            elif name == "delete_by_all_tags":
                return await self.handle_delete_by_all_tags(arguments)
            elif name == "debug_retrieve":
                return await self.handle_debug_retrieve(arguments)
            elif name == "exact_match_retrieve":
                return await self.handle_exact_match_retrieve(arguments)
            elif name == "get_raw_embedding":
                return await self.handle_get_raw_embedding(arguments)
            elif name == "recall_by_timeframe":
                return await self.handle_recall_by_timeframe(arguments)
            elif name == "delete_by_timeframe":
                return await self.handle_delete_by_timeframe(arguments)
            elif name == "delete_before_date":
                return await self.handle_delete_before_date(arguments)
            elif name == "consolidate_memories":
                logger.info("Calling handle_consolidate_memories")
                return await self.handle_consolidate_memories(arguments)
            elif name == "consolidation_status":
                logger.info("Calling handle_consolidation_status")
                return await self.handle_consolidation_status(arguments)
            elif name == "consolidation_recommendations":
                logger.info("Calling handle_consolidation_recommendations")
                return await self.handle_consolidation_recommendations(arguments)
            elif name == "scheduler_status":
                logger.info("Calling handle_scheduler_status")
                return await self.handle_scheduler_status(arguments)
            elif name == "trigger_consolidation":
                logger.info("Calling handle_trigger_consolidation")
                return await self.handle_trigger_consolidation(arguments)
            elif name == "pause_consolidation":
                logger.info("Calling handle_pause_consolidation")
                return await self.handle_pause_consolidation(arguments)
            elif name == "resume_consolidation":
                logger.info("Calling handle_resume_consolidation")
                return await self.handle_resume_consolidation(arguments)
            elif name == "ingest_document":
                logger.info("Calling handle_ingest_document")
                return await self.handle_ingest_document(arguments)
            elif name == "ingest_directory":
                logger.info("Calling handle_ingest_directory")
                return await self.handle_ingest_directory(arguments)
            elif name == "memory_rate":
                logger.info("Calling handle_rate_memory")
                return await self.handle_rate_memory(arguments)
            elif name == "get_memory_quality":
                logger.info("Calling handle_get_memory_quality")
                return await self.handle_get_memory_quality(arguments)
            elif name == "analyze_quality_distribution":
                logger.info("Calling handle_analyze_quality_distribution")
                return await self.handle_analyze_quality_distribution(arguments)
            elif name == "find_connected_memories":
                logger.info("Calling handle_find_connected_memories")
                return await self.handle_find_connected_memories(arguments)
            elif name == "find_shortest_path":
                logger.info("Calling handle_find_shortest_path")
                return await self.handle_find_shortest_path(arguments)
            elif name == "get_memory_subgraph":
                logger.info("Calling handle_get_memory_subgraph")
                return await self.handle_get_memory_subgraph(arguments)
            else:
                logger.warning("Unknown tool requested: %s", _sanitize_log_value(name))
                raise ValueError(f"Unknown tool: {name}")
        except Exception as e:
            error_msg = f"Error in {_sanitize_log_value(name)}: {str(e)}\n{traceback.format_exc()}"
            logger.error("%s", error_msg)
            print(f"ERROR in tool execution: {error_msg}", file=sys.stderr, flush=True)
            return [types.TextContent(type="text", text=f"Error: {str(e)}")]

    async def handle_call_tool(self, name: str, arguments: dict | None) -> List[types.TextContent]:
        """Public alias for call_tool (used by tests)."""
        return await self.call_tool(name, arguments)

    async def handle_list_tools(self) -> List[types.Tool]:
        """Public alias for list_tools (used by tests)."""
        return await self.list_tools()

    async def handle_store_memory(self, arguments: dict) -> List[types.TextContent]:
        """Store new memory (delegates to handler)."""
        from .server.handlers import memory as memory_handlers
        result = await memory_handlers.handle_store_memory(self, arguments)
        # §3: Increment consolidation counter on successful store
        self._consolidation_counter += 1
        await self._check_consolidation_threshold()
        return result

    async def handle_memory_observe(self, arguments: dict) -> List[types.TextContent]:
        """Observe conversation and auto-capture learnings (delegates to handler)."""
        from .server.handlers import memory as memory_handlers
        return await memory_handlers.handle_memory_observe(self, arguments)

    async def handle_store_session(self, arguments: dict) -> List[types.TextContent]:
        """Store a conversation session as one memory unit (delegates to handler)."""
        from .server.handlers import memory as memory_handlers
        return await memory_handlers.handle_store_session(self, arguments)

    async def handle_retrieve_memory(self, arguments: dict) -> List[types.TextContent]:
        """Retrieve memories (delegates to handler)."""
        from .server.handlers import memory as memory_handlers
        return await memory_handlers.handle_retrieve_memory(self, arguments)

    async def handle_memory_search(self, arguments: dict) -> List[types.TextContent]:
        """Unified memory search (delegates to handler)."""
        from .server.handlers import memory as memory_handlers
        return await memory_handlers.handle_memory_search(self, arguments)

    async def handle_retrieve_with_quality_boost(self, arguments: dict) -> List[types.TextContent]:
        """Handle quality-boosted memory retrieval with reranking (delegates to handler)."""
        from .server.handlers import memory as memory_handlers
        return await memory_handlers.handle_retrieve_with_quality_boost(self, arguments)

    async def handle_memory_list(self, arguments: dict) -> List[types.TextContent]:
        """List memories with pagination and filters (delegates to handler)."""
        from .server.handlers import memory as memory_handlers
        return await memory_handlers.handle_memory_list(self, arguments)

    async def handle_search_by_tag(self, arguments: dict) -> List[types.TextContent]:
        """Search by tag (delegates to handler)."""
        from .server.handlers import memory as memory_handlers
        return await memory_handlers.handle_search_by_tag(self, arguments)

    async def handle_delete_memory(self, arguments: dict) -> List[types.TextContent]:
        """Delete memory (delegates to handler)."""
        from .server.handlers import memory as memory_handlers
        return await memory_handlers.handle_delete_memory(self, arguments)

    async def handle_memory_delete(self, arguments: dict) -> List[types.TextContent]:
        """Unified memory deletion (delegates to handler)."""
        from .server.handlers import memory as memory_handlers
        return await memory_handlers.handle_memory_delete(self, arguments)

    async def handle_delete_by_tag(self, arguments: dict) -> List[types.TextContent]:
        """Handler for deleting memories by tags (delegates to handler)."""
        from .server.handlers import memory as memory_handlers
        return await memory_handlers.handle_delete_by_tag(self, arguments)

    async def handle_delete_by_tags(self, arguments: dict) -> List[types.TextContent]:
        """Handler for explicit multiple tag deletion with progress tracking (delegates to handler)."""
        from .server.handlers import memory as memory_handlers
        return await memory_handlers.handle_delete_by_tags(self, arguments)

    async def handle_delete_by_all_tags(self, arguments: dict) -> List[types.TextContent]:
        """Handler for deleting memories that contain ALL specified tags (delegates to handler)."""
        from .server.handlers import memory as memory_handlers
        return await memory_handlers.handle_delete_by_all_tags(self, arguments)

    async def handle_cleanup_duplicates(self, arguments: dict) -> List[types.TextContent]:
        """Cleanup duplicates (delegates to handler)."""
        from .server.handlers import memory as memory_handlers
        return await memory_handlers.handle_cleanup_duplicates(self, arguments)

    async def handle_update_memory_metadata(self, arguments: dict) -> List[types.TextContent]:
        """Handle memory metadata update requests (delegates to handler)."""
        from .server.handlers import memory as memory_handlers
        return await memory_handlers.handle_update_memory_metadata(self, arguments)

    # Consolidation tool handlers
    async def handle_consolidate_memories(self, arguments: dict) -> List[types.TextContent]:
        """Handle memory consolidation requests (delegates to handler)."""
        from .server.handlers import consolidation as consolidation_handlers
        return await consolidation_handlers.handle_consolidate_memories(self, arguments)

    async def handle_memory_consolidate(self, arguments: dict) -> List[types.TextContent]:
        """Unified memory consolidation management (delegates to handler)."""
        from .server.handlers import consolidation as consolidation_handlers
        return await consolidation_handlers.handle_memory_consolidate(self, arguments)

    async def handle_consolidation_status(self, arguments: dict) -> List[types.TextContent]:
        """Handle consolidation status requests (delegates to handler)."""
        from .server.handlers import consolidation as consolidation_handlers
        return await consolidation_handlers.handle_consolidation_status(self, arguments)

    async def handle_consolidation_recommendations(self, arguments: dict) -> List[types.TextContent]:
        """Handle consolidation recommendation requests (delegates to handler)."""
        from .server.handlers import consolidation as consolidation_handlers
        return await consolidation_handlers.handle_consolidation_recommendations(self, arguments)

    async def handle_scheduler_status(self, arguments: dict) -> List[types.TextContent]:
        """Handle scheduler status requests (delegates to handler)."""
        from .server.handlers import consolidation as consolidation_handlers
        return await consolidation_handlers.handle_scheduler_status(self, arguments)

    async def handle_trigger_consolidation(self, arguments: dict) -> List[types.TextContent]:
        """Handle manual consolidation trigger requests (delegates to handler)."""
        from .server.handlers import consolidation as consolidation_handlers
        return await consolidation_handlers.handle_trigger_consolidation(self, arguments)

    async def handle_pause_consolidation(self, arguments: dict) -> List[types.TextContent]:
        """Handle consolidation pause requests (delegates to handler)."""
        from .server.handlers import consolidation as consolidation_handlers
        return await consolidation_handlers.handle_pause_consolidation(self, arguments)

    async def handle_resume_consolidation(self, arguments: dict) -> List[types.TextContent]:
        """Handle consolidation resume requests (delegates to handler)."""
        from .server.handlers import consolidation as consolidation_handlers
        return await consolidation_handlers.handle_resume_consolidation(self, arguments)

    async def handle_debug_retrieve(self, arguments: dict) -> List[types.TextContent]:
        """Debug retrieve (delegates to handler)."""
        from .server.handlers import memory as memory_handlers
        return await memory_handlers.handle_debug_retrieve(self, arguments)

    async def handle_exact_match_retrieve(self, arguments: dict) -> List[types.TextContent]:
        """Exact match retrieve (delegates to handler)."""
        from .server.handlers import memory as memory_handlers
        return await memory_handlers.handle_exact_match_retrieve(self, arguments)

    async def handle_get_raw_embedding(self, arguments: dict) -> List[types.TextContent]:
        """Get raw embedding (delegates to handler)."""
        from .server.handlers import memory as memory_handlers
        return await memory_handlers.handle_get_raw_embedding(self, arguments)

    async def handle_recall_memory(self, arguments: dict) -> List[types.TextContent]:
        """Handle memory recall requests with natural language time expressions (delegates to handler)."""
        from .server.handlers import memory as memory_handlers
        return await memory_handlers.handle_recall_memory(self, arguments)

    async def handle_check_database_health(self, arguments: dict) -> List[types.TextContent]:
        """Handle database health check requests (delegates to handler)."""
        from .server.handlers import utility as utility_handlers
        return await utility_handlers.handle_check_database_health(self, arguments)

    async def handle_get_cache_stats(self, arguments: dict) -> List[types.TextContent]:
        """Get MCP server global cache statistics (delegates to handler)."""
        from .server.handlers import utility as utility_handlers
        return await utility_handlers.handle_get_cache_stats(self, arguments)

    async def handle_recall_by_timeframe(self, arguments: dict) -> List[types.TextContent]:
        """Handle recall by timeframe requests (delegates to handler)."""
        from .server.handlers import memory as memory_handlers
        return await memory_handlers.handle_recall_by_timeframe(self, arguments)

    async def handle_delete_by_timeframe(self, arguments: dict) -> List[types.TextContent]:
        """Handle delete by timeframe requests (delegates to handler)."""
        from .server.handlers import memory as memory_handlers
        return await memory_handlers.handle_delete_by_timeframe(self, arguments)

    async def handle_delete_before_date(self, arguments: dict) -> List[types.TextContent]:
        """Handle delete before date requests (delegates to handler)."""
        from .server.handlers import memory as memory_handlers
        return await memory_handlers.handle_delete_before_date(self, arguments)

    async def handle_memory_ingest(self, arguments: dict) -> List[types.TextContent]:
        """Handle unified document/directory ingestion (delegates to handler)."""
        from .server.handlers import documents as document_handlers
        return await document_handlers.handle_memory_ingest(self, arguments)

    async def handle_memory_harvest(self, arguments: dict) -> List[types.TextContent]:
        """Handle memory_harvest tool calls — extract learnings from session transcripts."""
        import os
        from pathlib import Path as _Path
        from .harvest.harvester import SessionHarvester
        from .harvest.models import HarvestConfig, MAX_CANDIDATE_PREVIEW_LENGTH

        # Resolve project directory
        project_path = arguments.get("project_path")
        if not project_path:
            # Check env var override first (supports any CLI)
            env_override = os.environ.get("MCP_HARVEST_SESSION_DIR")
            if env_override:
                project_path = _Path(env_override).expanduser()
            else:
                # Default: Claude Code project dir from cwd
                cwd = _Path.cwd()
                claude_projects = _Path.home() / ".claude" / "projects"
                project_dir_name = str(cwd).replace(os.sep, "-")
                project_path = claude_projects / project_dir_name
                # Fallback: Kiro CLI sessions if Claude path doesn't exist
                if not project_path.exists():
                    kiro_sessions = _Path.home() / ".kiro" / "sessions" / "cli"
                    if kiro_sessions.exists():
                        project_path = kiro_sessions
        else:
            project_path = _Path(project_path).resolve()  # codeql[py/path-injection]

        if not project_path.exists():  # codeql[py/path-injection]
            return [types.TextContent(
                type="text",
                text=json.dumps({"error": f"Project directory not found: {project_path}"})
            )]

        config = HarvestConfig(
            sessions=arguments.get("sessions", 1),
            session_ids=arguments.get("session_ids"),
            types=arguments.get("types", ["decision", "bug", "convention", "learning", "context"]),
            min_confidence=arguments.get("min_confidence", 0.6),
            dry_run=arguments.get("dry_run", True),
            project_path=str(project_path),
            use_llm=arguments.get("use_llm", False),
        )

        memory_service = None
        if not config.dry_run:
            await self._ensure_storage_initialized()
            memory_service = self.memory_service

        # T1 Fix: Filter out already-harvested sessions to prevent cross-run duplicates
        already_harvested = set()
        if not config.dry_run and not config.session_ids:
            async with self._harvest_lock:
                try:
                    tracker = await self.memory_service.list_memories(
                        page=1, page_size=1, tags=["harvest-tracker"],
                    )
                    for mem in tracker.get("memories", []):
                        content = mem.get("content", "")
                        if content.startswith("harvested_sessions:"):
                            ids_str = content.split(":", 1)[1]
                            already_harvested = {s for s in ids_str.split(",") if s}
                            break
                except Exception:
                    pass  # First run or tracker not found — proceed normally

        harvester = SessionHarvester(
            project_dir=project_path,
            memory_service=memory_service
        )

        if config.dry_run:
            results = harvester.harvest(config)
        else:
            # Pagination: resolve ALL sessions, filter by tracker, take config.sessions
            if already_harvested and not config.session_ids:
                from .harvest.models import HarvestConfig as _HC
                all_config = _HC(sessions=9999, project_path=config.project_path)
                all_sessions = harvester._resolve_sessions(all_config)
                filtered_sessions = [
                    s for s in all_sessions if s.stem not in already_harvested
                ]
                if not filtered_sessions:
                    return [types.TextContent(type="text", text=json.dumps({
                        "dry_run": False, "results": [],
                        "note": f"All {len(all_sessions)} sessions already harvested"
                    }))]
                # Process next batch (config.sessions = page size)
                config.session_ids = [s.stem for s in filtered_sessions[:config.sessions]]

            results = await harvester.harvest_and_store(config)

            # Track newly harvested sessions
            if results:
                new_ids = {r.session_id for r in results if r.session_id}
                if new_ids:
                    all_harvested = already_harvested | new_ids
                    tracker_content = f"harvested_sessions:{','.join(sorted(all_harvested))}"
                    # Upsert tracker (delete old + store new)
                    try:
                        old_tracker = await self.memory_service.list_memories(
                            page=1, page_size=1, tags=["harvest-tracker"],
                        )
                        for mem in old_tracker.get("memories", []):
                            await self.memory_service.storage.delete(mem["content_hash"])
                        await self.memory_service.store_memory(
                            content=tracker_content,
                            tags=["harvest-tracker"],
                            memory_type="observation",
                            metadata={"count": len(all_harvested)},
                        )
                    except Exception as e:
                        logger.warning(f"Failed to update harvest tracker: {e}")

        output = {
            "dry_run": config.dry_run,
            "results": [
                {
                    "session_id": r.session_id,
                    "total_messages": r.total_messages,
                    "found": r.found,
                    "stored": r.stored,
                    "by_type": r.by_type,
                    "candidates": [
                        {
                            "type": c.memory_type,
                            "content": c.content[:MAX_CANDIDATE_PREVIEW_LENGTH],
                            "confidence": round(c.confidence, 2),
                            "tags": c.tags,
                        }
                        for c in r.candidates
                    ]
                }
                for r in results
            ]
        }

        # §9: auto_commit — bridge harvest candidates to commit_session_legacy
        auto_commit = arguments.get("auto_commit", False)
        auto_commit_agent_id = arguments.get("agent_id", os.getenv("MCP_AGENT_ID", "unknown"))
        if auto_commit and not config.dry_run and results:
            auto_commit_results = []
            for r in results:
                if not r.candidates:
                    continue
                # Map candidates to commit_session_legacy fields
                decisions = [
                    {"decision": c.content[:500], "reason": "harvested"}
                    for c in r.candidates if c.memory_type == "decision"
                ]
                errors = [
                    {"error": c.content[:500], "count": 1, "severity": "medium"}
                    for c in r.candidates if c.memory_type == "bug"
                ]
                belief_updates = [
                    {"belief": c.content[:500], "new_confidence": round(c.confidence, 2)}
                    for c in r.candidates if c.memory_type in ("convention", "learning")
                ]
                # First context candidate becomes task_summary
                context_candidates = [c for c in r.candidates if c.memory_type == "context"]
                task_summary = context_candidates[0].content[:200] if context_candidates else "Harvested session"

                commit_args = {
                    "session_id": r.session_id,
                    "agent_id": auto_commit_agent_id,
                    "task_summary": task_summary,
                    "outcome": "success",
                    "decisions": decisions,
                    "errors": errors,
                    "belief_updates": belief_updates,
                }
                try:
                    commit_result = await self.handle_commit_session_legacy(commit_args)
                    auto_commit_results.append({
                        "session_id": r.session_id,
                        "committed": True,
                        "result": json.loads(commit_result[0].text) if commit_result else None,
                    })
                except Exception as e:
                    auto_commit_results.append({
                        "session_id": r.session_id,
                        "committed": False,
                        "error": str(e),
                    })
            output["auto_commit_results"] = auto_commit_results

        return [types.TextContent(type="text", text=json.dumps(output, indent=2))]

    async def handle_ingest_document(self, arguments: dict) -> List[types.TextContent]:
        """Handle document ingestion requests (delegates to handler)."""
        from .server.handlers import documents as document_handlers
        return await document_handlers.handle_ingest_document(self, arguments)

    async def handle_ingest_directory(self, arguments: dict) -> List[types.TextContent]:
        """Handle directory ingestion requests (delegates to handler)."""
        from .server.handlers import documents as document_handlers
        return await document_handlers.handle_ingest_directory(self, arguments)

    async def handle_memory_quality(self, arguments: dict) -> List[types.TextContent]:
        """Unified quality management handler (delegates to handler)."""
        from .server.handlers import quality as quality_handlers
        return await quality_handlers.handle_memory_quality(self, arguments)

    async def handle_rate_memory(self, arguments: dict) -> List[types.TextContent]:
        """Handle memory quality rating (delegates to handler)."""
        from .server.handlers import quality as quality_handlers
        return await quality_handlers.handle_rate_memory(self, arguments)

    async def handle_get_memory_quality(self, arguments: dict) -> List[types.TextContent]:
        """Get memory quality metrics (delegates to handler)."""
        from .server.handlers import quality as quality_handlers
        return await quality_handlers.handle_get_memory_quality(self, arguments)

    async def handle_analyze_quality_distribution(self, arguments: dict) -> List[types.TextContent]:
        """Analyze quality distribution (delegates to handler)."""
        from .server.handlers import quality as quality_handlers
        return await quality_handlers.handle_analyze_quality_distribution(self, arguments)

    async def handle_memory_graph(self, arguments: dict) -> List[types.TextContent]:
        """Unified graph operations handler (delegates to handler)."""
        from .server.handlers import graph as graph_handlers
        return await graph_handlers.handle_memory_graph(self, arguments)

    async def handle_find_connected_memories(self, arguments: dict) -> List[types.TextContent]:
        """Find connected memories (delegates to handler)."""
        from .server.handlers import graph as graph_handlers
        return await graph_handlers.handle_find_connected_memories(self, arguments)

    async def handle_find_shortest_path(self, arguments: dict) -> List[types.TextContent]:
        """Find shortest path between memories (delegates to handler)."""
        from .server.handlers import graph as graph_handlers
        return await graph_handlers.handle_find_shortest_path(self, arguments)

    async def handle_get_memory_subgraph(self, arguments: dict) -> List[types.TextContent]:
        """Get memory subgraph for visualization (delegates to handler)."""
        from .server.handlers import graph as graph_handlers
        return await graph_handlers.handle_get_memory_subgraph(self, arguments)

    # ============================================================
    # Conflict Detection Handlers (delegates to quality handler)
    # ============================================================

    async def handle_memory_distill(self, arguments: dict) -> List[types.TextContent]:
        """Extract insights from existing memories via LLM rewriter (batch mode)."""
        import json as _json
        await self._ensure_storage_initialized()

        batch_size = arguments.get("batch_size", 20)
        dry_run = arguments.get("dry_run", True)
        min_length = 200
        skip_types = {"mistake", "insight", "session"}

        # Collect candidates
        candidates = []
        for mtype in ["observation", "decision", "reference", "learning"]:
            if mtype in skip_types:
                continue
            mems = await self.memory_service.list_memories(
                page=1, page_size=batch_size, memory_type=mtype
            )
            for mem in mems.get("memories", []):
                content = mem.get("content", "")
                tags = mem.get("tags", "") or ""
                # Normalize: tags can be string ("tag1,tag2") or list ["tag1","tag2"]
                tag_str = ",".join(tags) if isinstance(tags, list) else tags
                if len(content) < min_length:
                    continue
                if "memory-distilled" in tag_str or "association" in tag_str:
                    continue
                if "checkpoint" in tag_str and "sessao" in tag_str:
                    continue  # Session checkpoints are temporal by nature
                candidates.append(mem)

        candidates = candidates[:batch_size]

        if dry_run:
            result = {
                "dry_run": True,
                "candidates_found": len(candidates),
                "candidates": [
                    {"hash": c["content_hash"], "type": c["memory_type"], "preview": c["content"][:150]}
                    for c in candidates
                ],
            }
            return [types.TextContent(type="text", text=_json.dumps(result, indent=2))]

        # Batch rewrite via LLM
        from .harvest.rewriter import HarvestRewriter
        from pathlib import Path as _Path
        rewriter = HarvestRewriter()

        items = [{"content": m["content"][:800], "memory_type": m["memory_type"]} for m in candidates]
        batch_results = await rewriter.rewrite_batch(items)

        stored = []
        skipped = 0
        for mem, result in zip(candidates, batch_results):
            if not result:
                skipped += 1
                continue
            # Note: no meta-filter here — LLM already decides what's actionable.
            # Meta-filter is for harvest (raw conversations), not distill (curated memories).
            # Store insight
            original_tags = mem.get("tags", "")
            if isinstance(original_tags, list):
                original_tags = ",".join(original_tags)
            new_tags = f"memory-distill,consolidado,{original_tags}".rstrip(",")
            await self.memory_service.store_memory(
                content=result.content,
                tags=new_tags,
                memory_type=result.memory_type,
                metadata={"source_hash": mem["content_hash"]},
            )
            # Mark original as processed
            if isinstance(original_tags, list):
                tag_list = [t.strip() for t in original_tags if t.strip()]
            else:
                tag_list = [t.strip() for t in original_tags.split(",") if t.strip()]
            tag_list.append("memory-distilled")
            await self.memory_service.storage.update_memory_metadata(
                mem["content_hash"], {"tags": tag_list}
            )
            stored.append({"hash": mem["content_hash"], "insight": result.content[:100], "type": result.memory_type})

        output = {
            "dry_run": False,
            "processed": len(candidates),
            "stored": len(stored),
            "skipped": skipped,
            "insights": stored,
        }
        return [types.TextContent(type="text", text=_json.dumps(output, indent=2))]

    async def handle_memory_conflicts(self, arguments: dict) -> List[types.TextContent]:
        """List unresolved memory conflicts (delegates to handler)."""
        from .server.handlers import quality as quality_handlers
        return await quality_handlers.handle_memory_conflicts(self, arguments)

    async def handle_memory_resolve(self, arguments: dict) -> List[types.TextContent]:
        """Resolve a memory conflict (delegates to handler)."""
        from .server.handlers import quality as quality_handlers
        return await quality_handlers.handle_memory_resolve(self, arguments)

    # ─── Mistake Notes Handlers (delegates to handler) ────────────

    async def handle_mistake_note_add(self, arguments: dict) -> List[types.TextContent]:
        """Record a mistake pattern for error replay (delegates to handler)."""
        from .server.handlers import mistake_notes as mistake_handlers
        return await mistake_handlers.handle_mistake_note_add(self, arguments)

    async def handle_mistake_note_search(self, arguments: dict) -> List[types.TextContent]:
        """Search mistake notes by semantic similarity (delegates to handler)."""
        from .server.handlers import mistake_notes as mistake_handlers
        return await mistake_handlers.handle_mistake_note_search(self, arguments)

    async def handle_mistake_note_update(self, arguments: dict) -> List[types.TextContent]:
        """Update fields of an existing mistake note (delegates to handler)."""
        from .server.handlers import mistake_notes as mistake_handlers
        return await mistake_handlers.handle_mistake_note_update(self, arguments)

    async def handle_mistake_note_delete(self, arguments: dict) -> List[types.TextContent]:
        """Delete a mistake note by content hash (delegates to handler)."""
        from .server.handlers import mistake_notes as mistake_handlers
        return await mistake_handlers.handle_mistake_note_delete(self, arguments)

        """Delete a mistake note by content hash."""
        await self._ensure_storage_initialized()
        result = await self.memory_service.mistake_note_delete(
            content_hash=arguments.get("content_hash", ""),
        )
        return [types.TextContent(type="text", text=json.dumps(result, indent=2, default=str))]
    # ─── Session Legacy & Bootstrap Profile Handlers ──────────────

    async def handle_commit_session_legacy(self, arguments: dict) -> List[types.TextContent]:
        """Record end-of-session learnings as structured observations."""
        await self._ensure_storage_initialized()

        session_id = arguments.get("session_id")
        agent_id = arguments.get("agent_id")
        task_summary = arguments.get("task_summary")
        outcome = arguments.get("outcome")

        if not all([session_id, agent_id, task_summary, outcome]):
            return [types.TextContent(type="text", text=json.dumps({"status": "error", "message": "Missing required fields: session_id, agent_id, task_summary, outcome"}))]

        observations_created = 0
        mistake_notes_updated = 0

        try:
            # Store full legacy as observation
            legacy_content = f"Session: {session_id} | Agent: {agent_id} | Task: {task_summary} | Outcome: {outcome}"
            await self.memory_service.store_memory(
                content=legacy_content,
                tags="session-legacy",
                memory_type="observation",
                metadata={
                    "observation_type": "session_legacy",
                    "session_id": session_id,
                    "agent_id": agent_id,
                    "source": "observation",
                    "outcome": outcome,
                },
            )
            observations_created += 1

            # Process errors → mistake_note_add
            for err in arguments.get("errors", []):
                await self.memory_service.mistake_note_add(
                    error_pattern=err.get("error", ""),
                    context_signature=err.get("tool", ""),
                    incorrect_action=err.get("error", ""),
                    correct_action=err.get("resolution", ""),
                )
                mistake_notes_updated += 1

            # Process user_corrections → separate observations
            for corr in arguments.get("user_corrections", []):
                content = f"User corrected: {corr.get('original', '')} → {corr.get('corrected_to', '')}"
                await self.memory_service.store_memory(
                    content=content,
                    tags="user-correction,high-priority",
                    memory_type="observation",
                    metadata={
                        "observation_type": "user_correction",
                        "session_id": session_id,
                        "agent_id": agent_id,
                        "source": "observation",
                    },
                )
                observations_created += 1

            # Process decisions → separate observations
            for dec in arguments.get("decisions", []):
                content = f"Decision: {dec.get('what', '')} — Reason: {dec.get('why', '')}"
                await self.memory_service.store_memory(
                    content=content,
                    tags="decision",
                    memory_type="observation",
                    metadata={
                        "observation_type": "decision",
                        "session_id": session_id,
                        "agent_id": agent_id,
                        "source": "observation",
                    },
                )
                observations_created += 1

            # Increment session counter for fresh-start sentinel
            await self._increment_session_counter(agent_id)

            # Server-side autolearn: trigger learning pipeline in background
            task = asyncio.create_task(
                self._post_commit_learning(session_id, agent_id)
            )
            self._background_tasks.add(task)
            task.add_done_callback(self._background_tasks.discard)

            return [types.TextContent(type="text", text=json.dumps({
                "status": "recorded",
                "observations_created": observations_created,
                "mistake_notes_updated": mistake_notes_updated,
            }))]

        except Exception as e:
            logger.error(f"Error in commit_session_legacy: {e}")
            return [types.TextContent(type="text", text=json.dumps({"status": "error", "message": str(e)}))]

    async def _post_commit_learning(self, session_id: str, agent_id: str):
        """Background: distill undistilled memories if threshold reached."""
        try:
            # Count undistilled memories
            undistilled = await self.memory_service.list_memories(
                page=1, page_size=1, memory_type="observation"
            )
            total = undistilled.get("total", 0)
            # Simple threshold: if many observations exist, run distill
            if total >= 10:
                await self.handle_memory_distill({"batch_size": 20, "dry_run": False})
                logger.info(f"Post-commit learning: distill completed for session {session_id}")
        except Exception as e:
            logger.warning(f"Post-commit learning failed (non-fatal): {e}")

    async def _scheduled_distill_check(self):
        """Periodic (6h): run distill if undistilled memories exceed threshold."""
        try:
            await self._ensure_storage_initialized()
            # Only run if there are enough undistilled candidates
            candidates = await self.memory_service.list_memories(
                page=1, page_size=1, memory_type="observation"
            )
            total = candidates.get("total", 0)
            if total < 20:
                return  # Not enough candidates to justify LLM call
            await self.handle_memory_distill({"batch_size": 20, "dry_run": False})
            logger.info("Scheduled distill_check completed")
        except Exception as e:
            logger.warning(f"Scheduled distill_check failed (non-fatal): {e}")

    # --- §3: Contradiction search (scheduled alongside distill) ---

    async def _scheduled_contradiction_check(self):
        """Periodic: check for unresolved memory conflicts and log warnings."""
        try:
            await self._ensure_storage_initialized()
            result = await self.handle_memory_conflicts({})
            if result and hasattr(result[0], 'text'):
                import json as _json
                data = _json.loads(result[0].text)
                conflicts = data.get("conflicts", [])
                unresolved = [c for c in conflicts if c.get("status") != "resolved"]
                if unresolved:
                    logger.warning(
                        f"Contradiction check: {len(unresolved)} unresolved conflict(s)"
                    )
        except Exception as e:
            logger.warning(f"Scheduled contradiction_check failed (non-fatal): {e}")

    # --- §3: Threshold trigger for consolidation ---

    _consolidation_counter: int = 0
    _last_consolidation_at: float = 0
    _consolidation_threshold: int = int(os.environ.get("MCP_CONSOLIDATION_THRESHOLD", "50"))
    _consolidation_min_interval: int = int(os.environ.get("MCP_CONSOLIDATION_MIN_INTERVAL", "86400"))

    async def _check_consolidation_threshold(self):
        """Check if consolidation should be triggered based on store count."""
        if (self._consolidation_counter >= self._consolidation_threshold
                and (time.time() - self._last_consolidation_at) > self._consolidation_min_interval):
            self._consolidation_counter = 0
            task = asyncio.create_task(self._background_consolidation())
            self._background_tasks.add(task)
            task.add_done_callback(self._background_tasks.discard)

    async def _background_consolidation(self):
        """Background: run incremental consolidation."""
        try:
            await self._ensure_storage_initialized()
            await self.handle_memory_consolidate({"time_horizon": "incremental"})
            self._last_consolidation_at = time.time()
            logger.info("Background consolidation (threshold-triggered) completed")
        except Exception as e:
            logger.warning(f"Background consolidation failed (non-fatal): {e}")

    # --- §7: Resource URI helpers ---

    @staticmethod
    def _get_bootstrap_resource_uri(agent_id: str) -> str:
        """Return the MCP resource URI for an agent's bootstrap profile."""
        return f"memory://agent/{agent_id}/bootstrap"

    async def _read_bootstrap_resource(self, agent_id: str) -> str:
        """Read bootstrap profile as resource content."""
        result = await self.handle_get_bootstrap_profile({"agent_ids": [agent_id]})
        if result and hasattr(result[0], 'text'):
            return result[0].text
        return ""

    # --- §4/§5: Session counter + Bootstrap profile ---

    async def _increment_session_counter(self, agent_id: str):
        """Increment session counter for fresh-start sentinel tracking."""
        counter_key = f"__session_counter_{agent_id}"
        try:
            existing = await self.memory_service.retrieve_memories(
                query=counter_key,
                n_results=1,
                memory_type="observation",
            )
            if existing.get("memories"):
                for mem in existing["memories"]:
                    meta = mem.get("metadata") or {}
                    if isinstance(meta, str):
                        meta = json.loads(meta) if meta else {}
                    if meta.get("counter_key") == counter_key:
                        meta["session_count"] = meta.get("session_count", 0) + 1
                        await self.storage.update_memory_metadata(
                            content_hash=mem["content_hash"],
                            updates={"metadata": meta},
                            preserve_timestamps=False,
                        )
                        return

            # Create new counter
            await self.memory_service.store_memory(
                content=counter_key,
                tags="session-counter,internal",
                memory_type="observation",
                metadata={
                    "counter_key": counter_key,
                    "session_count": 1,
                    "agent_id": agent_id,
                    "observation_type": "session_legacy",
                    "source": "observation",
                },
            )
        except Exception as e:
            logger.debug(f"Failed to increment session counter: {e}")

    async def _get_session_count(self, agent_id: str) -> int:
        """Get current session count for an agent."""
        counter_key = f"__session_counter_{agent_id}"
        try:
            existing = await self.memory_service.retrieve_memories(
                query=counter_key,
                n_results=3,
                memory_type="observation",
            )
            if existing.get("memories"):
                for mem in existing["memories"]:
                    meta = mem.get("metadata") or {}
                    if isinstance(meta, str):
                        meta = json.loads(meta) if meta else {}
                    if meta.get("counter_key") == counter_key:
                        return meta.get("session_count", 0)
        except Exception:
            pass
        return 0

    async def _reset_session_counter(self, agent_id: str):
        """Reset session counter after fresh-start trigger."""
        counter_key = f"__session_counter_{agent_id}"
        try:
            existing = await self.memory_service.retrieve_memories(
                query=counter_key,
                n_results=3,
                memory_type="observation",
            )
            if existing.get("memories"):
                for mem in existing["memories"]:
                    meta = mem.get("metadata") or {}
                    if isinstance(meta, str):
                        meta = json.loads(meta) if meta else {}
                    if meta.get("counter_key") == counter_key:
                        meta["session_count"] = 0
                        await self.storage.update_memory_metadata(
                            content_hash=mem["content_hash"],
                            updates={"metadata": meta},
                            preserve_timestamps=False,
                        )
                        return
        except Exception:
            pass

    async def handle_get_bootstrap_profile(self, arguments: dict) -> List[types.TextContent]:
        """Generate a behavioral bootstrap profile for ephemeral agents."""
        await self._ensure_storage_initialized()

        # Opt-in: disabled by default to avoid token budget issues on tight clients
        enabled = os.getenv("MCP_BOOTSTRAP_ENABLED", "false").lower() in ("true", "1", "yes")
        if not enabled:
            return [types.TextContent(type="text", text="=== BEHAVIORAL PROFILE (v1) ===\n\nBootstrap disabled. Set MCP_BOOTSTRAP_ENABLED=true to enable.\n=== END PROFILE ===")]

        agent_ids = arguments.get("agent_ids", [])
        max_tokens = arguments.get("max_tokens", int(os.getenv("MCP_BOOTSTRAP_MAX_TOKENS", "2048")))
        fresh_start_interval = int(os.getenv("MCP_BOOTSTRAP_FRESH_START_INTERVAL", "10"))

        avoidances = []
        preferences = []
        conventions = []
        fresh_start_recommended = False

        try:
            # Check fresh-start sentinel for each agent
            for agent_id in agent_ids:
                count = await self._get_session_count(agent_id)
                if count >= fresh_start_interval:
                    fresh_start_recommended = True
                    await self._reset_session_counter(agent_id)

            # Query avoid-rule mistake notes
            all_mistakes = await self.memory_service.list_memories(
                page=1, page_size=50, memory_type="mistake"
            )
            for mem in all_mistakes.get("memories", []):
                meta = mem.get("metadata") or {}
                if isinstance(meta, str):
                    meta = json.loads(meta) if meta else {}
                if agent_ids and meta.get("agent_id") and meta.get("agent_id") not in agent_ids:
                    continue
                if meta.get("is_avoid_rule") or meta.get("frustration_score", 0) >= 3.0 or meta.get("confidence", 0) > 0.7:
                    content = mem.get("content", "")
                    conf = meta.get("confidence", 0.5)
                    count = meta.get("failure_count", 1)
                    avoidances.append(f"- ⚠️ {content} [confidence: {conf:.2f}, errors: {count}]")

            # Query user_correction and decision observations
            corrections = await self.memory_service.list_memories(
                page=1, page_size=50, memory_type="observation"
            )
            for mem in corrections.get("memories", []):
                meta = mem.get("metadata") or {}
                if isinstance(meta, str):
                    meta = json.loads(meta) if meta else {}
                obs_type = meta.get("observation_type")
                if obs_type == "user_correction":
                    if not agent_ids or meta.get("agent_id") in agent_ids:
                        preferences.append(f"- {mem.get('content', '')}")
                elif obs_type == "decision":
                    if not agent_ids or meta.get("agent_id") in agent_ids:
                        conventions.append(f"- {mem.get('content', '')}")

            # Query harvest-produced memories
            harvest_types = {"convention": conventions, "bug": avoidances, "decision": conventions, "learning": preferences}
            for htype, target_list in harvest_types.items():
                for _htag in ["session-harvest", "memory-distill"]:
                    harvest_mems = await self.memory_service.list_memories(
                        page=1, page_size=20, memory_type=htype, tags=[_htag],
                    )
                    for mem in harvest_mems.get("memories", []):
                        content = mem.get("content", "")
                        if content and len(content) > 20:
                            meta = mem.get("metadata") or {}
                            if isinstance(meta, str):
                                meta = json.loads(meta) if meta else {}
                            conf = meta.get("confidence", 0.75)
                            prefix = "⚠️ " if htype == "bug" else ""
                            entry = f"- {prefix}{content} [confidence: {conf:.2f}]"
                            if entry not in target_list:
                                target_list.append(entry)

            # Deduplicate and rank
            from mcp_memory_service.harvest.bootstrap_utils import deduplicate_entries, rank_entries

            def _dedup_and_rank(entries: list) -> list:
                parsed = []
                for e in entries:
                    conf = 0.75
                    if "confidence:" in e:
                        try:
                            conf = float(e.split("confidence:")[1].split("]")[0].strip().rstrip(","))
                        except (ValueError, IndexError):
                            pass
                    parsed.append({"content": e, "confidence": conf, "quality_score": conf, "created_at": time.time()})
                deduped = deduplicate_entries(parsed, similarity_threshold=0.70)
                ranked = rank_entries(deduped)
                return [r["content"] for r in ranked]

            avoidances = _dedup_and_rank(avoidances)
            preferences = _dedup_and_rank(preferences)
            conventions = _dedup_and_rank(conventions)

            # Build profile using formatter plugin
            from .bootstrap.formatter import get_formatter_for_agent
            agent_id_for_format = agent_ids[0] if agent_ids else "claude-code"
            formatter = get_formatter_for_agent(agent_id_for_format)
            meta = {"fresh_start": fresh_start_recommended}
            profile = formatter.format(avoidances, preferences, conventions, meta)

            # Truncate to token budget (rough: 1 token ≈ 4 chars)
            max_chars = max_tokens * 4
            if len(profile) > max_chars:
                profile = profile[:max_chars] + "\n... (truncated to token budget)"

            return [types.TextContent(type="text", text=profile)]

        except Exception as e:
            logger.error(f"Error in get_bootstrap_profile: {e}")
            return [types.TextContent(type="text", text="=== BEHAVIORAL PROFILE (v1) ===\n\nNo data available yet.\n=== END PROFILE ===")]

    # ============================================================
    # Test Compatibility Wrapper Methods
    # ============================================================
    # These methods provide a simplified API for testing,
    # wrapping the underlying MemoryService and Storage calls.

    async def store_memory(
        self,
        content: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Store a new memory (test-compatible wrapper).

        Args:
            content: The memory content to store
            metadata: Optional metadata dict with tags, type, etc.

        Returns:
            Dictionary with operation result including success, memory/memories, and hash
        """
        await self._ensure_storage_initialized()

        # Extract metadata fields
        metadata = metadata or {}
        tags = metadata.get("tags", [])
        memory_type = metadata.get("type", "note")

        # Call MemoryService
        result = await self.memory_service.store_memory(
            content=content,
            tags=tags,
            memory_type=memory_type,
            metadata=metadata
        )

        # Add a 'hash' field for test compatibility
        if result.get("success"):
            if "memory" in result:
                # Single memory - add hash shortcut
                result["hash"] = result["memory"]["content_hash"]
            elif "memories" in result and len(result["memories"]) > 0:
                # Chunked - use first chunk's hash
                result["hash"] = result["memories"][0]["content_hash"]

        return result

    async def retrieve_memory(
        self,
        query: str,
        n_results: int = 5
    ) -> List[str]:
        """
        Retrieve memories using semantic search (test-compatible wrapper).

        Args:
            query: Search query
            n_results: Number of results to return

        Returns:
            List of memory content strings
        """
        await self._ensure_storage_initialized()

        result = await self.memory_service.retrieve_memories(
            query=query,
            n_results=n_results
        )

        # Extract just the content from each memory for test compatibility
        memories = result.get("memories", [])
        return [m["content"] for m in memories]

    async def search_by_tag(
        self,
        tags: List[str]
    ) -> List[str]:
        """
        Search memories by tags (test-compatible wrapper).

        Args:
            tags: List of tags to search for

        Returns:
            List of memory content strings
        """
        await self._ensure_storage_initialized()

        # Call storage directly (search_by_tags is not in MemoryService)
        memories = await self.storage.search_by_tags(
            tags=tags,
            operation="OR"  # Match ANY tag (more permissive for tests)
        )

        return [m.content for m in memories]

    async def delete_memory(
        self,
        content_hash: str
    ) -> Dict[str, Any]:
        """
        Delete a memory by its content hash (test-compatible wrapper).

        Args:
            content_hash: The content hash of the memory to delete

        Returns:
            Dictionary with success status
        """
        await self._ensure_storage_initialized()

        result = await self.memory_service.delete_memory(content_hash=content_hash)
        return result

    async def check_database_health(self) -> Dict[str, Any]:
        """
        Check database health and get statistics (test-compatible wrapper).

        Returns:
            Dictionary with health status and statistics
        """
        await self._ensure_storage_initialized()

        # Get stats from storage
        stats = await self.storage.get_stats()

        return {
            "status": "healthy",
            "memory_count": stats.get("total_memories", 0),
            "database_size": stats.get("database_size_bytes", 0),
            "storage_type": stats.get("storage_backend", "unknown"),
            **stats  # Include all other stats
        }

    async def create_backup(self, description: str = None) -> Dict[str, Any]:
        """
        Create a database backup (test-compatible wrapper).

        Args:
            description: Optional description for the backup

        Returns:
            Dictionary with success status and backup path
        """
        await self._ensure_storage_initialized()

        # Use backup scheduler if available
        if hasattr(self, 'backup_scheduler') and self.backup_scheduler:
            result = await self.backup_scheduler.create_backup(description)
            # Normalize response for test compatibility
            if result.get('success'):
                return {
                    "success": True,
                    "backup_path": result.get('path')
                }
            return result

        # Fallback: Create backup directly if no scheduler
        from pathlib import Path
        import sqlite3
        from datetime import datetime, timezone
        import tempfile

        try:
            # Get database path from storage
            db_path = None
            if hasattr(self.storage, 'db_path'):
                db_path = self.storage.db_path
            elif hasattr(self.storage, 'sqlite_storage') and hasattr(self.storage.sqlite_storage, 'db_path'):
                db_path = self.storage.sqlite_storage.db_path

            # Handle in-memory databases (for tests)
            if not db_path or db_path == ':memory:':
                # Create temp backup for in-memory databases
                timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
                backup_filename = f"memory_backup_{timestamp}.db"
                temp_dir = Path(tempfile.gettempdir()) / "mcp_test_backups"
                temp_dir.mkdir(exist_ok=True)
                backup_path = temp_dir / backup_filename

                # For in-memory, we can't really backup, so just create empty file
                backup_path.touch()

                return {
                    "success": True,
                    "backup_path": str(backup_path)
                }

            if not Path(db_path).exists():
                return {
                    "success": False,
                    "error": f"Database file not found: {db_path}"
                }

            # Create backups directory
            backups_dir = Path(db_path).parent / "backups"
            backups_dir.mkdir(exist_ok=True)

            # Generate backup filename
            timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
            backup_filename = f"memory_backup_{timestamp}.db"
            backup_path = backups_dir / backup_filename

            # Create backup using SQLite's native backup API
            def _do_backup():
                source = sqlite3.connect(str(db_path))
                dest = sqlite3.connect(str(backup_path))
                try:
                    source.backup(dest)
                finally:
                    source.close()
                    dest.close()

            await asyncio.to_thread(_do_backup)

            return {
                "success": True,
                "backup_path": str(backup_path)
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    async def optimize_db(self) -> Dict[str, Any]:
        """
        Optimize database by running VACUUM and rebuilding indexes (test-compatible wrapper).

        Returns:
            Dictionary with success status and optimized size
        """
        await self._ensure_storage_initialized()

        try:
            # Get database path
            db_path = None
            if hasattr(self.storage, 'db_path'):
                db_path = self.storage.db_path
            elif hasattr(self.storage, 'sqlite_storage') and hasattr(self.storage.sqlite_storage, 'db_path'):
                db_path = self.storage.sqlite_storage.db_path

            # Handle in-memory databases (for tests)
            if not db_path or db_path == ':memory:':
                return {
                    "success": True,
                    "optimized_size": 0,
                    "size_before": 0,
                    "size_saved": 0
                }

            from pathlib import Path
            import sqlite3

            if not Path(db_path).exists():
                return {
                    "success": False,
                    "error": f"Database file not found: {db_path}"
                }

            # Get size before optimization
            size_before = Path(db_path).stat().st_size

            # Run VACUUM to optimize database
            def _do_optimize():
                conn = sqlite3.connect(str(db_path))
                try:
                    conn.execute("VACUUM")
                    conn.execute("ANALYZE")
                    conn.commit()
                finally:
                    conn.close()

            await asyncio.to_thread(_do_optimize)

            # Get size after optimization
            size_after = Path(db_path).stat().st_size

            return {
                "success": True,
                "optimized_size": size_after,
                "size_before": size_before,
                "size_saved": size_before - size_after
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    async def cleanup_duplicates(self) -> Dict[str, Any]:
        """
        Remove duplicate memories (test-compatible wrapper).

        Returns:
            Dictionary with success status and duplicates removed count
        """
        await self._ensure_storage_initialized()

        try:
            # Call storage's cleanup_duplicates method
            count_removed, message = await self.storage.cleanup_duplicates()

            return {
                "success": True,
                "duplicates_removed": count_removed,
                "message": message
            }

        except Exception as e:
            return {
                "success": False,
                "duplicates_removed": 0,
                "error": str(e)
            }

    async def exact_match_retrieve(self, content: str) -> List[str]:
        """
        Retrieve memories using exact content match (test-compatible wrapper).

        Args:
            content: Exact content to match

        Returns:
            List of memory content strings that exactly match
        """
        await self._ensure_storage_initialized()

        try:
            # Use semantic search with the exact content as query
            # This will find the most similar items (which should include exact matches)
            results = await self.storage.retrieve(content, n_results=50)

            # Filter for exact matches only
            exact_matches = []
            for result in results:
                if result.memory.content == content:
                    exact_matches.append(result.memory.content)

            return exact_matches
        except Exception as e:
            # Return empty list on error
            return []

    async def debug_retrieve(
        self,
        query: str,
        n_results: int = 5,
        similarity_threshold: float = 0.0
    ) -> List[str]:
        """
        Retrieve memories with debug information (test-compatible wrapper).

        Args:
            query: Search query
            n_results: Number of results to return
            similarity_threshold: Minimum similarity threshold

        Returns:
            List of memory content strings
        """
        await self._ensure_storage_initialized()

        try:
            from .utils.debug import debug_retrieve_memory
            results = await debug_retrieve_memory(
                self.storage,
                query=query,
                n_results=n_results,
                similarity_threshold=similarity_threshold
            )
            return [result.memory.content for result in results]
        except Exception as e:
            # Return empty list on error
            return []

    async def shutdown(self) -> None:
        """
        Shutdown the server and cleanup resources.

        This method properly cleans up all caches and resources to free memory.
        Called during graceful shutdown (SIGTERM/SIGINT) or process exit.

        Cleanup includes:
        - Service and storage caches (cache_manager)
        - Embedding model caches (sqlite_vec)
        - Garbage collection to reclaim memory
        """
        import gc
        from .server.cache_manager import clear_all_caches
        from .storage.sqlite_vec import clear_model_caches

        logger.info("Initiating graceful shutdown...")

        try:
            # Clear service and storage caches
            cache_stats = clear_all_caches()
            logger.info(f"Cleared service caches: {cache_stats}")

            # Clear model caches (embedding models)
            model_stats = clear_model_caches()
            logger.info(f"Cleared model caches: {model_stats}")

            # Force garbage collection to reclaim memory
            gc_collected = gc.collect()
            logger.info(f"Garbage collection: {gc_collected} objects collected")

            logger.info("Graceful shutdown complete")
        except Exception as e:
            logger.warning(f"Error during shutdown cleanup: {e}")


def _print_system_diagnostics(system_info: Any) -> None:
    """Print system diagnostics for LM Studio."""
    print("\n=== MCP Memory Service System Diagnostics ===", file=sys.stdout, flush=True)
    print(f"OS: {system_info.os_name} {system_info.architecture}", file=sys.stdout, flush=True)
    print(f"Python: {platform.python_version()}", file=sys.stdout, flush=True)
    print(f"Hardware Acceleration: {system_info.accelerator}", file=sys.stdout, flush=True)
    print(f"Memory: {system_info.memory_gb:.2f} GB", file=sys.stdout, flush=True)
    print(f"Optimal Model: {system_info.get_optimal_model()}", file=sys.stdout, flush=True)
    print(f"Optimal Batch Size: {system_info.get_optimal_batch_size()}", file=sys.stdout, flush=True)
    print(f"Storage Backend: {STORAGE_BACKEND}", file=sys.stdout, flush=True)
    print("================================================\n", file=sys.stdout, flush=True)


async def async_main():
    """Main async entry point for MCP Memory Service."""
    from .utils.startup_orchestrator import (
        StartupCheckOrchestrator,
        InitializationRetryManager,
        ServerRunManager
    )

    # Run all startup checks
    StartupCheckOrchestrator.run_all_checks()

    # Print system diagnostics only for LM Studio
    system_info = get_system_info()
    if MCP_CLIENT == 'lm_studio':
        _print_system_diagnostics(system_info)

    logger.info(f"Starting MCP Memory Service with storage backend: {STORAGE_BACKEND}")

    try:
        # Create server instance
        memory_server = MemoryServer()

        # Initialize with retry logic
        retry_manager = InitializationRetryManager(max_retries=2, timeout=30.0, retry_delay=2.0)
        await retry_manager.initialize_with_retry(memory_server)

        # Run server based on mode
        run_manager = ServerRunManager(memory_server, system_info)

        if ServerRunManager.is_streamable_http_mode():
            await run_manager.run_streamable_http()
        elif ServerRunManager.is_sse_mode():
            await run_manager.run_sse()
        elif ServerRunManager.is_standalone_mode():
            await run_manager.run_standalone()
        else:
            await run_manager.run_stdio()

    except Exception as e:
        logger.error(f"Server error: {str(e)}")
        logger.error(traceback.format_exc())
        print(f"Fatal server error: {str(e)}", file=sys.stderr, flush=True)
        raise

def _cleanup_on_shutdown():
    """
    Cleanup function called on process shutdown (SIGTERM, SIGINT, KeyboardInterrupt).

    This function clears all caches to free memory and runs garbage collection.
    It's designed to be called from signal handlers (synchronous context).
    """
    import gc
    from .server.cache_manager import clear_all_caches
    from .storage.sqlite_vec import clear_model_caches

    try:
        logger.info("Running shutdown cleanup...")

        # Clear service and storage caches
        cache_stats = clear_all_caches()
        logger.info(f"Cleared service caches: {cache_stats}")

        # Clear model caches (embedding models)
        model_stats = clear_model_caches()
        logger.info(f"Cleared model caches: {model_stats}")

        # Force garbage collection
        gc_collected = gc.collect()
        logger.info(f"Garbage collection: {gc_collected} objects collected")

        logger.info("Shutdown cleanup complete")
    except Exception as e:
        logger.warning(f"Error during shutdown cleanup: {e}")


def main():
    import signal
    import atexit
    from mcp_memory_service.config import validate_config

    # Log any configuration issues at startup for visibility
    config_issues = validate_config()
    if config_issues:
        for issue in config_issues:
            logger.warning("Configuration issue: %s", issue)

    # Register cleanup function for normal exit
    atexit.register(_cleanup_on_shutdown)

    # Set up signal handlers for graceful shutdown
    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum}, shutting down gracefully...")
        _cleanup_on_shutdown()
        # Use os._exit(0) instead of sys.exit(0) to avoid buffered I/O lock issues
        # during shutdown. os._exit() bypasses Python's cleanup which is safe here
        # because _cleanup_on_shutdown() has already performed necessary cleanup.
        # See: https://github.com/doobidoo/mcp-memory-service/issues/368
        os._exit(0)

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    try:
        # Check if running in Docker
        if os.path.exists('/.dockerenv') or os.environ.get('DOCKER_CONTAINER', False):
            logger.info("Running in Docker container")
            if MCP_CLIENT == 'lm_studio':
                print("MCP Memory Service starting in Docker mode", file=sys.stdout, flush=True)

        asyncio.run(async_main())
    except KeyboardInterrupt:
        logger.info("Shutting down gracefully (KeyboardInterrupt)...")
        _cleanup_on_shutdown()
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}\n{traceback.format_exc()}")
        sys.exit(1)

if __name__ == "__main__":
    main()
