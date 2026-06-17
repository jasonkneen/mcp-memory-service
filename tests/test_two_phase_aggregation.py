"""Tests for two-phase aggregation (standalone, no composite scoring)."""
import pytest
from unittest.mock import AsyncMock, MagicMock

from mcp_memory_service.server.handlers.graph import (
    _build_knowledge_map,
    _hydrate_chunks,
    _discover_related_entities,
)


@pytest.fixture
def mock_graph():
    graph = AsyncMock()
    graph.get_entity_profile = AsyncMock(return_value={"entity_types": ["concept"]})
    graph.find_memories_by_entity = AsyncMock(return_value=["hash1", "hash2"])
    graph.common_neighbors = AsyncMock(return_value=[])
    return graph


@pytest.fixture
def mock_storage():
    storage = AsyncMock()

    async def _get_by_hash(h):
        mem = MagicMock()
        mem.content = f"Content for {h}. Second sentence."
        mem.quality_score = 0.8
        return mem

    storage.get_by_hash = _get_by_hash
    return storage


@pytest.fixture
def chunk_pool():
    return [
        {"hash": "hash1", "content": "First chunk content. More text.", "relevance": 0.9},
        {"hash": "hash2", "content": "Second chunk content. Extra.", "relevance": 0.7},
        {"hash": "hash3", "content": "Third chunk content.", "relevance": 0.5},
    ]


# --- _build_knowledge_map tests ---

class TestBuildKnowledgeMap:
    @pytest.mark.asyncio
    async def test_normal_entities(self, mock_graph, chunk_pool):
        entities_raw = [{"entity_name": "python", "count": 5}]
        mock_graph.find_memories_by_entity.return_value = ["hash1", "hash2"]

        result = await _build_knowledge_map(mock_graph, entities_raw, chunk_pool, 2)

        assert len(result) == 1
        ent = result[0]
        assert ent["name"] == "python"
        assert ent["entity_type"] == "concept"
        assert ent["relation_count"] == 5
        assert len(ent["top_chunks"]) == 2
        # Ranked by relevance: hash1 (0.9) first
        assert ent["top_chunks"][0]["hash"] == "hash1"
        assert ent["summary"] != ""

    @pytest.mark.asyncio
    async def test_empty_chunk_pool(self, mock_graph):
        entities_raw = [{"entity_name": "empty", "count": 0}]
        mock_graph.find_memories_by_entity.return_value = []

        result = await _build_knowledge_map(mock_graph, entities_raw, [], 3)

        assert len(result) == 1
        assert result[0]["top_chunks"] == []
        assert result[0]["summary"] == ""

    @pytest.mark.asyncio
    async def test_entity_no_linked_memories_fallback(self, mock_graph, chunk_pool):
        entities_raw = [{"entity_name": "orphan", "count": 1}]
        # Entity has no linked memories in the chunk_pool
        mock_graph.find_memories_by_entity.return_value = ["nonexistent_hash"]

        result = await _build_knowledge_map(mock_graph, entities_raw, chunk_pool, 2)

        # Falls back to full chunk_pool
        assert len(result[0]["top_chunks"]) == 2
        assert result[0]["top_chunks"][0]["hash"] == "hash1"  # highest relevance


# --- _hydrate_chunks tests ---

class TestHydrateChunks:
    @pytest.mark.asyncio
    async def test_normal_hashes(self, mock_storage):
        result = await _hydrate_chunks(mock_storage, ["h1", "h2"])

        assert len(result) == 2
        assert result[0]["hash"] in ("h1", "h2")
        assert "Content for" in result[0]["content"]
        assert result[0]["relevance"] == 0.8

    @pytest.mark.asyncio
    async def test_hash_not_found(self):
        storage = AsyncMock()
        storage.get_by_hash = AsyncMock(return_value=None)

        result = await _hydrate_chunks(storage, ["missing"])

        assert len(result) == 1
        assert result[0]["content"] is None
        assert result[0]["relevance"] is None

    @pytest.mark.asyncio
    async def test_empty_list(self, mock_storage):
        result = await _hydrate_chunks(mock_storage, [])

        assert result == []

    @pytest.mark.asyncio
    async def test_null_content_guard(self):
        storage = AsyncMock()
        mem = MagicMock()
        mem.content = None
        mem.quality_score = 0.5
        storage.get_by_hash = AsyncMock(return_value=mem)

        result = await _hydrate_chunks(storage, ["h1"])

        assert result[0]["content"] == ""

    @pytest.mark.asyncio
    async def test_ranking_by_quality(self):
        storage = AsyncMock()

        async def _get(h):
            m = MagicMock()
            m.content = f"text {h}"
            m.quality_score = {"a": 0.3, "b": 0.9, "c": 0.6}[h]
            return m

        storage.get_by_hash = _get

        result = await _hydrate_chunks(storage, ["a", "b", "c"])

        assert result[0]["hash"] == "b"  # highest quality
        assert result[1]["hash"] == "c"
        assert result[2]["hash"] == "a"


# --- _discover_related_entities tests ---

class TestDiscoverRelatedEntities:
    @pytest.mark.asyncio
    async def test_normal_neighbors(self, mock_graph):
        mock_graph.common_neighbors = AsyncMock(
            side_effect=[
                [("entity_a", 3, 5), ("entity_b", 1, 2)],
                [],  # second hash yields nothing new
            ]
        )

        result = await _discover_related_entities(mock_graph, ["h1", "h2"], max_hops=1)

        assert len(result) == 2
        assert result[0]["shared_count"] == 3
        assert result[1]["shared_count"] == 1

    @pytest.mark.asyncio
    async def test_empty_neighbors(self, mock_graph):
        mock_graph.common_neighbors.return_value = []

        result = await _discover_related_entities(mock_graph, ["h1"], max_hops=1)

        assert result == []

    @pytest.mark.asyncio
    async def test_dedup_same_entity(self, mock_graph):
        # Same candidate hash appears from multiple memory hashes -> merge shared_count
        mock_graph.common_neighbors = AsyncMock(
            side_effect=[
                [("entity_x", 2, 5)],
                [("entity_x", 3, 5)],
            ]
        )

        result = await _discover_related_entities(mock_graph, ["h1", "h2"], max_hops=1)

        assert len(result) == 1
        assert result[0]["shared_count"] == 5  # 2 + 3

    @pytest.mark.asyncio
    async def test_limit_to_10(self, mock_graph):
        # Return more than 10 unique candidates
        neighbors = [(f"ent_{i}", i, 10) for i in range(15)]
        mock_graph.common_neighbors.return_value = neighbors

        result = await _discover_related_entities(mock_graph, ["h1"], max_hops=0)

        assert len(result) == 10
        # Should be sorted by shared_count descending
        assert result[0]["shared_count"] == 14
