"""Tests for harvest LLM rewriter — converts conversational text to standalone insights."""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from mcp_memory_service.harvest.rewriter import HarvestRewriter, RewriteResult


@pytest.fixture
def rewriter():
    """Rewriter with mocked LLM client."""
    return HarvestRewriter()


class TestRewriterOutput:
    """Rewriter should produce standalone insights from conversational text."""

    @pytest.mark.asyncio
    async def test_rewrite_produces_standalone_insight(self, rewriter):
        """LLM rewriter converts conversational text to standalone insight."""
        input_text = (
            "Boa pergunta. O problema era que o handler com asyncio.to_thread "
            "bloqueava o event loop. A solução foi usar asyncio.create_task."
        )
        with patch.object(rewriter, '_call_llm', new_callable=AsyncMock) as mock_llm:
            mock_llm.return_value = "bug: asyncio.to_thread inside an async handler still blocks the event loop. Fix: use asyncio.create_task for background work."
            result = await rewriter.rewrite(input_text, suggested_type="bug")

        assert result is not None
        assert isinstance(result, RewriteResult)
        assert "asyncio" in result.content
        assert "Boa pergunta" not in result.content
        assert len(result.content) < 200

    @pytest.mark.asyncio
    async def test_rewrite_returns_none_for_skip(self, rewriter):
        """LLM rewriter returns None when content has no clear insight."""
        input_text = "sim, pode fazer. Vamos em frente com isso."
        with patch.object(rewriter, '_call_llm', new_callable=AsyncMock) as mock_llm:
            mock_llm.return_value = "SKIP"
            result = await rewriter.rewrite(input_text, suggested_type="context")

        assert result is None

    @pytest.mark.asyncio
    async def test_rewrite_preserves_suggested_type(self, rewriter):
        """Rewriter uses the type from LLM response, falling back to suggested_type."""
        input_text = "decidimos usar RRF em vez de weighted average porque tem melhor recall."
        with patch.object(rewriter, '_call_llm', new_callable=AsyncMock) as mock_llm:
            mock_llm.return_value = "decision: Use RRF instead of weighted average for hybrid search — better recall in practice."
            result = await rewriter.rewrite(input_text, suggested_type="decision")

        assert result is not None
        assert result.memory_type == "decision"

    @pytest.mark.asyncio
    async def test_rewrite_handles_llm_failure_gracefully(self, rewriter):
        """If LLM fails, rewriter returns None (don't store garbage)."""
        input_text = "The root cause was a missing index."
        with patch.object(rewriter, '_call_llm', new_callable=AsyncMock) as mock_llm:
            mock_llm.side_effect = Exception("Groq rate limit exceeded")
            result = await rewriter.rewrite(input_text, suggested_type="bug")

        assert result is None

    @pytest.mark.asyncio
    async def test_rewrite_strips_markdown_and_filler(self, rewriter):
        """Rewriter output should not contain markdown formatting or conversational filler."""
        input_text = "## Debug\n\n**Resultado:** O bug era no parser de JSON que não tratava arrays vazios."
        with patch.object(rewriter, '_call_llm', new_callable=AsyncMock) as mock_llm:
            mock_llm.return_value = "bug: JSON parser crashes on empty arrays — needs null check before iteration."
            result = await rewriter.rewrite(input_text, suggested_type="bug")

        assert result is not None
        assert "##" not in result.content
        assert "**" not in result.content


class TestRewriterPrompt:
    """Verify the prompt construction is correct."""

    @pytest.mark.asyncio
    async def test_prompt_includes_input_text(self, rewriter):
        """The LLM prompt should include the input text."""
        input_text = "We decided to use PostgreSQL over MySQL."
        with patch.object(rewriter, '_call_llm', new_callable=AsyncMock) as mock_llm:
            mock_llm.return_value = "decision: Use PostgreSQL over MySQL."
            await rewriter.rewrite(input_text, suggested_type="decision")

        call_args = mock_llm.call_args[0][0]  # First positional arg = prompt
        assert "PostgreSQL" in call_args

    @pytest.mark.asyncio
    async def test_prompt_includes_type_hint(self, rewriter):
        """The LLM prompt should include the suggested type as context."""
        input_text = "The fix was adding a retry with exponential backoff."
        with patch.object(rewriter, '_call_llm', new_callable=AsyncMock) as mock_llm:
            mock_llm.return_value = "bug: Fix connection failures with retry + exponential backoff."
            await rewriter.rewrite(input_text, suggested_type="bug")

        call_args = mock_llm.call_args[0][0]
        assert "bug" in call_args.lower()


class TestRewriterParsing:
    """Test parsing of LLM response format."""

    def test_parse_typed_response(self, rewriter):
        """Parse 'TYPE: content' format correctly."""
        result = rewriter._parse_response("decision: Use RRF for hybrid search.", "decision")
        assert result is not None
        assert result.memory_type == "decision"
        assert result.content == "Use RRF for hybrid search."

    def test_parse_skip_response(self, rewriter):
        """Parse SKIP response."""
        result = rewriter._parse_response("SKIP", "bug")
        assert result is None

    def test_parse_skip_case_insensitive(self, rewriter):
        """SKIP detection is case-insensitive."""
        result = rewriter._parse_response("skip", "bug")
        assert result is None

    def test_parse_untyped_response_uses_suggested(self, rewriter):
        """If LLM doesn't include type prefix, use suggested_type."""
        result = rewriter._parse_response("Always use WAL mode for SQLite.", "convention")
        assert result is not None
        assert result.memory_type == "convention"
        assert result.content == "Always use WAL mode for SQLite."

    def test_parse_empty_response_returns_none(self, rewriter):
        """Empty LLM response returns None."""
        result = rewriter._parse_response("", "bug")
        assert result is None


class TestRewriterConfiguration:
    """Issue #178: a configured provider chain must count as configured.

    `_call_llm` prefers `HARVEST_LLM_PROVIDERS` and only falls back to Groq,
    but the harvester decided whether a rewriter existed at all by looking at
    `GROQ_API_KEY`. Deployments pointing at an OpenAI-compatible endpoint got
    no rewriting and no error.
    """

    def test_provider_chain_counts_as_configured(self, monkeypatch):
        monkeypatch.delenv('GROQ_API_KEY', raising=False)
        monkeypatch.setenv('HARVEST_LLM_PROVIDERS', 'litellm')
        monkeypatch.setenv('HARVEST_LLM_LITELLM_BASE_URL', 'http://litellm.svc:4000/v1')
        monkeypatch.setenv('HARVEST_LLM_LITELLM_MODEL', 'ollama/qwen2.5:7b-instruct')

        assert HarvestRewriter().is_configured is True

    def test_groq_key_alone_still_counts_as_configured(self, monkeypatch):
        monkeypatch.delenv('HARVEST_LLM_PROVIDERS', raising=False)
        monkeypatch.setenv('GROQ_API_KEY', 'gsk-test')

        assert HarvestRewriter().is_configured is True

    def test_no_provider_and_no_key_is_unconfigured(self, monkeypatch):
        monkeypatch.delenv('HARVEST_LLM_PROVIDERS', raising=False)
        monkeypatch.delenv('GROQ_API_KEY', raising=False)

        assert HarvestRewriter().is_configured is False

    def test_harvester_keeps_rewriter_when_only_provider_chain_is_set(self, monkeypatch):
        """The gate itself, not just the property."""
        from mcp_memory_service.harvest.harvester import SessionHarvester

        monkeypatch.delenv('GROQ_API_KEY', raising=False)
        monkeypatch.setenv('HARVEST_LLM_PROVIDERS', 'litellm')
        monkeypatch.setenv('HARVEST_LLM_LITELLM_BASE_URL', 'http://litellm.svc:4000/v1')
        monkeypatch.setenv('HARVEST_LLM_LITELLM_MODEL', 'ollama/qwen2.5:7b-instruct')

        harvester = SessionHarvester.__new__(SessionHarvester)
        rewriter = harvester._get_rewriter()

        assert rewriter is not None
        assert rewriter.is_configured is True
