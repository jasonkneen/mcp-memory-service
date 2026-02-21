"""Tests for log injection prevention in tag sanitization."""
import pytest
import logging
from mcp_memory_service.services.memory_service import _sanitize_log_value


def test_tag_with_newline_does_not_inject_into_log():
    """Log entries must not contain raw newlines from user input."""
    malicious_tag = "legit-tag\nINJECTED: fake log entry"
    result = _sanitize_log_value(malicious_tag)
    assert "\n" not in result
    assert "INJECTED" in result  # content preserved, but newline removed


def test_tag_with_carriage_return_does_not_inject_into_log():
    """CR characters in tags must be stripped from log output."""
    malicious_tag = "tag\rINJECTED"
    result = _sanitize_log_value(malicious_tag)
    assert "\r" not in result


def test_tag_with_ansi_escape_does_not_inject_into_log():
    """ANSI escape codes in tags must be stripped from log output."""
    malicious_tag = "tag\x1b[31mRED\x1b[0m"
    result = _sanitize_log_value(malicious_tag)
    assert "\x1b" not in result


def test_normal_tag_passes_through_unchanged():
    """Normal tags must not be modified by log sanitization."""
    assert _sanitize_log_value("python-asyncio") == "python-asyncio"
    assert _sanitize_log_value("my-tag-123") == "my-tag-123"
    assert _sanitize_log_value("snake_case_tag") == "snake_case_tag"
