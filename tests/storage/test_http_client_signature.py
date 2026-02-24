"""Tests for HTTPClientStorage method signatures matching base class."""
import inspect
import pytest
from mcp_memory_service.storage.http_client import HTTPClientStorage
from mcp_memory_service.storage.base import MemoryStorage


def test_retrieve_signature_matches_base_class():
    """HTTPClientStorage.retrieve must have same signature as MemoryStorage.retrieve."""
    base_sig = inspect.signature(MemoryStorage.retrieve)
    client_sig = inspect.signature(HTTPClientStorage.retrieve)

    base_params = dict(base_sig.parameters)
    client_params = dict(client_sig.parameters)

    # Both must have 'tags' parameter
    assert "tags" in client_params, (
        f"HTTPClientStorage.retrieve is missing 'tags' parameter. "
        f"Base class params: {list(base_params.keys())}, "
        f"Client params: {list(client_params.keys())}"
    )

    # 'tags' must be optional with default None
    assert client_params["tags"].default is None
