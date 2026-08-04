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

"""Interface-conformance guard for the multi-store `store` parameter (issue #133).

The multi-store partition key (commit 53745ac0, #57 Phase 1) added a `store`
keyword argument to a set of storage methods and to every call site in the
service/handler layer. Python does not check that each backend's override kept
its signature in sync, so the Milvus backend shipped with `count_all_memories`,
`search_memories`, and `store` still on the old signature -> `count_all_memories()
got an unexpected keyword argument 'store'` at runtime (issue #133).

This test is the practical equivalent of the compile-time check the reporter
asked for: it inspects each backend class (no live backend needed) and asserts
that every method in the multi-store contract accepts a `store` keyword, so the
signatures can never silently drift apart again.
"""

import importlib
import inspect

import pytest

from mcp_memory_service.storage.base import MemoryStorage

# Methods that callers invoke with `store=` (service + server/handlers layer).
# Any backend override of these MUST accept a `store` keyword argument.
STORE_CONTRACT_METHODS = [
    "store",
    "get_all_memories",
    "count_all_memories",
    "search_memories",
    "delete_memories",
]

# Backend modules to check. Each must be importable WITHOUT its optional heavy
# deps (pymilvus, etc.) so this guard runs in the ML-free CI image.
BACKEND_MODULES = [
    "mcp_memory_service.storage.sqlite_vec",
    "mcp_memory_service.storage.milvus",
    "mcp_memory_service.storage.cloudflare",
    "mcp_memory_service.storage.hybrid",
]


def _concrete_backend_classes():
    """Yield (class_name, class) for each MemoryStorage subclass defined in a
    backend module. Modules that cannot be imported at all are skipped with a
    marker so the guard still covers every backend that IS importable."""
    found = []
    for mod_name in BACKEND_MODULES:
        try:
            mod = importlib.import_module(mod_name)
        except Exception as exc:  # pragma: no cover - import guard
            found.append((mod_name, None, exc))
            continue
        for name, obj in vars(mod).items():
            if (
                inspect.isclass(obj)
                and issubclass(obj, MemoryStorage)
                and obj is not MemoryStorage
                and obj.__module__ == mod.__name__
            ):
                found.append((f"{name}", obj, None))
    return found


BACKENDS = _concrete_backend_classes()


def test_backend_modules_all_importable():
    """Every backend module imports without its optional heavy deps present."""
    failed = [(m, repr(e)) for (m, cls, e) in BACKENDS if e is not None]
    assert not failed, f"backend module(s) failed to import: {failed}"


@pytest.mark.parametrize("method_name", STORE_CONTRACT_METHODS)
def test_all_backends_accept_store_kwarg(method_name):
    """Each backend override of a multi-store contract method accepts `store`."""
    offenders = []
    for name, cls, err in BACKENDS:
        if cls is None:
            continue
        method = getattr(cls, method_name, None)
        assert method is not None, f"{name} is missing {method_name}()"
        params = inspect.signature(method).parameters
        accepts_store = (
            "store" in params
            or any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values())
        )
        if not accepts_store:
            offenders.append(name)
    assert not offenders, (
        f"{method_name}() is missing the multi-store `store` keyword on: "
        f"{offenders}. Callers pass store=... to this method (issue #133)."
    )


@pytest.mark.parametrize("method_name", STORE_CONTRACT_METHODS)
def test_base_interface_declares_store_kwarg(method_name):
    """The abstract interface must declare `store` too, not just the backends.

    Checking only concrete backends leaves the declaration free to understate the
    contract. That is exactly what had happened: all four backends and all four
    call sites (services/memory_service.py, server/handlers/documents.py,
    utils/document_processing.py) passed and accepted `store` on `store()`, while
    MemoryStorage.store() still stopped at skip_semantic_dedup — so a new backend
    written against the declaration would have reproduced #133 on day one.
    """
    method = getattr(MemoryStorage, method_name, None)
    assert method is not None, f"MemoryStorage is missing {method_name}()"
    params = inspect.signature(method).parameters
    assert "store" in params or any(
        p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values()
    ), (
        f"MemoryStorage.{method_name}() does not declare the multi-store `store` "
        f"keyword, but callers pass it and every backend accepts it (issue #133)."
    )
