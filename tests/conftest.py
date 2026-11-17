from __future__ import annotations

import pytest

import minbot_selective_proxy.server as server


@pytest.fixture(autouse=True)
def _reset_connection_state():
    """DNS answers and address penalties are process-wide; isolate tests."""
    server._DNS_CACHE.clear()
    server._DNS_CACHE.ttl = 30.0
    server._ADDRESS_PENALTIES.clear()
    yield
    server._DNS_CACHE.clear()
    server._DNS_CACHE.ttl = 30.0
    server._ADDRESS_PENALTIES.clear()
