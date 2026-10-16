"""Pytest configuration and shared fixtures."""
import pytest
import asyncio


@pytest.fixture(scope="session")
def event_loop():
    """Create an event loop for the session."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()
