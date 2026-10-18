import pytest
from fastapi.testclient import TestClient

from app.main import app
from app import state


@pytest.fixture(autouse=True)
def reset_lab_state():
    state.reset_state()
    yield
    state.reset_state()


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client
