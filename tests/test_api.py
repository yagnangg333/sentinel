import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient  # noqa: E402

from sentinel.agent import Agent  # noqa: E402
from sentinel.api import create_app  # noqa: E402
from sentinel.service import Sentinel  # noqa: E402
from sentinel.tools import build_tools  # noqa: E402

from .conftest import SAMPLE  # noqa: E402


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    s = Sentinel(db_path=str(tmp_path / "api.db"))
    return TestClient(create_app(s, Agent(build_tools(s))))


def test_end_to_end(client):
    assert client.get("/health").json()["status"] == "ok"
    r = client.post("/ingest", content=SAMPLE.read_bytes(), headers={"content-type": "text/plain"})
    assert r.status_code == 200 and r.json()["ingested"] > 800
    assert client.get("/stats").json()["unique_ips"] >= 25
    crit = client.get("/alerts", params={"severity": "critical"}).json()
    assert crit and all(a["severity"] == "critical" for a in crit)
    assert client.get("/logs", params={"ip": "192.0.2.77", "status": 429, "limit": 5}).status_code == 200
    assert client.get("/kb/search", params={"q": "sql injection"}).json()[0]["doc"] == "injection.md"
    ans = client.post("/ask", json={"question": "Summarise the attacks"}).json()
    assert ans["mode"] == "offline" and ans["steps"]


def test_validation(client):
    assert client.post("/ingest", content=b"").status_code == 400
    assert client.get("/alerts", params={"severity": "urgent"}).status_code == 422
    assert client.get("/logs", params={"limit": 100000}).status_code == 422
    assert client.post("/ask", json={"question": "x"}).status_code == 422
