"""REST API (FastAPI).

Run: uvicorn sentinel.api:app --reload   ->  interactive docs at http://localhost:8000/docs
"""
from __future__ import annotations

from fastapi import FastAPI, HTTPException, Query, Request
from pydantic import BaseModel, Field

from . import __version__
from .agent import Agent
from .service import Sentinel
from .tools import build_tools

MAX_INGEST_BYTES = 20 * 1024 * 1024


class AskRequest(BaseModel):
    question: str = Field(..., min_length=3, max_length=2000,
                          examples=["Which IPs attacked us and what should we do first?"])


def create_app(sentinel: Sentinel | None = None, agent: Agent | None = None) -> FastAPI:
    s = sentinel or Sentinel()
    tools = build_tools(s)
    ag = agent or Agent(tools)
    app = FastAPI(title="Sentinel", version=__version__,
                  description="AI-assisted security analysis for web server access logs.")

    @app.get("/health")
    def health():
        return {"status": "ok", "kb_chunks": s.kb.size, "llm": "enabled" if ag.client else "offline"}

    @app.post("/ingest", summary="Upload access-log text (combined format) as the raw request body")
    async def ingest(request: Request):
        body = await request.body()
        if len(body) > MAX_INGEST_BYTES:
            raise HTTPException(413, "log upload too large")
        if not body.strip():
            raise HTTPException(400, "empty body: send log lines as text/plain")
        return s.ingest_text(body.decode("utf-8", errors="replace"))

    @app.get("/stats")
    def stats():
        return s.store.stats()

    @app.get("/alerts")
    def alerts(severity: str | None = Query(None, pattern="^(critical|high|medium|low)$"),
               ip: str | None = None, limit: int = Query(50, ge=1, le=200)):
        return s.store.alerts(severity, ip, limit)

    @app.get("/logs")
    def logs(ip: str | None = None, status: int | None = Query(None, ge=100, le=599),
             path_contains: str | None = Query(None, max_length=200), limit: int = Query(50, ge=1, le=500)):
        return s.store.search_logs(ip, status, path_contains, limit)

    @app.get("/kb/search", summary="Semantic search over the security runbooks")
    def kb_search(q: str = Query(..., min_length=2, max_length=300), k: int = Query(3, ge=1, le=10)):
        return s.kb.search(q, k)

    @app.post("/ask", summary="Ask the AI analyst a question about the ingested logs")
    def ask(req: AskRequest):
        try:
            return ag.run(req.question).to_dict()
        except RuntimeError as e:  # upstream LLM failure
            raise HTTPException(502, str(e))

    @app.delete("/data", summary="Delete all ingested logs and alerts")
    def clear():
        s.store.clear()
        return {"cleared": True}

    return app


app = create_app()
