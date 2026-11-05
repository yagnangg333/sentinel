import json
import os
import subprocess
import sys
from pathlib import Path

from sentinel.mcp_server import McpServer

ROOT = Path(__file__).resolve().parent.parent


def test_handshake_and_tools(tools):
    srv = McpServer(tools)
    init = srv.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                       "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t"}}})
    assert init["result"]["protocolVersion"] == "2025-06-18"
    assert init["result"]["capabilities"]["tools"] is not None
    assert srv.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    listed = srv.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})["result"]["tools"]
    assert {t["name"] for t in listed} == {"get_stats", "get_alerts", "search_logs", "search_runbooks"}
    assert all("inputSchema" in t for t in listed)
    res = srv.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                      "params": {"name": "get_alerts", "arguments": {"severity": "critical"}}})["result"]
    assert res["isError"] is False and "command_injection" in res["content"][0]["text"]
    bad = srv.handle({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                      "params": {"name": "get_alerts", "arguments": {"limit": 0}}})["result"]
    assert bad["isError"] is True
    assert srv.handle({"jsonrpc": "2.0", "id": 5, "method": "nope"})["error"]["code"] == -32601


def test_stdio_transport(sentinel, tmp_path):
    db = sentinel.store._conn.execute("PRAGMA database_list").fetchone()[2]
    msgs = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "get_stats", "arguments": {}}},
    ]
    p = subprocess.run([sys.executable, "-m", "sentinel.mcp_server"], cwd=ROOT, capture_output=True, text=True,
                       input="\n".join(json.dumps(m) for m in msgs) + "\nnot json\n", timeout=30,
                       env={**os.environ, "SENTINEL_DB": db})
    replies = [json.loads(l) for l in p.stdout.splitlines()]
    assert [r.get("id") for r in replies] == [1, 2, None]          # no reply to the notification
    assert json.loads(replies[1]["result"]["content"][0]["text"])["total_requests"] > 800
    assert replies[2]["error"]["code"] == -32700                   # parse error
