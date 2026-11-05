# Sentinel

**AI-assisted security analysis for web server access logs.** Sentinel ingests HTTP access logs, detects attacks with explainable rules mapped to MITRE ATT&CK, and lets you ask questions in plain English. A Claude-powered agent investigates by calling tools (database queries plus retrieval over security runbooks) and writes an incident-style answer. The same tools are exposed over the **Model Context Protocol (MCP)**, so AI assistants such as Claude Desktop or Cursor can use them directly.

It pairs with [netforge](../netforge), a C++ HTTP server whose access logs Sentinel analyses.

```
 access.log ─▶ parser ─▶ SQLite ─▶ detection rules ─▶ alerts (MITRE ATT&CK)
                                        │
             ┌──────────────── tools (validated, output-capped) ────────────────┐
             │ get_stats · get_alerts · search_logs · search_runbooks (RAG)     │
             └───────┬──────────────────────────────┬───────────────────────────┘
                     ▼                              ▼
      Claude agent (tool-use loop)        MCP server (JSON-RPC 2.0 over stdio)
                     │                              │
         FastAPI REST API  /  CLI          Claude Desktop, Cursor, other MCP clients
```

## What it demonstrates

| Area | Implementation |
|---|---|
| **REST API** | FastAPI with request validation (`422` on bad input), OpenAPI docs at `/docs`, size-limited upload |
| **Database** | SQLite with indexes; every query uses bound parameters, so no SQL is built from user or LLM input |
| **Detection** | Path traversal (incl. double-encoded), SQL injection, XSS, command injection, sensitive-file probes, scanner user agents, content discovery, sliding-window flood detection (O(n) two-pointer), rate-limit abuse, error bursts, 5xx spikes. A 2xx response to an attack escalates the alert to *critical* |
| **RAG** | Markdown runbooks → section chunking → embeddings → in-memory vector index → cosine top-k. The default TF-IDF embedder runs offline in NumPy; the `Embedder` interface lets you swap in a neural embedding model |
| **AI agent** | Tool-use loop on the Anthropic Messages API: the model decomposes a question into tool calls, observes results, then answers. Tracks token usage and returns the full tool trace |
| **MCP** | MCP server written from the spec (initialize, tools/list, tools/call, ping) with no SDK, so the JSON-RPC wire format is visible |
| **Guardrails** | JSON-Schema argument validation, step budget, output truncation that stays valid JSON (protects the context window), read-only tools, and a system prompt that treats log data as **untrusted** (attackers control URLs and user agents, so logs can carry prompt injection; the sample log includes one) |
| **Fallback** | Without an API key, `/ask` returns a deterministic report from the same tools, so the project always runs |

## Quick start

```bash
python3 -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt

python -m sentinel ingest sample_logs/access.log         # 831 real requests captured from netforge
python -m sentinel alerts
python -m sentinel ask "Which IPs attacked us and what should we do first?"
```

Enable the LLM agent (otherwise it runs in offline mode):

```bash
export ANTHROPIC_API_KEY=sk-ant-...           # Windows PowerShell: $env:ANTHROPIC_API_KEY="sk-ant-..."
export SENTINEL_MODEL=claude-sonnet-5-5       # optional; any Messages API model name works
python -m sentinel ask "Did any attack succeed? Show the evidence." --json
```

REST API:

```bash
python -m sentinel serve                      # http://127.0.0.1:8000/docs
curl -X POST localhost:8000/ingest --data-binary @sample_logs/access.log -H 'Content-Type: text/plain'
curl 'localhost:8000/alerts?severity=critical'
curl 'localhost:8000/logs?ip=192.0.2.77&status=429&limit=5'
curl 'localhost:8000/kb/search?q=how+to+stop+sql+injection'
curl -X POST localhost:8000/ask -H 'Content-Type: application/json' -d '{"question":"Summarise the incident"}'
```

## Use it from Claude Desktop (MCP)

Add this to `claude_desktop_config.json` (Settings → Developer → Edit Config), using absolute paths:

```json
{
  "mcpServers": {
    "sentinel": {
      "command": "/path/to/sentinel/.venv/bin/python",
      "args": ["-m", "sentinel.mcp_server"],
      "cwd": "/path/to/sentinel",
      "env": { "SENTINEL_DB": "/path/to/sentinel/sentinel.db" }
    }
  }
}
```

Restart Claude Desktop and ask "Use sentinel to check for critical alerts". You can also try the server by hand:

```bash
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' | python -m sentinel.mcp_server
```

## Full demo with netforge

```bash
# terminal 1: run the C++ server; --trust-proxy lets the generator simulate many client IPs
../netforge/build/netforge --port 8080 --trust-proxy --log access.log
# terminal 2: send normal users, a Nikto scan, sqlmap, traversal, XSS, command injection,
#             a prompt-injection user agent, a request flood and method fuzzing
python scripts/generate_traffic.py --port 8080
python -m sentinel clear && python -m sentinel ingest access.log && python -m sentinel alerts
```

Expected alerts from the sample log:

```
[CRITICAL] xss                    198.51.100.23   x3     ... 1 of these returned 2xx and need manual review.
[CRITICAL] command_injection      198.51.100.23   x2     OS command injection payloads in the request URL.
[HIGH    ] request_flood          192.0.2.77      x450   450 requests within 60s from a single IP.
[HIGH    ] path_traversal         198.51.100.23   x6     ...
[HIGH    ] sql_injection          198.51.100.23   x5     ...
[MEDIUM  ] rate_limit_exceeded    192.0.2.77      x346   Client was rate limited 346 times and kept sending.
[MEDIUM  ] scanner_user_agent     203.0.113.45    x25    Known security-scanner user agent (Nikto).
...
```

None of the 20 normal-user IPs are flagged.

## Tests

```bash
python -m pytest -q
```

The suite covers the parser, every detection rule (including a no-false-positives check on normal traffic), retrieval accuracy (each runbook is found by a realistic query), tool validation and SQL-injection safety, the agent loop against a scripted fake Claude (tool results, token accounting, step budget, prompt-injection handling), the MCP protocol in-process and over a real stdio subprocess, and the REST API.

## Project layout

```
sentinel/
  logparser.py    combined-log-format parser
  detectors.py    detection rules, sliding windows, MITRE mapping
  db.py           SQLite store (parameterised queries)
  rag.py          chunking, TF-IDF embedder, vector index, knowledge base
  tools.py        tool registry shared by the agent and MCP (schemas, validation, output cap)
  agent.py        Claude tool-use loop + offline fallback
  api.py          FastAPI app
  mcp_server.py   MCP server (JSON-RPC 2.0 over stdio)
  __main__.py     CLI
knowledge/        security runbooks used for retrieval
sample_logs/      real access log captured from netforge under simulated attack
scripts/          traffic generator
tests/            pytest suite
```

## Ideas to extend

- Swap TF-IDF for a neural embedding model and a vector database (Chroma, pgvector) behind the same interface.
- Stream logs live (tail the file or receive syslog) and push alerts to Slack or email.
- Add an anomaly-detection model (per-IP request-rate baseline) alongside the rules.
