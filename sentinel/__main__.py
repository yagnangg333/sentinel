"""Command line interface.

  python -m sentinel ingest access.log      parse, store and analyse a log file
  python -m sentinel alerts                 print alerts
  python -m sentinel ask "question"         ask the AI analyst
  python -m sentinel serve                  start the REST API (needs fastapi + uvicorn)
  python -m sentinel mcp                    start the MCP server on stdio
"""
from __future__ import annotations

import argparse
import json
import sys

from .agent import Agent
from .service import Sentinel
from .tools import build_tools


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="sentinel", description="AI-assisted security log analysis")
    p.add_argument("--db", help="SQLite database path (default sentinel.db or $SENTINEL_DB)")
    sub = p.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("ingest", help="ingest one or more access-log files")
    i.add_argument("files", nargs="+")
    a = sub.add_parser("alerts", help="list alerts")
    a.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    q = sub.add_parser("ask", help="ask the AI analyst a question")
    q.add_argument("question")
    q.add_argument("--json", action="store_true", help="print the full result including tool trace")
    sub.add_parser("stats", help="traffic overview")
    sub.add_parser("clear", help="delete all stored data")
    sv = sub.add_parser("serve", help="run the REST API")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8000)
    sub.add_parser("mcp", help="run the MCP server on stdio")
    args = p.parse_args(argv)

    if args.cmd == "serve":
        import uvicorn
        if args.db:
            import os
            os.environ["SENTINEL_DB"] = args.db
        uvicorn.run("sentinel.api:app", host=args.host, port=args.port)
        return 0

    s = Sentinel(args.db)
    if args.cmd == "mcp":
        from .mcp_server import McpServer
        McpServer(build_tools(s)).serve()
    elif args.cmd == "ingest":
        for f in args.files:
            with open(f, encoding="utf-8", errors="replace") as fh:
                print(f"{f}: {json.dumps(s.ingest_text(fh.read()))}")
    elif args.cmd == "alerts":
        for al in s.store.alerts(args.severity, limit=200):
            print(f"[{al['severity'].upper():8}] {al['rule']:22} {al['ip']:15} x{al['count']:<5} {al['description']}")
    elif args.cmd == "stats":
        print(json.dumps(s.store.stats(), indent=2))
    elif args.cmd == "clear":
        s.store.clear()
        print("cleared")
    elif args.cmd == "ask":
        res = Agent(build_tools(s)).run(args.question)
        if args.json:
            print(json.dumps(res.to_dict(), indent=2))
        else:
            print(res.answer)
            print(f"\n[{res.mode} mode | tool calls: {len(res.steps)} | tokens in/out: "
                  f"{res.usage['input_tokens']}/{res.usage['output_tokens']}]", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
