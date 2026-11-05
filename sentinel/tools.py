"""Tools exposed to the LLM agent *and* to MCP clients (single source of truth).

Every tool has a JSON Schema, arguments are validated before execution, and
outputs are truncated so a large result cannot blow up the model's context
window.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable

from .service import Sentinel

MAX_OUTPUT_CHARS = 6000


class ToolError(ValueError):
    pass


@dataclass
class Tool:
    name: str
    description: str
    input_schema: dict
    fn: Callable[..., Any]

    def spec(self) -> dict:
        return {"name": self.name, "description": self.description, "input_schema": self.input_schema}


def _validate(schema: dict, args: dict) -> dict:
    if not isinstance(args, dict):
        raise ToolError("arguments must be an object")
    props = schema.get("properties", {})
    for req in schema.get("required", []):
        if req not in args:
            raise ToolError(f"missing required argument '{req}'")
    clean = {}
    for k, v in args.items():
        if k not in props:
            raise ToolError(f"unknown argument '{k}'")
        p = props[k]
        t = p.get("type")
        if t == "integer":
            if isinstance(v, bool) or not isinstance(v, int):
                raise ToolError(f"'{k}' must be an integer")
            if "minimum" in p and v < p["minimum"] or "maximum" in p and v > p["maximum"]:
                raise ToolError(f"'{k}' out of range [{p.get('minimum')}, {p.get('maximum')}]")
        elif t == "string":
            if not isinstance(v, str):
                raise ToolError(f"'{k}' must be a string")
            if len(v) > p.get("maxLength", 500):
                raise ToolError(f"'{k}' is too long")
            if "enum" in p and v not in p["enum"]:
                raise ToolError(f"'{k}' must be one of {p['enum']}")
        clean[k] = v
    return clean


def build_tools(s: Sentinel) -> dict[str, Tool]:
    tools = [
        Tool("get_stats",
             "Overview of the ingested traffic: total requests, unique IPs, time range, status-code classes, "
             "top talkers, top paths and alert counts by severity. Call this first to orient yourself.",
             {"type": "object", "properties": {}},
             lambda: s.store.stats()),
        Tool("get_alerts",
             "Security alerts raised by the detection rules (path traversal, injection, scanning, floods, "
             "brute force...), most severe first, with MITRE ATT&CK technique and evidence log lines.",
             {"type": "object", "properties": {
                 "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
                 "ip": {"type": "string", "maxLength": 64},
                 "limit": {"type": "integer", "minimum": 1, "maximum": 50}}},
             lambda severity=None, ip=None, limit=20: s.store.alerts(severity, ip, limit)),
        Tool("search_logs",
             "Search raw access-log entries, newest first. Filter by client IP, exact HTTP status code, "
             "and/or a substring of the request path.",
             {"type": "object", "properties": {
                 "ip": {"type": "string", "maxLength": 64},
                 "status": {"type": "integer", "minimum": 100, "maximum": 599},
                 "path_contains": {"type": "string", "maxLength": 200},
                 "limit": {"type": "integer", "minimum": 1, "maximum": 100}}},
             lambda ip=None, status=None, path_contains=None, limit=20: s.store.search_logs(ip, status, path_contains, limit)),
        Tool("search_runbooks",
             "Semantic search over the team's security runbooks (RAG). Use it to find how to recognise, respond "
             "to and prevent a type of attack. Returns the most relevant sections with their titles.",
             {"type": "object", "properties": {
                 "query": {"type": "string", "maxLength": 300},
                 "k": {"type": "integer", "minimum": 1, "maximum": 5}},
              "required": ["query"]},
             lambda query, k=3: s.kb.search(query, k)),
    ]
    return {t.name: t for t in tools}


def call_tool(tools: dict[str, Tool], name: str, args: dict | None) -> str:
    """Validate and run a tool; always returns a JSON string (errors included)."""
    if name not in tools:
        return json.dumps({"error": f"unknown tool '{name}'"})
    try:
        clean = _validate(tools[name].input_schema, args or {})
        result = tools[name].fn(**clean)
    except ToolError as e:
        return json.dumps({"error": str(e)})
    return _fit(result)


def _fit(result: Any) -> str:
    """Serialise, keeping the output valid JSON and under MAX_OUTPUT_CHARS."""
    out = json.dumps(result, default=str)
    if len(out) <= MAX_OUTPUT_CHARS:
        return out
    note = "output truncated to fit the context budget: narrow the query with filters or a lower limit"
    if isinstance(result, list):
        kept = list(result)
        while kept:
            kept.pop()
            out = json.dumps({"results": kept, "returned": len(kept), "total": len(result), "note": note}, default=str)
            if len(out) <= MAX_OUTPUT_CHARS:
                return out
    return json.dumps({"preview": out[:MAX_OUTPUT_CHARS - 200], "note": note})
