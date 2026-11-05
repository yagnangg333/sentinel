"""SQLite persistence for log entries and alerts."""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime

from .detectors import Alert
from .logparser import LogEntry

SCHEMA = """
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY,
    ip TEXT NOT NULL, ts TEXT NOT NULL, method TEXT, path TEXT, version TEXT,
    status INTEGER, bytes INTEGER, user_agent TEXT
);
CREATE INDEX IF NOT EXISTS idx_logs_ip ON logs(ip);
CREATE INDEX IF NOT EXISTS idx_logs_status ON logs(status);
CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs(ts);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY,
    rule TEXT, severity TEXT, ip TEXT, count INTEGER, first_seen TEXT, last_seen TEXT,
    description TEXT, mitre TEXT, evidence TEXT
);
"""


class Store:
    def __init__(self, path: str = "sentinel.db"):
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._conn.executescript(SCHEMA)

    def add_entries(self, entries: list[LogEntry]) -> int:
        rows = [(e.ip, e.ts.isoformat(), e.method, e.path, e.version, e.status, e.bytes, e.user_agent) for e in entries]
        with self._lock, self._conn:
            self._conn.executemany(
                "INSERT INTO logs(ip, ts, method, path, version, status, bytes, user_agent) VALUES (?,?,?,?,?,?,?,?)", rows)
        return len(rows)

    def all_entries(self) -> list[LogEntry]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM logs ORDER BY ts").fetchall()
        return [LogEntry(r["ip"], datetime.fromisoformat(r["ts"]), r["method"], r["path"], r["version"],
                         r["status"], r["bytes"], r["user_agent"]) for r in rows]

    def replace_alerts(self, alerts: list[Alert]) -> None:
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM alerts")
            self._conn.executemany(
                "INSERT INTO alerts(rule, severity, ip, count, first_seen, last_seen, description, mitre, evidence) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                [(a.rule, a.severity, a.ip, a.count, a.first_seen, a.last_seen, a.description, a.mitre,
                  json.dumps(a.evidence)) for a in alerts])

    def alerts(self, severity: str | None = None, ip: str | None = None, limit: int = 50) -> list[dict]:
        q, args = "SELECT * FROM alerts WHERE 1=1", []
        if severity:
            q += " AND severity = ?"; args.append(severity)
        if ip:
            q += " AND ip = ?"; args.append(ip)
        q += " ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, count DESC LIMIT ?"
        args.append(limit)
        with self._lock:
            rows = self._conn.execute(q, args).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["evidence"] = json.loads(d["evidence"])
            out.append(d)
        return out

    def search_logs(self, ip: str | None = None, status: int | None = None, path_contains: str | None = None,
                    limit: int = 50) -> list[dict]:
        # All filters are bound parameters: no SQL built from user/LLM input.
        q, args = "SELECT ip, ts, method, path, status, bytes, user_agent FROM logs WHERE 1=1", []
        if ip:
            q += " AND ip = ?"; args.append(ip)
        if status is not None:
            q += " AND status = ?"; args.append(int(status))
        if path_contains:
            q += " AND instr(path, ?) > 0"; args.append(path_contains)
        q += " ORDER BY ts DESC LIMIT ?"
        args.append(max(1, min(int(limit), 500)))
        with self._lock:
            return [dict(r) for r in self._conn.execute(q, args).fetchall()]

    def stats(self) -> dict:
        with self._lock:
            c = self._conn
            total = c.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
            ips = c.execute("SELECT COUNT(DISTINCT ip) FROM logs").fetchone()[0]
            span = c.execute("SELECT MIN(ts), MAX(ts) FROM logs").fetchone()
            by_class = {f"{r[0]}xx": r[1] for r in c.execute(
                "SELECT status/100, COUNT(*) FROM logs GROUP BY status/100 ORDER BY 1")}
            top = [dict(r) for r in c.execute(
                "SELECT ip, COUNT(*) AS requests, SUM(status >= 400) AS errors FROM logs "
                "GROUP BY ip ORDER BY requests DESC LIMIT 10")]
            paths = [dict(r) for r in c.execute(
                "SELECT path, COUNT(*) AS hits FROM logs GROUP BY path ORDER BY hits DESC LIMIT 10")]
            sev = {r[0]: r[1] for r in c.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity")}
        return {"total_requests": total, "unique_ips": ips, "first_seen": span[0], "last_seen": span[1],
                "status_classes": by_class, "top_talkers": top, "top_paths": paths, "alerts_by_severity": sev}

    def clear(self) -> None:
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM logs")
            self._conn.execute("DELETE FROM alerts")
