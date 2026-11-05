"""Parse access logs in the Apache/Nginx *combined* format.

Example line:
127.0.0.1 - - [03/Nov/2026:17:20:01 +0000] "GET /index.html HTTP/1.1" 200 512 "-" "curl/8.5"
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Iterable, Iterator
from urllib.parse import unquote

_LINE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<version>[^"]+)" '
    r'(?P<status>\d{3}) (?P<bytes>\d+|-)'
    r'(?: "(?P<referer>[^"]*)" "(?P<ua>[^"]*)")?'
)
_TS_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


@dataclass(frozen=True)
class LogEntry:
    ip: str
    ts: datetime
    method: str
    path: str
    version: str
    status: int
    bytes: int
    user_agent: str

    @property
    def decoded_path(self) -> str:
        """Path with percent-encoding removed (twice, to catch double-encoding)."""
        return unquote(unquote(self.path))

    def to_dict(self) -> dict:
        d = asdict(self)
        d["ts"] = self.ts.isoformat()
        return d


def parse_line(line: str) -> LogEntry | None:
    m = _LINE.match(line.strip())
    if not m:
        return None
    try:
        ts = datetime.strptime(m["ts"], _TS_FORMAT)
    except ValueError:
        return None
    return LogEntry(
        ip=m["ip"],
        ts=ts,
        method=m["method"],
        path=m["path"],
        version=m["version"],
        status=int(m["status"]),
        bytes=0 if m["bytes"] == "-" else int(m["bytes"]),
        user_agent=m["ua"] or "-",
    )


def parse_lines(lines: Iterable[str]) -> tuple[list[LogEntry], int]:
    """Return (entries, number_of_unparseable_lines)."""
    entries, bad = [], 0
    for line in lines:
        if not line.strip():
            continue
        e = parse_line(line)
        if e is None:
            bad += 1
        else:
            entries.append(e)
    return entries, bad


def iter_file(path: str) -> Iterator[str]:
    with open(path, encoding="utf-8", errors="replace") as f:
        yield from f
