"""Rule-based threat detection over parsed log entries.

Each detector looks at all entries and returns Alerts. Rules are deliberately
simple and explainable: every alert carries the evidence lines that triggered
it and a MITRE ATT&CK technique for context.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Callable

from .logparser import LogEntry

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass
class Alert:
    rule: str
    severity: str
    ip: str
    count: int
    first_seen: str
    last_seen: str
    description: str
    mitre: str
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class Thresholds:
    scan_distinct_404: int = 15          # distinct missing paths from one IP
    error_burst: int = 30                # 4xx responses from one IP within the window
    rate_limited: int = 20               # 429 responses to one IP
    flood_requests: int = 300            # requests from one IP within the window
    window: timedelta = timedelta(minutes=1)
    server_error_ratio: float = 0.2      # share of 5xx across all traffic
    server_error_min: int = 10


_TRAVERSAL = re.compile(r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|win\.ini|boot\.ini|/proc/self)", re.I)
_SQLI = re.compile(r"(\bunion\b.+\bselect\b|'\s*or\s+'?1'?\s*=\s*'?1|\bor\s+1\s*=\s*1\b|;\s*drop\s+table|\bsleep\s*\(|information_schema|--\s*$)", re.I)
_XSS = re.compile(r"(<script|javascript:|onerror\s*=|onload\s*=|<svg[^>]*on\w+=)", re.I)
_CMD = re.compile(r"(;|\|\||&&|\$\(|`)\s*(cat|id|whoami|wget|curl|nc|bash|sh)\b", re.I)
_SENSITIVE = re.compile(r"(/\.env|/\.git/|/wp-admin|/wp-login|/phpmyadmin|/admin\b|/\.aws/|/server-status|/config\.(php|json|yml))", re.I)
_SCANNER_UA = re.compile(r"(sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|wpscan|nuclei|ffuf|acunetix)", re.I)


def _fmt(e: LogEntry) -> str:
    return f'{e.ts.isoformat()} {e.ip} "{e.method} {e.path}" {e.status} "{e.user_agent}"'


def _group_by_ip(entries: list[LogEntry]) -> dict[str, list[LogEntry]]:
    g: dict[str, list[LogEntry]] = defaultdict(list)
    for e in entries:
        g[e.ip].append(e)
    for v in g.values():
        v.sort(key=lambda e: e.ts)
    return g


def _alert(rule, severity, ip, hits, description, mitre) -> Alert:
    return Alert(
        rule=rule, severity=severity, ip=ip, count=len(hits),
        first_seen=hits[0].ts.isoformat(), last_seen=hits[-1].ts.isoformat(),
        description=description, mitre=mitre, evidence=[_fmt(h) for h in hits[:5]],
    )


def _max_in_window(items: list[LogEntry], window: timedelta) -> tuple[int, list[LogEntry]]:
    """Largest number of items inside any sliding time window (two pointers, O(n))."""
    best, best_slice, lo = 0, [], 0
    for hi in range(len(items)):
        while items[hi].ts - items[lo].ts > window:
            lo += 1
        if hi - lo + 1 > best:
            best, best_slice = hi - lo + 1, items[lo:hi + 1]
    return best, best_slice


def detect_payloads(entries, t: Thresholds) -> list[Alert]:
    rules = [
        ("path_traversal", _TRAVERSAL, "high", "Path traversal attempt: requests try to escape the web root to read system files.", "T1190 Exploit Public-Facing Application"),
        ("sql_injection", _SQLI, "high", "SQL injection payloads in the request URL.", "T1190 Exploit Public-Facing Application"),
        ("xss", _XSS, "medium", "Cross-site scripting payloads in the request URL.", "T1190 Exploit Public-Facing Application"),
        ("command_injection", _CMD, "critical", "OS command injection payloads in the request URL.", "T1190 Exploit Public-Facing Application"),
        ("sensitive_file_probe", _SENSITIVE, "medium", "Probing for admin panels, secrets or config files (.env, .git, wp-admin...).", "T1595.003 Active Scanning: Wordlist Scanning"),
    ]
    alerts = []
    for ip, items in _group_by_ip(entries).items():
        for rule, rx, sev, desc, mitre in rules:
            hits = [e for e in items if rx.search(e.decoded_path)]
            if hits:
                succeeded = [h for h in hits if 200 <= h.status < 300]
                a = _alert(rule, sev, ip, hits, desc, mitre)
                if succeeded:  # the attack got a 2xx: escalate
                    a.severity = "critical"
                    a.description += f" {len(succeeded)} of these returned 2xx and need manual review."
                alerts.append(a)
    return alerts


def detect_scanners(entries, t: Thresholds) -> list[Alert]:
    alerts = []
    for ip, items in _group_by_ip(entries).items():
        ua_hits = [e for e in items if _SCANNER_UA.search(e.user_agent)]
        if ua_hits:
            tool = _SCANNER_UA.search(ua_hits[0].user_agent).group(1)
            alerts.append(_alert("scanner_user_agent", "medium", ip, ua_hits,
                                 f"Known security-scanner user agent ({tool}).", "T1595 Active Scanning"))
        missing = [e for e in items if e.status == 404]
        distinct = {e.path for e in missing}
        if len(distinct) >= t.scan_distinct_404:
            alerts.append(_alert("content_discovery", "medium", ip, missing,
                                 f"{len(distinct)} distinct non-existent paths requested (directory brute forcing).",
                                 "T1595.003 Active Scanning: Wordlist Scanning"))
    return alerts


def detect_abuse(entries, t: Thresholds) -> list[Alert]:
    alerts = []
    for ip, items in _group_by_ip(entries).items():
        n, burst = _max_in_window(items, t.window)
        if n >= t.flood_requests:
            alerts.append(_alert("request_flood", "high", ip, burst,
                                 f"{n} requests within {int(t.window.total_seconds())}s from a single IP.",
                                 "T1499 Endpoint Denial of Service"))
        limited = [e for e in items if e.status == 429]
        if len(limited) >= t.rate_limited:
            alerts.append(_alert("rate_limit_exceeded", "medium", ip, limited,
                                 f"Client was rate limited {len(limited)} times and kept sending.",
                                 "T1499 Endpoint Denial of Service"))
        errors = [e for e in items if 400 <= e.status < 500 and e.status not in (404, 429)]
        n, burst = _max_in_window(errors, t.window)
        if n >= t.error_burst:
            alerts.append(_alert("error_burst", "medium", ip, burst,
                                 f"{n} client errors (400/401/403/405...) within {int(t.window.total_seconds())}s; "
                                 "typical of brute forcing or fuzzing.", "T1110 Brute Force"))
    return alerts


def detect_server_errors(entries, t: Thresholds) -> list[Alert]:
    errs = sorted((e for e in entries if e.status >= 500 and e.status != 503), key=lambda e: e.ts)
    if len(errs) >= t.server_error_min and len(errs) / max(1, len(entries)) >= t.server_error_ratio:
        a = _alert("server_error_spike", "high", "*", errs,
                   f"{len(errs)} server errors ({len(errs) / len(entries):.0%} of traffic).",
                   "T1499 Endpoint Denial of Service")
        return [a]
    return []


DETECTORS: list[Callable[[list[LogEntry], Thresholds], list[Alert]]] = [
    detect_payloads, detect_scanners, detect_abuse, detect_server_errors,
]


def run_all(entries: list[LogEntry], thresholds: Thresholds | None = None) -> list[Alert]:
    t = thresholds or Thresholds()
    alerts = [a for d in DETECTORS for a in d(entries, t)]
    alerts.sort(key=lambda a: (SEVERITY_ORDER[a.severity], -a.count))
    return alerts
