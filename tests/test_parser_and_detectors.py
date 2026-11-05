from datetime import datetime, timedelta, timezone

from sentinel.detectors import Thresholds, _max_in_window, run_all
from sentinel.logparser import LogEntry, parse_line, parse_lines

LINE = '198.51.100.23 - - [03/Nov/2026:17:20:01 +0000] "GET /a?x=%252e%252e HTTP/1.1" 404 25 "-" "sqlmap/1.8"'
T0 = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)


def entry(ip="10.0.0.1", path="/", status=200, ua="Mozilla/5.0", dt=0.0, method="GET"):
    return LogEntry(ip, T0 + timedelta(seconds=dt), method, path, "HTTP/1.1", status, 10, ua)


def test_parse_combined_line():
    e = parse_line(LINE)
    assert e.ip == "198.51.100.23" and e.status == 404 and e.bytes == 25
    assert e.user_agent == "sqlmap/1.8" and e.ts.year == 2026
    assert e.decoded_path == "/a?x=.."          # double-encoding is unwrapped


def test_parse_rejects_garbage():
    entries, bad = parse_lines([LINE, "not a log line", "", '1.2.3.4 - - [bad date] "GET / HTTP/1.1" 200 1'])
    assert len(entries) == 1 and bad == 2


def rules(entries, **kw):
    return {(a.rule, a.ip) for a in run_all(entries, Thresholds(**kw))}


def test_normal_traffic_has_no_alerts():
    normal = [entry(ip=f"10.0.0.{i % 20}", path=p, dt=i)
              for i, p in enumerate(["/", "/health", "/api/kv/device-1", "/index.html"] * 50)]
    assert run_all(normal) == []


def test_payload_rules():
    e = [entry(ip="6.6.6.6", path="/%2e%2e/%2e%2e/etc/passwd", status=403),
         entry(ip="6.6.6.6", path="/s?q=1%20UNION%20SELECT%20pw%20FROM%20users"),
         entry(ip="6.6.6.6", path="/s?q=%3Cscript%3Ealert(1)%3C/script%3E", status=404),
         entry(ip="6.6.6.6", path="/ping?h=1;cat%20/etc/passwd", status=404),
         entry(ip="6.6.6.6", path="/.git/config", status=404)]
    found = rules(e)
    for r in ["path_traversal", "sql_injection", "xss", "command_injection", "sensitive_file_probe"]:
        assert (r, "6.6.6.6") in found


def test_successful_attack_is_escalated_to_critical():
    a = run_all([entry(ip="6.6.6.6", path="/../../etc/passwd", status=200)])
    assert a[0].rule == "path_traversal" and a[0].severity == "critical"


def test_scanner_and_discovery():
    e = [entry(ip="7.7.7.7", path=f"/missing{i}", status=404, ua="Nikto/2.5", dt=i) for i in range(20)]
    found = rules(e)
    assert ("scanner_user_agent", "7.7.7.7") in found and ("content_discovery", "7.7.7.7") in found


def test_flood_uses_sliding_window():
    burst = [entry(ip="8.8.8.8", dt=i * 0.1) for i in range(300)]          # 300 req in 30 s
    spread = [entry(ip="9.9.9.9", dt=i * 10) for i in range(300)]           # 300 req in 50 min
    found = rules(burst + spread)
    assert ("request_flood", "8.8.8.8") in found
    assert ("request_flood", "9.9.9.9") not in found


def test_max_in_window():
    items = [entry(dt=t) for t in [0, 1, 2, 100, 101]]
    n, sl = _max_in_window(items, timedelta(seconds=10))
    assert n == 3 and sl[0].ts == T0


def test_sample_log_detects_every_scenario(sentinel):
    found = {(a["rule"], a["ip"]) for a in sentinel.store.alerts(limit=200)}
    assert ("path_traversal", "198.51.100.23") in found
    assert ("sql_injection", "198.51.100.23") in found
    assert ("command_injection", "198.51.100.23") in found
    assert ("scanner_user_agent", "203.0.113.45") in found
    assert ("request_flood", "192.0.2.77") in found
    assert ("rate_limit_exceeded", "192.0.2.77") in found
    assert ("error_burst", "198.51.100.60") in found
    assert not any(ip.startswith("10.0.0.") for _, ip in found)  # no false positives on normal users
