import json

from sentinel.rag import TfidfEmbedder, chunk_markdown, tokenize
from sentinel.tools import MAX_OUTPUT_CHARS, call_tool


def test_tokenize_drops_stopwords():
    assert tokenize("How do I stop the SQL injection?") == ["stop", "sql", "injection"]


def test_chunk_markdown_by_section():
    md = "# Title\n\nIntro text.\n\n## Detect\n\nLook for X.\n\n## Respond\n\nBlock it."
    chunks = chunk_markdown("doc.md", md)
    assert [c.title for c in chunks] == ["Title > Overview", "Title > Detect", "Title > Respond"]


def test_embeddings_are_normalised():
    e = TfidfEmbedder()
    e.fit(["alpha beta", "beta gamma"])
    v = e.embed(["beta gamma gamma"])
    assert abs(float((v ** 2).sum()) - 1.0) < 1e-5


def test_retrieval_finds_the_right_runbook(sentinel):
    cases = {
        "how do I prevent sql injection with parameterised queries": "injection.md",
        "client keeps getting 429 too many requests token bucket": "dos_rate_limiting.md",
        "someone requested /etc/passwd with ../ sequences": "path_traversal.md",
        "nikto scanner probing .env and .git": "scanning.md",
        "which TLS versions should be disabled": "tls_hardening.md",
        "many 401 failed logins credential stuffing": "brute_force.md",
    }
    for query, doc in cases.items():
        assert sentinel.kb.search(query, k=1)[0]["doc"] == doc, query


def test_tool_argument_validation(tools):
    assert "unknown argument" in call_tool(tools, "get_alerts", {"bogus": 1})
    assert "must be one of" in call_tool(tools, "get_alerts", {"severity": "urgent"})
    assert "out of range" in call_tool(tools, "search_logs", {"limit": 10_000})
    assert "must be an integer" in call_tool(tools, "search_logs", {"status": "404"})
    assert "missing required" in call_tool(tools, "search_runbooks", {})
    assert "unknown tool" in call_tool(tools, "rm_rf", {})


def test_search_logs_is_injection_safe(tools):
    out = json.loads(call_tool(tools, "search_logs", {"ip": "' OR '1'='1", "limit": 5}))
    assert out == []  # treated as a literal value, not SQL


def test_tool_output_stays_valid_json_when_truncated(tools):
    out = call_tool(tools, "search_logs", {"limit": 100})
    assert len(out) <= MAX_OUTPUT_CHARS
    data = json.loads(out)
    assert data["total"] == 100 and data["returned"] < 100


def test_stats(tools):
    st = json.loads(call_tool(tools, "get_stats", {}))
    assert st["total_requests"] > 800 and st["unique_ips"] >= 25
