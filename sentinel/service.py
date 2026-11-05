"""Ties together storage, detection and the knowledge base."""
from __future__ import annotations

import os
from pathlib import Path

from .db import Store
from .detectors import Thresholds, run_all
from .logparser import parse_lines
from .rag import KnowledgeBase

DEFAULT_KB = Path(__file__).resolve().parent.parent / "knowledge"


class Sentinel:
    def __init__(self, db_path: str | None = None, kb_path: str | Path | None = None,
                 thresholds: Thresholds | None = None):
        self.store = Store(db_path or os.environ.get("SENTINEL_DB", "sentinel.db"))
        self.kb = KnowledgeBase(kb_path or os.environ.get("SENTINEL_KB", DEFAULT_KB))
        self.thresholds = thresholds or Thresholds()

    def ingest_text(self, text: str) -> dict:
        entries, bad = parse_lines(text.splitlines())
        added = self.store.add_entries(entries)
        alerts = self.analyze()
        return {"ingested": added, "unparsed_lines": bad, "alerts": len(alerts)}

    def analyze(self):
        """Re-run every detector over all stored traffic and persist the alerts."""
        alerts = run_all(self.store.all_entries(), self.thresholds)
        self.store.replace_alerts(alerts)
        return alerts
