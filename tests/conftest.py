import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sentinel.service import Sentinel  # noqa: E402
from sentinel.tools import build_tools  # noqa: E402

SAMPLE = ROOT / "sample_logs" / "access.log"


@pytest.fixture
def sentinel(tmp_path):
    s = Sentinel(db_path=str(tmp_path / "t.db"))
    s.ingest_text(SAMPLE.read_text())
    return s


@pytest.fixture
def tools(sentinel):
    return build_tools(sentinel)
