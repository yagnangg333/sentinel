"""Retrieval-Augmented Generation over a folder of Markdown security runbooks.

Pipeline: load .md files -> split into chunks by section -> embed -> store the
vectors in an in-memory vector index -> cosine-similarity top-k search.

The default embedder is TF-IDF implemented with NumPy so the project runs
fully offline with no model download. Anything that implements the
`Embedder` protocol (e.g. a sentence-transformers or API embedding model) can
be swapped in without touching the rest of the pipeline.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import numpy as np

_TOKEN = re.compile(r"[a-z0-9]+(?:\.[0-9]+)?")
_STOP = set("""a an and are as at be by for from has have how if in into is it its of on or that the this to was
were what when where which who why will with you your can do does not no should than then there these they""".split())


def tokenize(text: str) -> list[str]:
    return [t for t in _TOKEN.findall(text.lower()) if t not in _STOP and len(t) > 1]


@dataclass
class Chunk:
    doc: str        # source file name
    title: str      # document title + section heading
    text: str

    def to_dict(self) -> dict:
        return {"doc": self.doc, "title": self.title, "text": self.text}


class Embedder(Protocol):
    def fit(self, texts: list[str]) -> None: ...
    def embed(self, texts: list[str]) -> np.ndarray: ...


class TfidfEmbedder:
    """Sublinear TF x smoothed IDF, L2-normalised (so dot product == cosine)."""

    def __init__(self) -> None:
        self.vocab: dict[str, int] = {}
        self.idf: np.ndarray = np.zeros(0)

    def fit(self, texts: list[str]) -> None:
        df: Counter[str] = Counter()
        for t in texts:
            df.update(set(tokenize(t)))
        self.vocab = {w: i for i, w in enumerate(sorted(df))}
        n = len(texts)
        self.idf = np.array([math.log((1 + n) / (1 + df[w])) + 1 for w in sorted(df)], dtype=np.float32)

    def embed(self, texts: list[str]) -> np.ndarray:
        m = np.zeros((len(texts), len(self.vocab)), dtype=np.float32)
        for row, t in enumerate(texts):
            for w, c in Counter(tokenize(t)).items():
                if (j := self.vocab.get(w)) is not None:
                    m[row, j] = 1 + math.log(c)
        m *= self.idf
        norms = np.linalg.norm(m, axis=1, keepdims=True)
        return m / np.where(norms == 0, 1, norms)


class VectorIndex:
    """Minimal in-memory vector store: normalised vectors + payloads, cosine top-k."""

    def __init__(self) -> None:
        self.vectors = np.zeros((0, 0), dtype=np.float32)
        self.items: list[Chunk] = []

    def build(self, vectors: np.ndarray, items: list[Chunk]) -> None:
        self.vectors, self.items = vectors, items

    def search(self, qvec: np.ndarray, k: int) -> list[tuple[Chunk, float]]:
        if not self.items:
            return []
        scores = self.vectors @ qvec
        top = np.argsort(-scores)[:k]
        return [(self.items[i], float(scores[i])) for i in top if scores[i] > 0]


def chunk_markdown(name: str, text: str, max_chars: int = 1200) -> list[Chunk]:
    """Split on '## ' headings; long sections are split further on blank lines."""
    title_match = re.search(r"^# (.+)$", text, re.M)
    doc_title = title_match.group(1).strip() if title_match else name
    sections = re.split(r"^## ", text, flags=re.M)
    chunks: list[Chunk] = []
    for i, sec in enumerate(sections):
        if i == 0:
            body = re.sub(r"^# .+$", "", sec, flags=re.M).strip()
            heading = "Overview"
        else:
            heading, _, body = sec.partition("\n")
            body = body.strip()
        if not body:
            continue
        buf = ""
        for para in body.split("\n\n"):
            if buf and len(buf) + len(para) > max_chars:
                chunks.append(Chunk(name, f"{doc_title} > {heading.strip()}", buf.strip()))
                buf = ""
            buf += para + "\n\n"
        if buf.strip():
            chunks.append(Chunk(name, f"{doc_title} > {heading.strip()}", buf.strip()))
    return chunks


class KnowledgeBase:
    def __init__(self, folder: str | Path, embedder: Embedder | None = None):
        self.folder = Path(folder)
        self.embedder = embedder or TfidfEmbedder()
        self.index = VectorIndex()
        self.reload()

    def reload(self) -> int:
        chunks: list[Chunk] = []
        for p in sorted(self.folder.glob("*.md")):
            chunks += chunk_markdown(p.name, p.read_text(encoding="utf-8"))
        texts = [f"{c.title}\n{c.text}" for c in chunks]
        if texts:
            self.embedder.fit(texts)
            self.index.build(self.embedder.embed(texts), chunks)
        return len(chunks)

    def search(self, query: str, k: int = 3) -> list[dict]:
        q = self.embedder.embed([query])[0]
        return [{**c.to_dict(), "score": round(s, 3)} for c, s in self.index.search(q, k)]

    @property
    def size(self) -> int:
        return len(self.index.items)
