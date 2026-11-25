"""Xabar matnidagi firibgarlik (social engineering) belgilari."""
from __future__ import annotations

import re

from .data import BRANDS, SCAM_TEXT_PATTERNS

_APOS = re.compile(r"[ʻʼ‘’`´ʹ′]")
_COMPILED = [(re.compile(p, re.I), w, why) for p, w, why in SCAM_TEXT_PATTERNS]


def norm_text(text: str) -> str:
    return _APOS.sub("'", (text or "").lower())


def scam_score(text: str) -> tuple[int, list[str]]:
    t = norm_text(text)
    score, reasons = 0, []
    for rx, w, why in _COMPILED:
        if rx.search(t):
            score += w
            reasons.append(why)
    return min(score, 45), reasons


def mentioned_brands(text: str) -> list[str]:
    t = norm_text(text)
    out = []
    for name, b in BRANDS.items():
        for kw in b["kw"]:
            if re.search(r"(?<![\w])" + re.escape(kw) + r"(?![\w])", t):
                out.append(name)
                break
    return out
