"""Xabarni to'liq tekshiruvchi asosiy dvigatel.

Tezlik uchun ikki bosqich:
  1) lokal evristika (millisekundlar) — aniq xavfli bo'lsa darhol o'chiriladi;
  2) tarmoq tekshiruvlari parallel (redirect, sahifa, domen yoshi, GSB/VT/URLhaus, fishing bazalari).
"""
from __future__ import annotations

import asyncio
import io
import logging
import time

import aiohttp

from ..config import config
from . import apk as apk_mod
from . import url as url_mod
from .extract import from_message
from .result import MALICIOUS, SAFE, SUSPICIOUS, Finding, Verdict
from .text import mentioned_brands, scam_score

log = logging.getLogger(__name__)
_session: aiohttp.ClientSession | None = None
_sem = asyncio.Semaphore(20)


async def session() -> aiohttp.ClientSession:
    global _session
    if _session is None or _session.closed:
        _session = aiohttp.ClientSession(trust_env=True, connector=aiohttp.TCPConnector(limit=50, ttl_dns_cache=300))
    return _session


async def close():
    if _session and not _session.closed:
        await _session.close()


def _context(msg) -> str:
    parts = [msg.text or "", msg.caption or ""]
    kb = getattr(msg, "reply_markup", None)
    for row in getattr(kb, "inline_keyboard", None) or []:
        parts += [b.text or "" for b in row]
    if getattr(msg, "document", None) and msg.document.file_name:
        parts.append(msg.document.file_name)
    return "\n".join(parts)


def _apply_context(f: Finding, text_pts: int, text_why: list[str], via_bot: bool, is_button: bool):
    """Matndagi firibgarlik belgilarini havola bahosiga qo'shadi (matnning o'zi hech qachon o'chirmaydi)."""
    if f.trusted and not f.hard:
        return
    if text_pts:
        f.add(text_pts, "xabar matnida firibgarlik belgilari: " + ", ".join(text_why[:3]), strong=text_pts >= 18)
    if via_bot and is_button:
        f.add(15, "inline-bot/forward orqali tugmali «reklama» ko'rinishida yuborilgan (fishingning asosiy usuli)")


async def scan_message(bot, msg, *, quick_only: bool = False, extra_context: str = "",
                       allow_fast: bool = True) -> Verdict:
    t0 = time.monotonic()
    v = Verdict()
    ctx = _context(msg) + ("\n" + extra_context if extra_context else "")
    urls, buttons = from_message(msg)
    text_pts, text_why = scam_score(ctx)
    via_bot = bool(getattr(msg, "via_bot", None)) or bool(getattr(msg, "forward_origin", None))
    sess = await session()

    # ── 1) lokal tekshiruv
    quick: dict[str, Finding] = {}
    for u in urls + buttons:
        f = url_mod.static_check(u, ctx)
        _apply_context(f, text_pts, text_why, via_bot, u in buttons)
        quick[u] = f

    doc = getattr(msg, "document", None)
    file_task = None
    if doc and apk_mod.is_risky_file(doc.file_name or "", doc.mime_type):
        file_task = asyncio.create_task(_scan_doc(bot, sess, doc, text_pts, text_why))

    mal, sus = config.malicious_threshold, config.suspicious_threshold
    if allow_fast and any(f.level(mal, sus) == MALICIOUS for f in quick.values()) and file_task is None:
        v.findings = list(quick.values())
        v.level = MALICIOUS
        v.fast = True
        v.elapsed = time.monotonic() - t0
        return v
    if quick_only:
        v.findings = list(quick.values())
        for f in v.findings:
            v.bump(f.level(mal, sus))
        return v

    # ── 2) chuqur tekshiruv (parallel, umumiy vaqt chegarasi bilan)
    async def _deep(u: str) -> Finding:
        async with _sem:
            f = await url_mod.deep_check(sess, u)
        # kontekst bo'yicha qo'shimchalar (keshga tushmaydi)
        q = quick[u]
        f.score = _merge(f, q, u)
        for r in q.reasons:
            if r not in f.reasons:
                f.reasons.append(r)
                f.weights[r] = q.weights.get(r, 5)
        f.strong |= q.strong
        return f

    tasks = [asyncio.create_task(_deep(u)) for u in quick]
    if file_task:
        tasks.append(file_task)
    done, pending = await asyncio.wait(tasks, timeout=config.scan_timeout) if tasks else (set(), set())
    for p in pending:
        p.cancel()
    results = {}
    for t in done:
        if not t.cancelled() and t.exception() is None:
            r = t.result()
            results[r.target] = r
    findings = []
    for u, q in quick.items():
        findings.append(results.get(u, q))
    if file_task:
        if file_task in done and file_task.exception() is None:
            findings.append(file_task.result())
        else:
            fb = Finding(target=doc.file_name or "fayl", kind="file")
            apk_mod.name_check(doc.file_name or "", fb)
            findings.append(fb)
    v.findings = findings
    for f in findings:
        v.bump(f.level(mal, sus))
    v.elapsed = time.monotonic() - t0
    return v


def _merge(deep: Finding, quick: Finding, url: str) -> int:
    """Chuqur tahlil (kontekstsiz) + kontekst ballari."""
    base_static = url_mod.static_check(url).score
    context_extra = max(0, quick.score - base_static)
    return deep.score + context_extra


async def _scan_doc(bot, sess, doc, text_pts, text_why) -> Finding:
    data = None
    if doc.file_size and doc.file_size <= config.max_file_mb * 1024 * 1024:
        try:
            buf = io.BytesIO()
            await bot.download(doc, destination=buf, timeout=60)
            data = buf.getvalue()
        except Exception as e:  # noqa: BLE001
            log.warning("download failed: %s", e)
    f = await apk_mod.analyze_file(sess, doc.file_name or "fayl", data, doc.file_size)
    if text_pts:
        f.add(min(text_pts, 25), "fayl bilan birga aldovchi matn: " + ", ".join(text_why[:3]))
    return f


async def scan_url_text(text: str) -> Verdict:
    """Shaxsiy chatda /check uchun: matndagi havolalarni chuqur tekshirish."""
    from .extract import from_text, normalize
    t0 = time.monotonic()
    v = Verdict()
    sess = await session()
    tp, tw = scam_score(text)
    urls = [n for n in (normalize(u) for u in from_text(text)) if n]
    fs = await asyncio.gather(*(url_mod.deep_check(sess, u) for u in dict.fromkeys(urls)))
    for f in fs:
        if mentioned_brands(text):
            q = url_mod.static_check(f.target, text)
            for r in q.reasons:
                if r not in f.reasons:
                    f.reasons.append(r)
                    f.weights[r] = q.weights.get(r, 5)
            f.score = _merge(f, q, f.target)
        _apply_context(f, tp, tw, False, False)
        v.findings.append(f)
        v.bump(f.level(config.malicious_threshold, config.suspicious_threshold))
    v.elapsed = time.monotonic() - t0
    return v


__all__ = ["scan_message", "scan_url_text", "close", "session", "SAFE", "SUSPICIOUS", "MALICIOUS"]
