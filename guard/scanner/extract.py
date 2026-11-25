"""Xabardan barcha havolalarni ajratib olish: matn, yashirin havolalar, tugmalar, obfuskatsiya."""
from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit

import tldextract

_tld = tldextract.TLDExtract(suffix_list_urls=())  # internetsiz, ichki ro'yxat

# hxxp://, [.] , (.) , " dot " kabi niqoblarni ochish
_DEOBF = [
    (re.compile(r"h[x*]{2}p(s?)://", re.I), r"http\1://"),
    (re.compile(r"\s*[\[\(\{]\s*(\.|dot|nuqta)\s*[\]\)\}]\s*", re.I), "."),
    (re.compile(r"\s+(dot|nuqta)\s+", re.I), "."),
]
_URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"'«»]+", re.I)
_BARE_RE = re.compile(r"(?<![@\w.-])((?:[a-z0-9Ѐ-ӿ-]+\.)+[a-zЀ-ӿ]{2,24}(?::\d+)?(?:/[^\s<>\"'«»]*)?)", re.I)
_FILE_EXT_TLDS = {"apk", "exe", "jpg", "png", "mp4", "pdf", "zip", "rar", "txt", "doc", "docx", "js", "py"}


def deobfuscate(text: str) -> str:
    for rx, rep in _DEOBF:
        text = rx.sub(rep, text)
    return text


def normalize(url: str) -> str | None:
    url = url.strip().rstrip(".,;:!?)»”’]}")
    if not url:
        return None
    if not re.match(r"^[a-z][a-z0-9+.-]*://", url, re.I):
        url = "http://" + url
    try:
        p = urlsplit(url)
    except ValueError:
        return None
    if p.scheme.lower() not in ("http", "https", "tg"):
        return None
    host = (p.hostname or "").lower().rstrip(".")
    if not host:
        return None
    try:
        host_idna = host.encode("idna").decode() if not host.isascii() else host
    except UnicodeError:
        host_idna = host
    netloc = host_idna + (f":{p.port}" if p.port else "")
    return urlunsplit((p.scheme.lower(), netloc, p.path or "/", p.query, ""))


def registered_domain(host: str) -> str:
    e = _tld(host)
    if e.domain and e.suffix:
        return f"{e.domain}.{e.suffix}"
    return host


def split_host(host: str):
    return _tld(host)


def from_text(text: str) -> list[str]:
    if not text:
        return []
    t = deobfuscate(text)
    found = [m.group(0) for m in _URL_RE.finditer(t)]
    covered = " ".join(found)
    for m in _BARE_RE.finditer(t):
        cand = m.group(1)
        if cand in covered:
            continue
        e = _tld(cand.split("/")[0].split(":")[0])
        if not e.suffix or e.suffix.lower() in _FILE_EXT_TLDS or not e.domain:
            continue
        found.append(cand)
    return found


def from_message(msg) -> tuple[list[str], list[str]]:
    """(urllar, tugma_urllar) qaytaradi. aiogram Message obyekti bilan ishlaydi."""
    raw: list[str] = []
    buttons: list[str] = []
    for text, entities in ((msg.text, msg.entities), (msg.caption, msg.caption_entities)):
        if not text:
            continue
        raw += from_text(text)
        for ent in entities or []:
            if ent.type == "text_link" and ent.url:
                raw.append(ent.url)
            elif ent.type == "url":
                raw.append(ent.extract_from(text))
    kb = getattr(msg, "reply_markup", None)
    for row in getattr(kb, "inline_keyboard", None) or []:
        for b in row:
            for u in (b.url, getattr(b.web_app, "url", None), getattr(b.login_url, "url", None)):
                if u:
                    buttons.append(u)
    lpo = getattr(msg, "link_preview_options", None)
    if lpo is not None and getattr(lpo, "url", None):
        raw.append(lpo.url)

    def _uniq(seq):
        out, seen = [], set()
        for u in seq:
            n = normalize(u)
            if n and n not in seen:
                seen.add(n)
                out.append(n)
        return out

    btn = _uniq(buttons)
    return [u for u in _uniq(raw) if u not in btn], btn
