"""URL tahlili: lokal evristika (bir zumda) + tarmoq tekshiruvlari (redirect, sahifa mazmuni,
domen yoshi, Google Safe Browsing, VirusTotal, URLhaus, ochiq fishing ro'yxatlari)."""
from __future__ import annotations

import asyncio
import base64
import ipaddress
import logging
import re
import socket
import time
from datetime import datetime, timezone
from urllib.parse import parse_qs, urljoin, urlsplit

import aiohttp

from ..config import config
from .data import (BRANDS, FREE_HOSTING, SAFE_DOMAINS, SHORTENERS, SUSPICIOUS_TLDS, UNSAFE_SUBPATHS,
                   URL_KEYWORDS, USER_CONTENT_HOSTS)
from .extract import normalize, registered_domain, split_host
from .result import Finding
from .text import mentioned_brands, scam_score

log = logging.getLogger(__name__)
UA = ("Mozilla/5.0 (Linux; Android 14; SM-A546E) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/131.0 Mobile Safari/537.36")

# Kirill/lotin o'xshash harflar (homoglyph) -> lotin
_CONFUSABLE = str.maketrans({"а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i",
                             "ј": "j", "ԁ": "d", "һ": "h", "ӏ": "l", "ɡ": "g", "ո": "n", "ս": "u", "ν": "v",
                             "0": "o", "1": "l", "3": "e", "5": "s", "@": "a"})


def _lev(a: str, b: str) -> int:
    if abs(len(a) - len(b)) > 2:
        return 9
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _host_matches(host: str, domains) -> bool:
    return any(host == d or host.endswith("." + d) for d in domains)


def is_trusted(url: str) -> bool:
    p = urlsplit(url)
    host = (p.hostname or "").lower()
    if not _host_matches(host, SAFE_DOMAINS):
        return False
    hp = host + p.path
    return not any(hp.startswith(s) or hp.startswith("www." + s) for s in UNSAFE_SUBPATHS)


def _unicode_host(host: str) -> str:
    try:
        return host.encode().decode("idna") if "xn--" in host else host
    except UnicodeError:
        return host


# ─────────────────────────── 1) LOKAL EVRISTIKA ───────────────────────────
def static_check(url: str, context_text: str = "", f: Finding | None = None) -> Finding:
    f = f or Finding(target=url, kind="url")
    p = urlsplit(url)
    host = (p.hostname or "").lower()
    reg = registered_domain(host)
    ext = split_host(host)
    if is_trusted(url):
        f.trusted = True
        return f

    # IP manzil
    try:
        ipaddress.ip_address(host)
        f.add(35, "havola domen emas, to'g'ridan-to'g'ri IP manzil")
    except ValueError:
        pass

    # Punycode / kirill harflar bilan niqoblangan domen
    uhost = _unicode_host(host)
    if "xn--" in host or not uhost.isascii():
        f.add(30, f"domen o'xshash harflar bilan niqoblangan ({uhost})")
    skel = uhost.translate(_CONFUSABLE)

    # Brendni taqlid qilish (typosquatting)
    labels = [lbl for lbl in re.split(r"[.\-_]", skel) if lbl]
    tokens = set(labels) | {re.sub(r"\d", "", x) for x in labels}
    joined = re.sub(r"[.\-_]", "", skel)
    for brand, b in BRANDS.items():
        if _host_matches(host, b["domains"]):
            continue
        hit = False
        for bt in b["tokens"]:
            if bt in tokens or (len(bt) >= 6 and bt in joined):
                hit = True
            elif len(bt) >= 6 and any(len(t) >= 5 and _lev(t, bt) == 1 for t in tokens):
                hit = True
            if hit:
                break
        if hit:
            f.add(45, f"domen «{brand}» nomini taqlid qilmoqda, lekin rasmiy sayt emas")
            f.tags.add("brand"); f.details["brand"] = brand
            break

    # Xabarda brend nomi bor, havola esa boshqa joyga
    for brand in mentioned_brands(context_text):
        if not _host_matches(host, BRANDS[brand]["domains"]):
            f.add(25, f"xabar «{brand}» nomidan, lekin havola uning rasmiy saytiga olib bormaydi")
            break

    suffix = (ext.suffix or "").lower()
    if suffix in SUSPICIOUS_TLDS or suffix.split(".")[-1] in SUSPICIOUS_TLDS:
        f.add(15, f"fishingda ko'p ishlatiladigan domen zonasi (.{suffix})")
    if _host_matches(host, FREE_HOSTING):
        f.add(20, "bepul hosting/tunnel xizmatida joylashgan sayt")
    if reg in SHORTENERS or host in SHORTENERS:
        f.add(10, "qisqartirilgan havola (asl manzil yashirilgan)")
    if "@" in (p.netloc or ""):
        f.add(30, "havolada «@» hiylasi (asl domen yashirilgan)")
    if host.count(".") >= 4:
        f.add(10, "juda ko'p subdomenli manzil")
    if host.count("-") >= 3:
        f.add(10, "domenda ko'p defis")
    if p.port and p.port not in (80, 443):
        f.add(10, f"nostandart port :{p.port}")

    low = (skel + " " + p.path + " " + p.query).lower().replace("'", "")
    kw = 0
    for word, w in URL_KEYWORDS.items():
        if word in low:
            kw += w
    if kw:
        f.add(min(kw, 30), "manzilda fishingga xos so'zlar (login/gift/bonus/ovoz/premium...)")
    if re.search(r"\.(apk|apks|xapk)(\?|$)", p.path, re.I):
        f.add(45, "havola to'g'ridan-to'g'ri APK faylni yuklatadi")
        f.tags.add("apk")

    # Telegram bot havolalari
    if reg in ("t.me", "telegram.me", "telegram.dog"):
        seg = p.path.strip("/").split("/")[0].lower()
        q = parse_qs(p.query)
        if seg.endswith("bot") and ("start" in q or "startapp" in q or len(p.path.strip("/").split("/")) > 1):
            f.add(15, f"noma'lum Telegram botga yo'naltiradi (@{seg})")
    return f


# ─────────────────────────── 2) TARMOQ TEKSHIRUVLARI ───────────────────────────
_cache: dict[str, tuple[float, Finding]] = {}
_CACHE_TTL = 6 * 3600
_feed_urls: set[str] = set()
_feed_hosts: set[str] = set()
_feed_loaded = 0.0
_rdap_cache: dict[str, int | None] = {}


def _is_public(ip: str) -> bool:
    a = ipaddress.ip_address(ip)
    return not (a.is_private or a.is_loopback or a.is_link_local or a.is_reserved or a.is_multicast
                or a.is_unspecified)


async def _host_is_public(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return _is_public(host)
    except ValueError:
        pass
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError:
        return False
    return bool(infos) and all(_is_public(i[4][0]) for i in infos)


async def fetch_chain(session: aiohttp.ClientSession, url: str, max_hops: int = 6):
    """Redirectlarni xavfsiz kuzatadi (ichki tarmoqqa so'rov yubormaydi).
    Qaytaradi: (zanjir, yakuniy_url, html|None, content_type)"""
    chain, cur = [url], url
    for _ in range(max_hops):
        host = urlsplit(cur).hostname or ""
        if not await _host_is_public(host):
            return chain, cur, None, ""
        try:
            async with session.get(cur, allow_redirects=False, headers={"User-Agent": UA},
                                   timeout=aiohttp.ClientTimeout(total=6), ssl=False) as r:
                ctype = r.headers.get("Content-Type", "").lower()
                if r.status in (301, 302, 303, 307, 308) and r.headers.get("Location"):
                    nxt = normalize(urljoin(cur, r.headers["Location"]))
                    if not nxt or nxt in chain:
                        return chain, cur, None, ctype
                    chain.append(nxt)
                    cur = nxt
                    continue
                if "html" in ctype or "text" in ctype:
                    body = await r.content.read(400_000)
                    html = body.decode(r.get_encoding() if r.charset else "utf-8", errors="ignore")
                    # meta refresh / JS redirect
                    m = re.search(r"http-equiv=[\"']?refresh[\"']?[^>]*url=([^\"'>\s]+)", html, re.I) or \
                        re.search(r"(?:window\.|document\.)?location(?:\.href)?\s*=\s*[\"'](https?://[^\"']+)", html, re.I)
                    if m and len(html) < 20_000:
                        nxt = normalize(urljoin(cur, m.group(1)))
                        if nxt and nxt not in chain:
                            chain.append(nxt)
                            cur = nxt
                            continue
                    return chain, cur, html, ctype
                return chain, cur, None, ctype
        except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeError, ValueError) as e:
            log.debug("fetch %s: %s", cur, e)
            return chain, cur, None, ""
    return chain, cur, None, ""


_TG_KIT = re.compile(r"auth\.sendCode|auth\.signIn|auth\.checkPassword|gramjs|telegram(\.min)?\.js|tdweb|"
                     r"mtproto|api_hash|apiHash|telegram-web-app\.js.{0,200}phone|tgme_page_photo|tgme_action_button", re.I)
_PHONE_INPUT = re.compile(r"type=[\"']tel[\"']|name=[\"'](phone|tel|number)[\"']|\+998|placeholder=[\"'][^\"']*(raqam|номер|phone)", re.I)
_CODE_INPUT = re.compile(r"kodni kiriting|введите код|enter (the )?code|tasdiqlash kodi|код из (смс|telegram)|login code", re.I)
_CARD = re.compile(r"\bcvv\b|\bcvc\b|karta raqam|номер карты|card number|amal qilish muddati|срок действия карты", re.I)
_PASS = re.compile(r"type=[\"']password[\"']", re.I)
_APK_LINK = re.compile(r"href=[\"'][^\"']+\.(apk|xapk|apks)[\"'?#]|vnd\.android\.package-archive", re.I)
_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_TAGS = re.compile(r"<script.*?</script>|<style.*?</style>|<[^>]+>", re.I | re.S)


def analyze_html(f: Finding, html: str, host: str, skip_forms: bool = False):
    title = (_TITLE.search(html).group(1).strip() if _TITLE.search(html) else "")[:200]
    visible = re.sub(r"\s+", " ", _TAGS.sub(" ", html))[:20000]
    low_all = (title + " " + visible).lower()
    tg_word = "telegram" in low_all or "телеграм" in low_all
    if _TG_KIT.search(html) and not _host_matches(host, BRANDS["Telegram"]["domains"]):
        f.add(55, "sahifada Telegram akkauntiga kirish kodini o'g'irlovchi kod bor (soxta Telegram login)")
        f.tags.add("tg_steal")
    if not skip_forms:
        if tg_word and _PHONE_INPUT.search(html):
            f.add(40, "sahifa Telegram nomidan telefon raqamingizni so'ramoqda")
            f.tags.add("tg_steal")
        if _CODE_INPUT.search(visible):
            f.add(25, "sahifa SMS/Telegram tasdiqlash kodini so'ramoqda")
        if _CARD.search(visible) or _CARD.search(html[:50000]):
            f.add(35, "sahifa bank karta ma'lumotlarini (raqam/CVV/muddat) so'ramoqda")
            f.tags.add("card")
    if _APK_LINK.search(html):
        f.add(40, "sahifa telefonga APK ilova o'rnatishga undaydi")
        f.tags.add("apk")
    brands = mentioned_brands(title + " " + visible[:3000])
    for b in brands:
        if b != "Google" and not _host_matches(host, BRANDS[b]["domains"]):
            f.add(25, f"sahifa «{b}» nomidan ochilgan, lekin domen rasmiy emas")
            f.tags.add("brand"); f.details.setdefault("brand", b)
            if _PASS.search(html):
                f.add(15, "soxta sahifada parol maydoni bor")
            break
    s, _ = scam_score(title + " " + visible[:3000])
    if s >= 20:
        f.add(min(s, 25), "sahifa matnida firibgarlik belgilari (sovg'a/yutuq/ovoz berish)")


async def domain_age_days(session, domain: str) -> int | None:
    if domain in _rdap_cache:
        return _rdap_cache[domain]
    age = None
    try:
        async with session.get(f"https://rdap.org/domain/{domain}", timeout=aiohttp.ClientTimeout(total=4)) as r:
            if r.status == 200:
                data = await r.json(content_type=None)
                for ev in data.get("events", []):
                    if ev.get("eventAction") == "registration":
                        d = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                        age = (datetime.now(timezone.utc) - d).days
    except Exception as e:  # noqa: BLE001
        log.debug("rdap %s: %s", domain, e)
    _rdap_cache[domain] = age
    return age


async def refresh_feeds(session):
    """Ochiq fishing/zararli URL ro'yxatlari (kalit talab qilinmaydi)."""
    global _feed_loaded
    if not config.feeds_enabled or time.time() - _feed_loaded < 1800:
        return
    _feed_loaded = time.time()
    urls, hosts = set(), set()
    for src in ("https://openphish.com/feed.txt", "https://urlhaus.abuse.ch/downloads/text_online/"):
        try:
            async with session.get(src, timeout=aiohttp.ClientTimeout(total=20)) as r:
                if r.status != 200:
                    continue
                for line in (await r.text()).splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    n = normalize(line)
                    if n:
                        urls.add(n)
                        h = urlsplit(n).hostname or ""
                        if h and not _host_matches(h, FREE_HOSTING) and not _host_matches(h, SAFE_DOMAINS):
                            hosts.add(h)
        except Exception as e:  # noqa: BLE001
            log.warning("feed %s: %s", src, e)
    if urls:
        _feed_urls.clear(); _feed_urls.update(urls)
        _feed_hosts.clear(); _feed_hosts.update(hosts)
        log.info("Fishing ro'yxatlari yangilandi: %d URL, %d domen", len(urls), len(hosts))


def feed_hit(url: str) -> bool:
    return url in _feed_urls or (urlsplit(url).hostname or "") in _feed_hosts


async def gsb_check(session, urls: list[str]) -> bool:
    if not config.gsb_api_key:
        return False
    body = {"client": {"clientId": "tg-guard", "clientVersion": "1.0"},
            "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                                           "POTENTIALLY_HARMFUL_APPLICATION"],
                           "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"],
                           "threatEntries": [{"url": u} for u in urls]}}
    try:
        async with session.post("https://safebrowsing.googleapis.com/v4/threatMatches:find",
                                params={"key": config.gsb_api_key}, json=body,
                                timeout=aiohttp.ClientTimeout(total=5)) as r:
            return bool((await r.json(content_type=None)).get("matches"))
    except Exception as e:  # noqa: BLE001
        log.debug("gsb: %s", e)
        return False


async def urlhaus_check(session, url: str) -> bool:
    if not config.urlhaus_key:
        return False
    try:
        async with session.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url},
                                headers={"Auth-Key": config.urlhaus_key},
                                timeout=aiohttp.ClientTimeout(total=5)) as r:
            return (await r.json(content_type=None)).get("query_status") == "ok"
    except Exception as e:  # noqa: BLE001
        log.debug("urlhaus: %s", e)
        return False


async def vt_url(session, url: str) -> tuple[int, int, int] | None:
    """(malicious, suspicious, jami) dvijoklar soni yoki None."""
    if not config.vt_api_key:
        return None
    h = {"x-apikey": config.vt_api_key}
    uid = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    try:
        async with session.get(f"https://www.virustotal.com/api/v3/urls/{uid}", headers=h,
                               timeout=aiohttp.ClientTimeout(total=6)) as r:
            if r.status == 200:
                st = (await r.json())["data"]["attributes"]["last_analysis_stats"]
                return st.get("malicious", 0), st.get("suspicious", 0), sum(st.values())
            if r.status != 404:
                return None
        async with session.post("https://www.virustotal.com/api/v3/urls", headers=h, data={"url": url},
                                timeout=aiohttp.ClientTimeout(total=6)) as r:
            if r.status != 200:
                return None
            aid = (await r.json())["data"]["id"]
        deadline = time.monotonic() + config.vt_submit_wait
        while time.monotonic() < deadline:
            await asyncio.sleep(2)
            async with session.get(f"https://www.virustotal.com/api/v3/analyses/{aid}", headers=h,
                                   timeout=aiohttp.ClientTimeout(total=5)) as r:
                a = (await r.json())["data"]["attributes"]
                if a.get("status") == "completed":
                    st = a["stats"]
                    return st.get("malicious", 0), st.get("suspicious", 0), sum(st.values())
    except Exception as e:  # noqa: BLE001
        log.debug("vt url: %s", e)
    return None


# ─────────────────────────── 3) SANDBOX NATIJASINI BAHOLASH ───────────────────────────
_geo_cache: dict[str, tuple[str, str]] = {}


async def geo(session, ip: str) -> tuple[str, str]:
    """(davlat, provayder) — server joylashuvi."""
    if not ip or ip in _geo_cache:
        return _geo_cache.get(ip, ("", ""))
    res = ("", "")
    try:
        async with session.get(f"http://ip-api.com/json/{ip}", params={"fields": "country,org,isp", "lang": "ru"},
                               timeout=aiohttp.ClientTimeout(total=3)) as r:
            d = await r.json(content_type=None)
            res = (d.get("country", ""), d.get("org") or d.get("isp", ""))
    except Exception:  # noqa: BLE001
        pass
    _geo_cache[ip] = res
    return res


def _classify_inputs(inputs: list[dict]) -> set[str]:
    asks = set()
    for i in inputs:
        blob = " ".join(str(i.get(k, "")) for k in ("name", "id", "ph", "ac"))
        t = i.get("type", "")
        if t == "tel" or i.get("ac") == "tel" or re.search(r"phone|telefon|raqam|номер|\+998|mobile", blob):
            if not re.search(r"card|karta|карт", blob):
                asks.add("telefon raqam")
        if t == "password" or "password" in blob or "parol" in blob or "пароль" in blob:
            asks.add("parol")
        if re.search(r"\bcode\b|kod|код|otp|sms", blob) or (i.get("ml") in (4, 5, 6) and i.get("im") == "numeric"):
            asks.add("tasdiqlash kodi")
        if re.search(r"cc-number|card|karta|карт|8600|9860|0000 0000", blob):
            asks.add("karta raqami")
        if re.search(r"cvv|cvc|cc-csc|cc-exp|muddat|срок|mm/yy|oo/yy", blob):
            asks.add("CVV/amal qilish muddati")
        if t == "email" or "email" in blob:
            asks.add("email")
    return asks


async def analyze_sandbox(session, f: Finding, rep) -> None:
    from . import apk as apk_mod
    final = rep.final_url or f.target
    host = urlsplit(final).hostname or ""
    official_tg = _host_matches(host, BRANDS["Telegram"]["domains"])
    d = f.details
    d["final_url"] = final
    d["chain"] = rep.chain
    d["status"] = rep.status
    d["ip"] = rep.ip
    d["title"] = rep.title
    if rep.ip:
        d["country"], d["org"] = await geo(session, rep.ip)
    f.final_url = final if final != f.target else None
    f.screenshot = rep.screenshot

    # Yo'naltirishlar zanjiri
    if len(rep.chain) > 1:
        if len(rep.chain) > 2:
            f.add(10, f"{len(rep.chain) - 1} marta yo'naltirish (redirect) orqali asl manzil yashirilgan")
        best = None
        for hop in rep.chain[1:]:
            hf = static_check(hop)
            if not hf.trusted and (best is None or hf.score > best.score):
                best = hf
        if best and best.score:
            f.score += best.score
            f.tags |= best.tags
            for r in best.reasons:
                if f"yakuniy manzil: {r}" not in f.reasons:
                    f.reasons.append(f"yakuniy manzil: {r}")
                    f.weights[f"yakuniy manzil: {r}"] = best.weights.get(r, 5)

    # Sahifa nimalarni so'rayapti (JS bajarilgandan keyingi haqiqiy DOM)
    asks = _classify_inputs(rep.inputs)
    d["asks"] = sorted(asks)
    low = (rep.title + " " + rep.text[:4000]).lower()
    tg_word = "telegram" in low or "телеграм" in low or "premium" in low
    if not official_tg:
        if rep.tg_api_calls:
            f.add(60, "sahifa fonda haqiqiy Telegram serverlariga ulanmoqda — kiritgan kodingiz bilan "
                      "akkauntingizga kirib olish uchun")
            f.tags.add("tg_steal")
        if "telefon raqam" in asks and (tg_word or "tasdiqlash kodi" in asks):
            f.add(45, "sahifa telefon raqamingizni so'ramoqda (Telegram akkauntini o'g'irlash shabloni)")
            f.tags.add("tg_steal")
        elif "telefon raqam" in asks:
            f.add(15, "sahifa telefon raqam so'ramoqda")
        if "tasdiqlash kodi" in asks:
            f.add(25, "sahifa SMS/Telegram tasdiqlash kodini so'ramoqda")
    bank_host = any(_host_matches(host, b["domains"]) for b in BRANDS.values())
    if not bank_host and ({"karta raqami", "CVV/amal qilish muddati"} & asks):
        f.add(45 if "CVV/amal qilish muddati" in asks else 30,
              "sahifa bank karta ma'lumotlarini so'ramoqda (" + ", ".join(sorted(asks & {"karta raqami", "CVV/amal qilish muddati"})) + ")")
        f.tags.add("card")
    if rep.html:
        analyze_html(f, rep.html, host, skip_forms=True)

    # Sahifa yuklatgan fayllar — o'rnatilmasdan tahlil qilinadi
    if rep.downloads:
        d["downloads"] = [x["name"] for x in rep.downloads]
        for x in rep.downloads:
            ff = await apk_mod.analyze_file(session, x["name"], x["data"], x["size"])
            f.add(max(30, ff.score // 2), f"sahifa ochilishi bilan fayl yuklatdi: {x['name']}")
            for r in ff.top_reasons(3):
                key = f"{x['name']}: {r}"
                if key not in f.reasons:
                    f.reasons.append(key)
                    f.weights[key] = ff.weights.get(r, 5)
            f.tags.add("apk")
            if ff.hard or ff.score >= config.malicious_threshold:
                f.mark_hard(f"yuklatilgan fayl ({x['name']}) zararli dastur", tag="apk")
    if rep.error and not rep.ok:
        d["error"] = rep.error


# ─────────────────────────── 4) TO'LIQ TEKSHIRUV ───────────────────────────
async def deep_check(session, url: str) -> Finding:
    """Kontekstsiz (keshlanadigan) to'liq tahlil. Havola sandbox brauzerda ochiladi."""
    hit = _cache.get(url)
    if hit and time.time() - hit[0] < _CACHE_TTL:
        return hit[1].copy()

    f = static_check(url)
    host = urlsplit(url).hostname or ""
    user_content = any(host == h or host.endswith("." + h) for h in USER_CONTENT_HOSTS)
    if f.trusted:
        f.details["official"] = True

    async def _content():
        if f.trusted and not user_content:
            return  # rasmiy sayt — brauzerda ochish shart emas
        if config.sandbox:
            from .sandbox import sandbox
            rep = await sandbox.visit(url)
            f.checks["sandbox"] = "ochildi" if rep.ok else "ochilmadi"
            if not rep.ok:
                err = rep.error or ""
                f.details["error"] = ("domen ishlamayapti yoki ichki tarmoqqa yo'naltirilgan"
                                      if "BLOCKED_BY_CLIENT" in err or "NAME_NOT_RESOLVED" in err else
                                      "sayt javob bermadi" if "TIMED_OUT" in err or "Timeout" in err else
                                      "sayt ochilmadi")
            if rep.ok or rep.downloads:
                await analyze_sandbox(session, f, rep)
                return
        # zaxira: oddiy HTTP (JS bajarilmaydi)
        if config.fetch_pages:
            chain, final, html, ctype = await fetch_chain(session, url)
            f.details["chain"] = chain
            f.details["final_url"] = final
            if final != url:
                f.final_url = final
                hf = static_check(final)
                if not hf.trusted and hf.score:
                    f.score += hf.score
                    f.tags |= hf.tags
                    f.reasons += [f"yakuniy manzil: {r}" for r in hf.reasons if f"yakuniy manzil: {r}" not in f.reasons]
            if "android.package-archive" in ctype:
                f.add(50, "havola telefonga APK fayl yuklatadi")
                f.tags.add("apk")
            if html:
                analyze_html(f, html, urlsplit(final).hostname or "")

    async def _reputation():
        await refresh_feeds(session)
        hit_feed = feed_hit(url)
        f.checks["fishing bazalari"] = "TOPILDI" if hit_feed else ("topilmadi" if _feed_urls else "yuklanmagan")
        if hit_feed:
            f.mark_hard("ochiq fishing/zararli URL bazalarida (OpenPhish/URLhaus) ro'yxatga olingan")
        gsb, uh, vt = await asyncio.gather(gsb_check(session, [url]), urlhaus_check(session, url),
                                           vt_url(session, url))
        f.checks["Google Safe Browsing"] = ("XAVFLI" if gsb else "toza") if config.gsb_api_key else "kalit yo'q"
        f.checks["URLhaus"] = ("XAVFLI" if uh else "toza") if config.urlhaus_key else "kalit yo'q"
        if gsb:
            f.mark_hard("Google Safe Browsing: xavfli sayt deb belgilangan")
        if uh:
            f.mark_hard("URLhaus: zararli dastur tarqatuvchi manzil")
        if not config.vt_api_key:
            f.checks["VirusTotal"] = "kalit yo'q"
        elif vt is None:
            f.checks["VirusTotal"] = "natija olinmadi"
        else:
            mal, sus, tot = vt
            f.checks["VirusTotal"] = f"{mal + sus}/{tot} antivirus"
            if mal >= 2:
                f.mark_hard(f"VirusTotal: {mal} ta antivirus xavfli deb topdi")
            elif mal == 1 or sus >= 2:
                f.add(35, f"VirusTotal: {mal + sus} ta antivirus shubhali deb belgiladi")

    async def _age():
        reg = registered_domain(host)
        if f.trusted or _host_matches(host, FREE_HOSTING) or reg in SHORTENERS:
            return
        age = await domain_age_days(session, reg)
        f.details["age_days"] = age
        if age is not None and age < 14:
            f.add(35, f"domen atigi {age} kun oldin ro'yxatdan o'tgan")
        elif age is not None and age < 60:
            f.add(15, f"domen yangi ({age} kunlik)")

    for r in await asyncio.gather(_content(), _reputation(), _age(), return_exceptions=True):
        if isinstance(r, Exception):
            log.warning("deep_check %s: %r", url, r)

    # Yakuniy manzilni ham bazalar bo'yicha tekshirish
    if f.final_url and not f.hard:
        if feed_hit(f.final_url) or await gsb_check(session, [f.final_url]):
            f.mark_hard("yakuniy manzil xavfli saytlar bazasida")
        else:
            fh = urlsplit(f.final_url).hostname or ""
            freg = registered_domain(fh)
            if freg != registered_domain(host) and not is_trusted(f.final_url) and not _host_matches(fh, FREE_HOSTING):
                age = await domain_age_days(session, freg)
                f.details["final_age_days"] = age
                if age is not None and age < 14:
                    f.add(35, f"yakuniy domen atigi {age} kun oldin ochilgan")

    _cache[url] = (time.time(), f)
    if len(_cache) > 3000:
        for k in sorted(_cache, key=lambda k: _cache[k][0])[:600]:
            _cache.pop(k, None)
    return f.copy()
