"""Oflayn testlar: python -m pytest -q  (tarmoq so'rovlari mock qilingan)"""
import asyncio
import io
import os
import zipfile

os.environ.update(FEEDS="0", BOT_TOKEN="1:x", SANDBOX="0")

import pytest  # noqa: E402
from aiogram.types import Message  # noqa: E402

from guard.scanner import apk as apk_mod  # noqa: E402
from guard.scanner import engine, url as url_mod  # noqa: E402
from guard.scanner.extract import from_text  # noqa: E402

PAGES: dict[str, str] = {}


async def fake_chain(session, u, max_hops=6):
    return [u], u, PAGES.get(u), "text/html" if u in PAGES else ""


async def no_age(session, d):
    return None


url_mod.fetch_chain = fake_chain
url_mod.domain_age_days = no_age


def msg(text=None, buttons=None, via_bot=False, caption=None, entities=None, document=None):
    data = {"message_id": 1, "date": 0, "chat": {"id": -100, "type": "supergroup", "title": "G"},
            "from": {"id": 5, "is_bot": False, "first_name": "Nigor"}}
    if text is not None:
        data["text"] = text
    if caption is not None:
        data["caption"] = caption
        data["photo"] = [{"file_id": "a", "file_unique_id": "b", "width": 1, "height": 1}]
    if entities:
        data["entities"] = entities
    if buttons:
        data["reply_markup"] = {"inline_keyboard": [[{"text": t, "url": u} for t, u in buttons]]}
    if via_bot:
        data["via_bot"] = {"id": 7, "is_bot": True, "first_name": "PostBot", "username": "PostBot"}
    if document:
        data["document"] = document
    return Message.model_validate(data)


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro) if False else asyncio.run(coro)


def scan(m, **kw):
    async def _go():
        try:
            return await engine.scan_message(None, m, **kw)
        finally:
            await engine.close()
            engine._session = None
    return asyncio.run(_go())


def test_screenshot_nbu_case():
    """Rasmdagi hujum: @PostBot orqali «NBU 70 000 so'm sovg'a», «OLING» tugmasi."""
    m = msg(caption="", buttons=[("OLING", "https://nbu-sovga.xyz/olish")], via_bot=True)
    v = scan(m, extra_context="Sizlar ham olinglar, menga ham berishdi")
    assert v.level == "malicious", v.findings[0].reasons


def test_generic_domain_with_tg_login_page():
    u = "https://gift-uz.site/claim"
    PAGES[url_mod.normalize(u) if hasattr(url_mod, "normalize") else u] = (
        "<html><title>Telegram Premium</title><body>Telegram Premium sovg'a! "
        "<input type='tel' placeholder='Telefon raqam'> Kodni kiriting"
        "<script src='telegram.min.js'></script></body></html>")
    m = msg(buttons=[("OLING", u)], via_bot=True)
    v = scan(m)
    assert v.level == "malicious", v.findings[0].reasons


def test_official_sites_safe():
    for t in ["NBU sovg'a aksiyasi haqida: https://nbu.uz/uz/news", "https://www.youtube.com/watch?v=abc",
              "Yangiliklar: https://kun.uz/news/2026/11/25/xyz", "https://t.me/kunuzofficial"]:
        v = scan(msg(text=t))
        assert v.level == "safe", (t, [f.reasons for f in v.findings])


def test_obfuscated_and_homoglyph():
    assert "nbu-bonus.top" in " ".join(from_text("bonusni oling: nbu-bonus[.]top"))
    assert scan(msg(text="Telegram premium bepul: https://teIegram-premium.com/login")).level == "malicious"
    assert scan(msg(text="https://tеlegram.org/auth")).level != "safe"  # kirillcha «е»


def test_vote_scam():
    v = scan(msg(text="Iltimos, jiyanimga ovoz bering 🙏 https://konkurs-golos.online/vote?id=12"))
    assert v.level == "malicious"


def test_plain_text_never_deleted():
    assert scan(msg(text="Menga ham berishdi, sovg'a oling!")).level == "safe"


def _fake_apk(perms=(), dex=b""):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00" + b"".join(
            f"android.permission.{p}".encode("utf-16-le") for p in perms))
        z.writestr("classes.dex", b"dex\n035\x00" + dex)
    return buf.getvalue()


def test_sms_stealer_apk():
    data = _fake_apk(["RECEIVE_SMS", "READ_SMS", "SEND_SMS", "READ_CONTACTS"],
                     b"https://api.telegram.org/bot1234567890:AAH" + b"x" * 32 + b"/sendMessage content://sms")
    f = asyncio.run(apk_mod.analyze_file(None, "Rasmlar.apk", data, len(data)))
    assert f.level(70, 40) == "malicious", f.reasons


def test_disguised_apk():
    data = _fake_apk(["READ_SMS"])
    f = asyncio.run(apk_mod.analyze_file(None, "photo_2026.jpg", data, len(data)))
    assert f.level(70, 40) != "safe"


def test_clean_apk_is_suspicious_not_hard():
    data = _fake_apk([])
    f = asyncio.run(apk_mod.analyze_file(None, "myapp.apk", data, len(data)))
    assert f.level(70, 40) == "suspicious"


if __name__ == "__main__":
    pytest.main([__file__, "-q"])


LEGIT_SPA = """<html><head><title>Smart QR Feedback</title>
<script type="module" src="/assets/index-abc.js"></script></head><body><div id="root">
<h1>Smart QR Feedback</h1><p>Har bir fikr muhim. Mijozlar fikrini QR orqali yig'ing.</p>
<form><input type="tel" name="phone" placeholder="Telefon raqamingiz"><textarea name="text"></textarea></form>
<p>Bildirishnomalar Telegram orqali keladi.</p></div>
<script>import {createClient} from 'supabase'; supabase.auth.signInWithPassword({}); import './telegram.js';
fetch('https://api.telegram.org/bot123/sendMessage')</script></body></html>"""


def test_legit_vercel_app_is_safe():
    """Foydalanuvchining halol sayti (vercel.app, Supabase login, Telegram bildirishnoma) xavfli bo'lmasligi kerak."""
    u = "https://smart-qr-feedback.vercel.app/"
    PAGES[u] = LEGIT_SPA
    v = scan(msg(text="smart-qr-feedback.vercel.app"))
    assert v.level == "safe", [(f.score, f.reasons) for f in v.findings]


def test_real_tg_phishing_on_vercel_still_caught():
    u = "https://tg-premium-gift.vercel.app/"
    PAGES[u] = ("<title>Telegram Premium</title>Telegram Premium bepul! <input type=tel> Kodni kiriting"
                "<script>const {StringSession}=gramjs; client.invoke(new Api.auth.sendCode({api_hash: H}))</script>")
    v = scan(msg(text="Premium bepul oling: https://tg-premium-gift.vercel.app/"))
    assert v.level == "malicious", [(f.score, f.reasons) for f in v.findings]


def test_content_only_never_malicious():
    """Faqat taxminiy belgilar (kuchli dalilsiz) — ko'pi bilan «shubhali»."""
    u = "https://my-shop-demo.netlify.app/checkout"
    PAGES[u] = "<title>Do'kon</title><input name=card placeholder='8600 0000 0000 0000'><input name=cvv> bonus promo"
    v = scan(msg(text=u))
    assert v.level != "malicious", [(f.score, f.reasons) for f in v.findings]
