"""Ogohlantirish matnlari va umumiy amallar."""
from __future__ import annotations

import asyncio
import html
import logging
from urllib.parse import urlsplit

from .config import config
from .scanner.result import MALICIOUS, SUSPICIOUS, Verdict

log = logging.getLogger(__name__)


def defang(target: str) -> str:
    """Havolani bosib bo'lmaydigan ko'rinishga keltiradi: example[.]com"""
    if target.startswith("http"):
        p = urlsplit(target)
        host = (p.hostname or "").replace(".", "[.]")
        path = p.path if len(p.path) < 40 else p.path[:37] + "..."
        return host + ("" if path in ("", "/") else path)
    return target


def mention(user=None, chat=None) -> str:
    if user:
        name = html.escape(user.full_name or "foydalanuvchi")
        return f'<a href="tg://user?id={user.id}">{name}</a>'
    if chat:
        return f"<b>{html.escape(chat.title or chat.full_name or 'kanal')}</b>"
    return "noma'lum"


THREATS = {
    "tg_steal": "Telegram akkauntini o'g'irlash",
    "card": "bank karta ma'lumotlarini o'g'irlash",
    "apk": "telefonga zararli ilova (APK) o'rnatish",
    "known": "xavfli saytlar bazasida ro'yxatga olingan",
}


def threat_name(f) -> str:
    names = [THREATS[t] for t in ("tg_steal", "card", "apk", "known") if t in f.tags]
    if "brand" in f.tags:
        names.append(f"«{f.details.get('brand', 'brend')}» nomidan soxta sayt")
    return ", ".join(names[:3])


def _e(x) -> str:
    return html.escape(str(x), quote=False)


def finding_block(f, full: bool = True) -> str:
    lvl = f.level(config.malicious_threshold, config.suspicious_threshold)
    mark = {"safe": "✅", "suspicious": "⚠️", "malicious": "⛔️"}[lvl]
    d = f.details
    icon = "📦" if f.kind == "file" else "🔗"
    out = [f"{icon} <code>{_e(defang(f.target))}</code>"]
    if d.get("official"):
        out.append("   🏛 Rasmiy/ishonchli domen")
    if f.final_url:
        hops = max(0, len(d.get("chain", [])) - 1)
        out.append(f"   ↪️ Yakuniy manzil: <code>{_e(defang(f.final_url))}</code>"
                   + (f" ({hops} ta yo'naltirish)" if hops else ""))
    if d.get("ip"):
        loc = ", ".join(x for x in (d.get("country"), d.get("org")) if x)
        out.append(f"   🌐 Server: {_e(d['ip'])}" + (f" — {_e(loc)}" if loc else ""))
    if d.get("age_days") is not None:
        out.append(f"   📅 Domen yoshi: {d['age_days']} kun")
    if d.get("title"):
        out.append(f"   📄 Sahifa sarlavhasi: «{_e(d['title'][:70])}»")
    if d.get("asks"):
        out.append(f"   🎯 Sahifa so'raydi: <b>{_e(', '.join(d['asks']))}</b>")
    if d.get("downloads"):
        out.append(f"   📥 Yuklatadi: {_e(', '.join(d['downloads'][:3]))}")
    if d.get("error"):
        out.append(f"   🔌 {_e(d['error'])} — sahifa mazmunini tekshirib bo'lmadi, faqat domen va bazalar tekshirildi")
    if f.checks and full:
        out.append("   🧪 " + " · ".join(f"{_e(k)}: {_e(v)}" for k, v in f.checks.items()))
    th = threat_name(f)
    if th and lvl != "safe":
        out.append(f"   🏷 Tahdid: <b>{_e(th)}</b>")
    out.append(f"   {mark} Xavf bali: <b>{min(f.score, 100)}/100</b>")
    n = 6 if full else 3
    for r in f.top_reasons(n):
        out.append(f"   • {_e(r)}")
    return "\n".join(out)


def warning_text(v: Verdict, who: str, *, private: bool = False, pending: bool = False) -> str:
    mal, sus = config.malicious_threshold, config.suspicious_threshold
    bad = [f for f in v.findings if f.level(mal, sus) != "safe"] or v.findings
    is_file = any(f.kind == "file" for f in bad)
    head = "⛔️ <b>Xavfli fayl o'chirildi!</b>" if is_file else "⛔️ <b>Xavfli havola o'chirildi!</b>"
    if v.level == SUSPICIOUS and not v.policy_block:
        head = "⚠️ <b>Shubhali havola o'chirildi</b>"
    if v.policy_block and v.level != MALICIOUS:
        head = "🚫 <b>APK fayl o'chirildi</b>"
    lines = [head, f"👤 Yuboruvchi: {who}"]
    if v.policy_block:
        lines.append(f"📌 {_e(v.policy_block)}")
    lines.append("")
    for f in bad[:3]:
        lines += [finding_block(f, full=False), ""]
    if pending:
        lines.append("🔬 <i>Havola xavfsiz muhitda (sandbox) ochilmoqda, batafsil ma'lumot shu yerda chiqadi...</i>")
    if is_file:
        lines.append("❗️ Bunday ilovalar o'rnatilsa SMS-kodlar, bank kartalari va Telegram akkauntini o'g'irlaydi. "
                     "Noma'lum APK'ni hech qachon o'rnatmang.")
    else:
        lines.append("❗️ Havolani ochmang. Hech kimga SMS/Telegram kodini va karta ma'lumotlarini bermang.")
    if not private:
        lines.append("💡 Yuboruvchining akkaunti buzilgan bo'lishi mumkin: <i>Sozlamalar → Qurilmalar → "
                     "Boshqa seanslarni yakunlash</i>, so'ng 2 bosqichli parolni yoqing.")
    lines.append("🛡 <i>Tekshiruv bot serverida, izolyatsiyalangan brauzerda bajarildi — "
                 "hech kimning akkaunti yoki telefoni ishtirok etmadi.</i>")
    return "\n".join(lines)[:4000]


def group_warning(v: Verdict, who: str, *, private: bool = False, pending: bool = False) -> str:
    """Guruh/chat uchun qisqa ogohlantirish: havola o'chirildi + asosiy sabab."""
    mal, sus = config.malicious_threshold, config.suspicious_threshold
    bad = [f for f in v.findings if f.level(mal, sus) != "safe"] or v.findings
    is_file = any(f.kind == "file" for f in bad)
    what = "fayl" if is_file else "havola"
    if v.policy_block and v.level != MALICIOUS:
        head = "🚫 <b>APK fayl o'chirildi</b>"
    elif v.level == SUSPICIOUS:
        head = f"⚠️ <b>Shubhali {what} o'chirildi</b>"
    else:
        head = f"⛔️ <b>Xavfli {what} o'chirildi!</b>"
    lines = [head, f"👤 {who} yuborgan xabar o'chirildi."]
    for f in bad[:2]:
        lines.append(f"{'📦' if f.kind == 'file' else '🔗'} <code>{_e(defang(f.target))}</code>")
        if f.final_url:
            lines.append(f"↪️ aslida: <code>{_e(defang(f.final_url))}</code>")
    w = max(bad, key=lambda x: (x.hard, x.score), default=None)
    if w:
        th = threat_name(w)
        if th:
            lines.append(f"🏷 <b>{_e(th[:1].upper() + th[1:])}</b>")
        if w.details.get("asks"):
            lines.append(f"🎯 Sahifa so'raydi: {_e(', '.join(w.details['asks']))}")
        top = w.top_reasons(2)
        if v.policy_block:
            top = [v.policy_block] + top[:1]
        if top:
            lines.append("📌 " + _e("; ".join(top)))
    if pending:
        lines.append("🔬 <i>Sandbox tekshiruvi davom etmoqda...</i>")
    lines.append("")
    lines.append("❗️ Bunday ilovani o'rnatmang." if is_file else
                 "❗️ Havolani ochmang. Kod, parol va karta ma'lumotini hech kimga bermang.")
    if not private:
        lines.append("💡 Yuboruvchi akkaunti buzilgan bo'lishi mumkin: Sozlamalar → Qurilmalar → "
                     "boshqa seanslarni yakunlang.")
    return "\n".join(lines)[:4000]


_me_username: str | None = None


async def details_button(bot, event_id: int | None):
    from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup
    global _me_username
    if not event_id:
        return None
    if not _me_username:
        try:
            _me_username = (await bot.me()).username
        except Exception:  # noqa: BLE001
            return None
    return InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(
        text="🔍 Batafsil hisobot", url=f"https://t.me/{_me_username}?start=r_{event_id}")]])


ADVICE = {
    "tg_steal": "Bu saytga telefon raqam yoki Telegram kodini kiritmang. Kiritgan bo'lsangiz: Sozlamalar → "
                "Qurilmalar → «Boshqa seanslarni yakunlash», keyin 2 bosqichli parolni yoqing.",
    "card": "Karta ma'lumotlarini kiritmang. Kiritgan bo'lsangiz, bankka qo'ng'iroq qilib kartani bloklang.",
    "apk": "Faylni o'rnatmang. O'rnatgan bo'lsangiz: internetni o'chiring, ilovani o'chiring va bankingizga xabar bering.",
}


def report_text(v: Verdict) -> str:
    """Foydalanuvchi uchun sodda hisobot: nima, nega xavfli, nima qilish kerak. Texnik tafsilotlarsiz."""
    if not v.findings:
        return "Xabarda havola yoki fayl topilmadi."
    mal, sus = config.malicious_threshold, config.suspicious_threshold
    head = {"safe": "✅ <b>Xavfli belgi topilmadi</b>", "suspicious": "⚠️ <b>Ehtiyot bo'ling — shubhali</b>",
            "malicious": "⛔️ <b>XAVFLI — ochmang!</b>"}[v.level]
    out = [head]
    tags: set = set()
    for f in v.findings[:5]:
        lvl = f.level(mal, sus)
        d = f.details
        out.append("")
        out.append(f"{'📦' if f.kind == 'file' else '🔗'} <code>{_e(defang(f.target))}</code>")
        if d.get("official"):
            out.append("🏛 Rasmiy sayt")
        if f.final_url:
            out.append(f"↪️ Aslida boshqa saytga olib boradi: <code>{_e(defang(f.final_url))}</code>")
        if lvl == "safe":
            if d.get("title"):
                out.append(f"📄 «{_e(d['title'][:70])}»")
            continue
        tags |= f.tags
        th = threat_name(f)
        if th:
            out.append(f"🏷 <b>{_e(th[:1].upper() + th[1:])}</b>")
        if d.get("asks"):
            out.append(f"🎯 Sizdan so'raydi: {_e(', '.join(d['asks']))}")
        if d.get("downloads"):
            out.append(f"📥 Telefoningizga yuklatadi: {_e(', '.join(d['downloads'][:2]))}")
        reasons = [r for r in f.top_reasons(4) if f.weights.get(r, 5) >= 10][:3]
        if reasons:
            out.append("📌 Nega:")
            out += [f"• {_e(r)}" for r in reasons]
    out.append("")
    if v.level == "safe":
        out.append("Shunday bo'lsa ham, kod va parolni hech kimga bermang.")
    else:
        tips = [ADVICE[t] for t in ("tg_steal", "card", "apk") if t in tags]
        out.append("💡 " + (tips[0] if tips else "Havolani ochmang va hech qanday ma'lumot kiritmang."))
    return "\n".join(out)[:4000]


def admin_report(v: Verdict) -> str:
    """Admin uchun to'liq texnik hisobot (server, bazalar, ball)."""
    out = [report_text(v), "", "— texnik ma'lumot —"]
    for f in v.findings[:5]:
        out += [finding_block(f, full=True), ""]
    return "\n".join(out)[:4000]


def best_screenshot(v: Verdict):
    if v.level == "safe":
        return None
    for f in sorted(v.findings, key=lambda x: (x.hard, x.score), reverse=True):
        if f.screenshot:
            return f.screenshot
    return None


async def delete_later(bot, chat_id: int, message_id: int, minutes: int, business_connection_id: str | None = None):
    if minutes <= 0:
        return

    async def _job():
        await asyncio.sleep(minutes * 60)
        try:
            if business_connection_id:
                await bot.delete_business_messages(business_connection_id=business_connection_id,
                                                   message_ids=[message_id])
            else:
                await bot.delete_message(chat_id, message_id)
        except Exception:  # noqa: BLE001
            pass
    asyncio.create_task(_job())


async def send_report(bot, chat_id: int, text: str, shot: bytes | None = None, **kw):
    """Skrinshot (bo'lsa) + to'liq matnli hisobot."""
    from aiogram.types import BufferedInputFile
    if shot:
        try:
            await bot.send_photo(chat_id, BufferedInputFile(shot, "sahifa.jpg"),
                                 caption="📸 Sahifa ko'rinishi",
                                 has_spoiler=True, **kw)
        except Exception as e:  # noqa: BLE001
            log.debug("photo: %s", e)
    return await bot.send_message(chat_id, text, disable_web_page_preview=True, **kw)


async def log_to_channel(bot, text: str, shot: bytes | None = None):
    if config.log_chat_id:
        try:
            await send_report(bot, config.log_chat_id, text, shot)
        except Exception as e:  # noqa: BLE001
            log.warning("log channel: %s", e)


# Buzilgan akkauntlar ko'pincha avval matn («menga ham berishdi»), keyin havolali post yuboradi.
# Shuning uchun bir yuboruvchining so'nggi 3 daqiqadagi matni ham kontekst sifatida olinadi.
_recent: dict[tuple[int, int], tuple[float, str]] = {}


def recent_context(m) -> str:
    import time
    sender = (m.from_user.id if m.from_user else 0) or (m.sender_chat.id if m.sender_chat else 0)
    key = (m.chat.id, sender)
    prev = _recent.get(key)
    txt = m.text or m.caption
    if txt:
        _recent[key] = (time.time(), txt[:500])
        if len(_recent) > 20000:
            _recent.clear()
    if prev and time.time() - prev[0] < 180 and prev[1] != txt:
        return prev[1]
    return ""


def purge_recent():
    import time
    now = time.time()
    for k in [k for k, (ts, _) in _recent.items() if now - ts > 180]:
        _recent.pop(k, None)
