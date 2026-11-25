"""Admin panel (faqat OWNER_IDS dagi foydalanuvchilar uchun): /admin"""
from __future__ import annotations

import asyncio
import html
import time
from datetime import datetime, timedelta, timezone

from aiogram import Bot, F, Router
from aiogram.enums import ChatType
from aiogram.filters import Command
from aiogram.types import CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup, Message

from .. import db
from ..config import config
from ..scanner import url as url_mod

router = Router(name="admin")
router.message.filter(F.chat.type == ChatType.PRIVATE, F.from_user.id.func(lambda i: i in config.owner_ids))
router.callback_query.filter(F.from_user.id.func(lambda i: i in config.owner_ids))

STARTED = time.time()
TZ = timezone(timedelta(hours=5))
_broadcast: dict[int, str] = {}   # admin_id -> "users" | "groups"


def _e(x) -> str:
    return html.escape(str(x), quote=False)


def menu() -> InlineKeyboardMarkup:
    b = InlineKeyboardButton
    return InlineKeyboardMarkup(inline_keyboard=[
        [b(text="📊 Statistika", callback_data="adm:stats"), b(text="🧾 So'nggi hodisalar", callback_data="adm:events")],
        [b(text="👥 Guruh va kanallar", callback_data="adm:chats"), b(text="⚙️ Tizim holati", callback_data="adm:sys")],
        [b(text="📣 Foydalanuvchilarga xabar", callback_data="adm:bc:users"),
         b(text="📣 Guruhlarga xabar", callback_data="adm:bc:groups")],
        [b(text="✅ Ishonchli saytlar", callback_data="adm:trusted"), b(text="🔄 Yangilash", callback_data="adm:stats")],
    ])


def back() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="⬅️ Orqaga", callback_data="adm:home")]])


async def stats_text() -> str:
    o = await db.overview()
    up = timedelta(seconds=int(time.time() - STARTED))
    return ("🛡 <b>Admin panel — statistika</b>\n\n"
            f"👥 Himoyadagi guruhlar: <b>{o['groups']}</b>\n"
            f"📢 Kanallar: <b>{o['channels']}</b>\n"
            f"⚠️ Admin huquqi berilmagan: <b>{o['no_admin']}</b>\n"
            f"👤 Bot foydalanuvchilari: <b>{o['users']}</b>\n"
            f"📱 Shaxsiy chat himoyasi (Business): <b>{o['business']}</b>\n\n"
            f"🔎 Tekshirilgan xabarlar: <b>{o['scanned']}</b>\n"
            f"⛔️ O'chirilgan xavfli xabarlar: <b>{o['deleted']}</b>\n"
            f"📅 Bugun aniqlangan: <b>{o['today']}</b> · 7 kunda: <b>{o['week']}</b>\n\n"
            f"⏱ Ishlash vaqti: {up}")


@router.message(Command("admin"))
async def cmd_admin(m: Message):
    _broadcast.pop(m.from_user.id, None)
    await m.answer(await stats_text(), reply_markup=menu())


@router.callback_query(F.data == "adm:home")
@router.callback_query(F.data == "adm:stats")
async def cb_stats(c: CallbackQuery):
    _broadcast.pop(c.from_user.id, None)
    try:
        await c.message.edit_text(await stats_text(), reply_markup=menu())
    except Exception:  # noqa: BLE001
        pass
    await c.answer()


@router.callback_query(F.data == "adm:events")
async def cb_events(c: CallbackQuery):
    rows = await db.recent_events(12)
    lines = ["🧾 <b>So'nggi aniqlangan xavflar</b>\n"]
    icon = {"malicious": "⛔️", "suspicious": "⚠️", "safe": "🚫"}
    for eid, ts, chat_id, title, target, level, score in rows:
        t = datetime.fromtimestamp(ts, TZ).strftime("%d.%m %H:%M")
        where = _e(title[:25]) if title else ("shaxsiy chat" if chat_id and chat_id > 0 else str(chat_id))
        tgt = _e(target.replace("http://", "").replace("https://", "").replace(".", "[.]")[:45])
        lines.append(f"{icon.get(level, '•')} {t} · {where}\n   <code>{tgt}</code> · {min(score, 100)}/100 · /r_{eid}")
    if len(lines) == 1:
        lines.append("Hozircha hodisa yo'q.")
    await c.message.edit_text("\n".join(lines), reply_markup=back())
    await c.answer()


@router.message(F.text.regexp(r"^/r_(\d+)$"))
async def cmd_report(m: Message):
    row = await db.get_event(int(m.text[3:]))
    await m.answer(row[6] if row and row[6] else "Hisobot topilmadi.", disable_web_page_preview=True)


@router.callback_query(F.data == "adm:chats")
async def cb_chats(c: CallbackQuery):
    rows = await db.list_chats(30)
    lines = ["👥 <b>Himoyadagi guruh va kanallar</b>\n"]
    for chat_id, title, ctype, is_admin, scanned, deleted in rows:
        mark = "✅" if is_admin else "⚠️"
        kind = "📢" if ctype == "channel" else "👥"
        lines.append(f"{mark}{kind} {_e((title or str(chat_id))[:35])}\n   ID <code>{chat_id}</code> · "
                     f"tekshirildi {scanned} · o'chirildi {deleted}")
    if len(lines) == 1:
        lines.append("Bot hali hech qaysi guruhga qo'shilmagan.")
    lines.append("\n⚠️ = botga admin huquqi berilmagan")
    await c.message.edit_text("\n".join(lines)[:4000], reply_markup=back())
    await c.answer()


@router.callback_query(F.data == "adm:sys")
async def cb_sys(c: CallbackQuery):
    def onoff(x):
        return "✅ yoqilgan" if x else "❌ o'chiq"
    sb = "❌ o'chiq"
    if config.sandbox:
        from ..scanner.sandbox import sandbox
        sb = "✅ ishlamoqda" if sandbox._browser and sandbox._browser.is_connected() else "🟡 kutish rejimida"
    text = ("⚙️ <b>Tizim holati</b>\n\n"
            f"🔬 Sandbox brauzer: {sb}\n"
            f"📚 Fishing bazalari: {len(url_mod._feed_urls)} ta URL, {len(url_mod._feed_hosts)} ta domen\n"
            f"🧪 VirusTotal: {onoff(config.vt_api_key)}\n"
            f"🧪 Google Safe Browsing: {onoff(config.gsb_api_key)}\n"
            f"🧪 URLhaus API: {onoff(config.urlhaus_key)}\n"
            f"🗂 URL kesh: {len(url_mod._cache)} ta\n"
            f"🎚 Chegaralar: xavfli ≥ {config.malicious_threshold}, shubhali ≥ {config.suspicious_threshold}")
    await c.message.edit_text(text, reply_markup=back())
    await c.answer()


@router.callback_query(F.data.startswith("adm:bc:"))
async def cb_broadcast(c: CallbackQuery):
    target = c.data.split(":")[2]
    _broadcast[c.from_user.id] = target
    who = "barcha bot foydalanuvchilariga" if target == "users" else "barcha himoyadagi guruhlarga"
    await c.message.edit_text(f"📣 Yuboriladigan xabarni jo'nating (matn, rasm, video — istalgan turi).\n"
                              f"U {who} nusxalanadi.\n\nBekor qilish: /admin", reply_markup=back())
    await c.answer()


@router.message(F.func(lambda m: m.from_user and m.from_user.id in _broadcast and not (m.text or "").startswith("/")))
async def do_broadcast(m: Message, bot: Bot):
    target = _broadcast.pop(m.from_user.id)
    ids = await db.all_ids(target)
    status = await m.answer(f"⏳ Yuborilmoqda: 0/{len(ids)}")
    ok = fail = 0
    for i, cid in enumerate(ids, 1):
        try:
            await bot.copy_message(cid, m.chat.id, m.message_id)
            ok += 1
        except Exception:  # noqa: BLE001
            fail += 1
            if target == "users":
                await db.set_user_blocked(cid)
        await asyncio.sleep(0.05)
        if i % 50 == 0:
            try:
                await status.edit_text(f"⏳ Yuborilmoqda: {i}/{len(ids)}")
            except Exception:  # noqa: BLE001
                pass
    await status.edit_text(f"✅ Yuborildi: {ok}\n❌ Yetkazilmadi: {fail}", reply_markup=back())


def _clean_host(raw: str) -> str:
    from ..scanner.extract import normalize
    from urllib.parse import urlsplit
    n = normalize(raw.strip())
    return (urlsplit(n).hostname or "") if n else ""


def _trusted_text() -> str:
    items = sorted(url_mod.EXTRA_TRUSTED)
    body = "\n".join(f"• <code>{_e(x)}</code>" for x in items) or "Hozircha bo'sh."
    return ("✅ <b>Ishonchli saytlar</b>\nBu saytlar (va ularning subdomenlari) xavfli deb topilmaydi.\n\n" + body +
            "\n\nQo'shish: <code>/trust sayt.uz</code>\nO'chirish: <code>/untrust sayt.uz</code>")


@router.callback_query(F.data == "adm:trusted")
async def cb_trusted(c: CallbackQuery):
    await c.message.edit_text(_trusted_text(), reply_markup=back())
    await c.answer()


@router.message(Command("trust"))
async def cmd_trust(m: Message):
    from ..scanner.data import FREE_HOSTING, SHORTENERS
    from ..scanner.extract import split_host
    arg = (m.text or "").split(maxsplit=1)
    host = _clean_host(arg[1]) if len(arg) > 1 else ""
    if not host:
        return await m.answer("Foydalanish: <code>/trust smart-qr-feedback.vercel.app</code>")
    ext = split_host(host)
    # Umumiy hostinglarni butunlay ishonchli qilib bo'lmaydi (u yerda firibgarlar ham sayt ochadi)
    if host in FREE_HOSTING or host in SHORTENERS or not ext.domain or host == ext.suffix:
        return await m.answer("⚠️ Bu umumiy hosting/qisqartiruvchi domen — uni to'liq ishonchli qilib bo'lmaydi. "
                              "Aniq saytingiz manzilini kiriting, masalan <code>mening-saytim.vercel.app</code>.")
    url_mod.EXTRA_TRUSTED.add(host)
    await db.save_trusted(url_mod.EXTRA_TRUSTED)
    for k in [k for k in url_mod._cache if host in k]:
        url_mod._cache.pop(k, None)
    await m.answer(f"✅ <code>{_e(host)}</code> ishonchli saytlar ro'yxatiga qo'shildi.\n\n" + _trusted_text())


@router.message(Command("untrust"))
async def cmd_untrust(m: Message):
    arg = (m.text or "").split(maxsplit=1)
    host = _clean_host(arg[1]) if len(arg) > 1 else ""
    if host in url_mod.EXTRA_TRUSTED:
        url_mod.EXTRA_TRUSTED.discard(host)
        await db.save_trusted(url_mod.EXTRA_TRUSTED)
        url_mod._cache.clear()
        await m.answer(f"🗑 <code>{_e(host)}</code> ro'yxatdan olib tashlandi.")
    else:
        await m.answer("Bu sayt ro'yxatda yo'q.\n\n" + _trusted_text())
