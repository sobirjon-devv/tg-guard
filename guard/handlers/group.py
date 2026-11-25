"""Guruh va kanallarni 24/7 himoya qilish."""
from __future__ import annotations

import html
import logging
import time
from datetime import timedelta

from aiogram import Bot, F, Router
from aiogram.enums import ChatMemberStatus, ChatType
from aiogram.filters import Command
from aiogram.types import (CallbackQuery, ChatMemberUpdated, ChatPermissions, InlineKeyboardButton,
                           InlineKeyboardMarkup, Message, ReplyParameters)

from .. import db
from ..branding import asset
from ..actions import (best_screenshot, delete_later, details_button, group_warning, log_to_channel, mention,
                       recent_context, admin_report, warning_text)
from ..scanner import apk as apk_mod
from ..scanner.engine import scan_message
from ..scanner.result import MALICIOUS, SUSPICIOUS

log = logging.getLogger(__name__)
router = Router(name="group")
GROUPS = {ChatType.GROUP, ChatType.SUPERGROUP}
_admins: dict[int, tuple[float, set[int]]] = {}


async def admin_ids(bot: Bot, chat_id: int) -> set[int]:
    hit = _admins.get(chat_id)
    if hit and time.time() - hit[0] < 300:
        return hit[1]
    try:
        ids = {m.user.id for m in await bot.get_chat_administrators(chat_id)}
    except Exception:  # noqa: BLE001
        ids = set()
    _admins[chat_id] = (time.time(), ids)
    return ids


def _has_payload(m: Message) -> bool:
    return bool(m.entities or m.caption_entities or m.reply_markup or m.document
                or (m.text and "." in m.text) or (m.caption and "." in m.caption))


_known_chats: set[int] = set()


async def process(bot: Bot, m: Message, *, channel: bool = False):
    if m.chat.id not in _known_chats:
        _known_chats.add(m.chat.id)
        await db.upsert_chat(m.chat.id, m.chat.title or "", m.chat.type)
    extra = recent_context(m)
    if not _has_payload(m):
        return
    s = await db.get_settings(m.chat.id)
    is_admin = channel or bool(m.is_automatic_forward) or (m.sender_chat and m.sender_chat.id == m.chat.id) \
        or (m.from_user and m.from_user.id in await admin_ids(bot, m.chat.id))
    v = await scan_message(bot, m, extra_context=extra)

    if m.document and s.apk_strict and not is_admin and \
            apk_mod.file_ext(m.document.file_name or "") in (".apk", ".apks", ".xapk", ".apkm"):
        v.policy_block = "guruhda APK yuborish taqiqlangan (qat'iy himoya rejimi)"

    delete = v.level == MALICIOUS or (v.level == SUSPICIOUS and s.delete_suspicious) or bool(v.policy_block)
    await db.bump(m.chat.id, delete)
    if not delete:
        return

    who = mention(m.from_user if not m.sender_chat else None, m.sender_chat)
    try:
        await m.delete()
        deleted = True
    except Exception as e:  # noqa: BLE001
        log.warning("delete failed in %s: %s", m.chat.id, e)
        deleted = False

    suffix = "" if deleted else "\n\n⚙️ <b>Botda «Xabarlarni o'chirish» huquqi yo'q!</b> Adminlar, iltimos, huquq bering."
    if s.mute_sender and deleted and not is_admin and m.from_user:
        try:
            await bot.restrict_chat_member(m.chat.id, m.from_user.id, ChatPermissions(can_send_messages=False),
                                           until_date=timedelta(hours=1))
            suffix += "\n🔇 Yuboruvchi 1 soatga cheklandi (akkaunt buzilgan bo'lsa spam tarqatmasligi uchun)."
        except Exception:  # noqa: BLE001
            pass

    w = v.worst
    event_id = await db.log_event(m.chat.id, m.from_user.id if m.from_user else None, w.target if w else "",
                                  v.level, w.score if w else 0, w.reasons if w else [], admin_report(v)) if w else None
    kb = await details_button(bot, event_id)
    try:
        sent = await bot.send_message(m.chat.id, group_warning(v, who, pending=v.fast) + suffix, reply_markup=kb,
                                      message_thread_id=m.message_thread_id if m.is_topic_message else None,
                                      reply_parameters=None if deleted else ReplyParameters(message_id=m.message_id))
        await delete_later(bot, m.chat.id, sent.message_id, s.warn_ttl)
    except Exception as e:  # noqa: BLE001
        log.warning("warn send failed: %s", e)
        sent = None

    if v.fast:
        # Xabar allaqachon o'chirildi; endi sandbox orqali aniq ma'lumot yig'ib, ogohlantirishni yangilaymiz
        v = await scan_message(bot, m, extra_context=extra, allow_fast=False)
        if event_id:
            await db.update_event_report(event_id, admin_report(v))
        if sent:
            try:
                await sent.edit_text(group_warning(v, who) + suffix, reply_markup=kb)
            except Exception as e:  # noqa: BLE001
                log.debug("edit warn: %s", e)

    await log_to_channel(bot, f"🛡 <b>{html.escape(m.chat.title or str(m.chat.id))}</b> ({m.chat.id})\n"
                              f"{warning_text(v, who)}", best_screenshot(v))


# ─────────────── bot guruhga qo'shilganda ───────────────
@router.my_chat_member()
async def on_added(ev: ChatMemberUpdated, bot: Bot):
    new = ev.new_chat_member
    if ev.chat.type == ChatType.PRIVATE:
        if new.status == ChatMemberStatus.KICKED:
            await db.set_user_blocked(ev.chat.id)
        return
    active = new.status in (ChatMemberStatus.ADMINISTRATOR, ChatMemberStatus.MEMBER)
    await db.upsert_chat(ev.chat.id, ev.chat.title or "", ev.chat.type,
                         is_admin=new.status == ChatMemberStatus.ADMINISTRATOR, active=active)
    if not active:
        return
    if ev.old_chat_member.status in (ChatMemberStatus.ADMINISTRATOR,) and new.status == ChatMemberStatus.ADMINISTRATOR:
        return
    ok = new.status == ChatMemberStatus.ADMINISTRATOR and getattr(new, "can_delete_messages", False)
    if ev.chat.type == ChatType.CHANNEL:
        return
    text = ("🛡 <b>Himoya yoqildi!</b>\nGuruhdagi har bir havola, tugma va fayl (APK) avtomatik tekshiriladi. "
            "Xavflisi darhol o'chirilib, hammaga ogohlantirish chiqariladi.\n\n"
            "Sozlash: /sozlamalar  •  Statistika: /holat")
    if not ok:
        text += ("\n\n⚠️ <b>Meni admin qiling</b> va «Xabarlarni o'chirish» hamda «Foydalanuvchilarni cheklash» "
                 "huquqlarini bering — aks holda xavfli xabarlarni o'chira olmayman.")
    try:
        banner = asset("banner_group.jpg")
        if banner:
            await bot.send_photo(ev.chat.id, banner, caption=text)
        else:
            await bot.send_message(ev.chat.id, text)
    except Exception:  # noqa: BLE001
        pass


# ─────────────── sozlamalar ───────────────
def _kb(chat_id: int, s: db.ChatSettings) -> InlineKeyboardMarkup:
    def b(label, key, on):
        return InlineKeyboardButton(text=f"{'✅' if on else '❌'} {label}", callback_data=f"set:{chat_id}:{key}")
    ttl = {0: "qoldirish", 5: "5 daqiqa", 30: "30 daqiqa"}.get(s.warn_ttl, f"{s.warn_ttl} daq")
    return InlineKeyboardMarkup(inline_keyboard=[
        [b("APK qat'iy taqiq (adminlardan tashqari)", "apk_strict", s.apk_strict)],
        [b("Shubhali havolalarni ham o'chirish", "delete_suspicious", s.delete_suspicious)],
        [b("Yuboruvchini 1 soatga cheklash", "mute_sender", s.mute_sender)],
        [InlineKeyboardButton(text=f"🕒 Ogohlantirish: {ttl}", callback_data=f"set:{chat_id}:warn_ttl")],
    ])


@router.message(Command("sozlamalar", "settings"), F.chat.type.in_(GROUPS))
async def cmd_settings(m: Message, bot: Bot):
    if not m.from_user or m.from_user.id not in await admin_ids(bot, m.chat.id):
        return await m.reply("Faqat adminlar uchun.")
    s = await db.get_settings(m.chat.id)
    await m.reply("⚙️ <b>Himoya sozlamalari</b>", reply_markup=_kb(m.chat.id, s))


@router.callback_query(F.data.startswith("set:"))
async def cb_settings(c: CallbackQuery, bot: Bot):
    _, chat_id, key = c.data.split(":")
    chat_id = int(chat_id)
    if c.from_user.id not in await admin_ids(bot, chat_id):
        return await c.answer("Faqat adminlar o'zgartira oladi", show_alert=True)
    s = await db.get_settings(chat_id)
    if key == "warn_ttl":
        val = {0: 5, 5: 30, 30: 0}.get(s.warn_ttl, 0)
    else:
        val = int(not getattr(s, key))
    await db.set_setting(chat_id, key, val)
    await c.message.edit_reply_markup(reply_markup=_kb(chat_id, await db.get_settings(chat_id)))
    await c.answer("Saqlandi")


@router.message(Command("privacy", "maxfiylik"), F.chat.type.in_(GROUPS))
async def cmd_privacy(m: Message):
    from ..config import PRIVACY_URL
    await m.reply(f"🔒 Maxfiylik siyosati: {PRIVACY_URL}\nQisqacha: oddiy xabarlar saqlanmaydi; faqat xavfli "
                  "deb topilgan havola/fayl haqidagi yozuv 90 kun saqlanadi.", disable_web_page_preview=True)


@router.message(Command("holat", "stats"), F.chat.type.in_(GROUPS))
async def cmd_stats(m: Message):
    scanned, deleted = await db.get_stats(m.chat.id)
    await m.reply(f"🛡 Tekshirilgan xabarlar: <b>{scanned}</b>\n⛔️ O'chirilgan xavfli xabarlar: <b>{deleted}</b>")


# Umumiy ushlagichlar oxirida turadi, buyruqlar birinchi ishlashi uchun
@router.message(F.chat.type.in_(GROUPS))
@router.edited_message(F.chat.type.in_(GROUPS))
async def on_group_message(m: Message, bot: Bot):
    await process(bot, m)


@router.channel_post()
@router.edited_channel_post()
async def on_channel_post(m: Message, bot: Bot):
    await process(bot, m, channel=True)
