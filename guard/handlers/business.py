"""Shaxsiy chatlarni himoya qilish — Telegram Business «Chatbotlar» orqali ulanish.

Foydalanuvchi: Sozlamalar → Telegram Business → Chatbotlar → @bot_username → «Xabarlarni o'chirish»
huquqini yoqadi. Shundan so'ng unga kelgan har bir shaxsiy xabar tekshiriladi.
"""
from __future__ import annotations

import html
import logging

from aiogram import Bot, Router
from aiogram.types import BusinessConnection, Message

from .. import db
from ..actions import (best_screenshot, delete_later, group_warning, mention, recent_context, report_text,
                       send_report)
from ..scanner import apk as apk_mod
from ..scanner.engine import scan_message
from ..scanner.result import MALICIOUS, SUSPICIOUS

log = logging.getLogger(__name__)
router = Router(name="business")


def _rights(bc: BusinessConnection) -> tuple[bool, bool]:
    r = getattr(bc, "rights", None)
    can_delete = bool(r and (r.can_delete_all_messages))
    can_reply = bool(r.can_reply) if r else bool(getattr(bc, "can_reply", False))
    return can_delete, can_reply


@router.business_connection()
async def on_connection(bc: BusinessConnection, bot: Bot):
    can_delete, can_reply = _rights(bc)
    await db.save_business(bc.id, bc.user.id, bc.user_chat_id, can_delete, bc.is_enabled)
    if not bc.is_enabled:
        text = "🔌 Shaxsiy chatlar himoyasi o'chirildi."
    else:
        text = "🛡 <b>Shaxsiy chatlaringiz himoyada!</b>\nKontaktlardan kelgan har bir havola va APK fayl tekshiriladi."
        miss = []
        if not can_delete:
            miss.append("«Barcha xabarlarni o'chirish» (Delete all messages)")
        if not can_reply:
            miss.append("«Xabarlarga javob berish» (Reply to messages)")
        if miss:
            text += ("\n\n⚠️ To'liq ishlashi uchun Telegram Business → Chatbotlar bo'limida quyidagi huquqlarni yoqing:\n• "
                     + "\n• ".join(miss))
    try:
        await bot.send_message(bc.user_chat_id, text)
    except Exception:  # noqa: BLE001
        pass


@router.business_message()
@router.edited_business_message()
async def on_business_message(m: Message, bot: Bot):
    conn = await db.get_business(m.business_connection_id)
    if conn is None:
        try:
            bc = await bot.get_business_connection(m.business_connection_id)
            can_delete, _ = _rights(bc)
            await db.save_business(bc.id, bc.user.id, bc.user_chat_id, can_delete, bc.is_enabled)
            conn = (bc.user.id, bc.user_chat_id, int(can_delete), int(bc.is_enabled))
        except Exception as e:  # noqa: BLE001
            log.warning("business conn lookup: %s", e)
            return
    owner_id, owner_chat, can_delete, enabled = conn
    if not enabled:
        return
    extra = recent_context(m)
    if not (m.entities or m.caption_entities or m.reply_markup or m.document or
            (m.text and "." in m.text) or (m.caption and "." in m.caption)):
        return

    outgoing = bool(m.from_user and m.from_user.id == owner_id)
    v = await scan_message(bot, m, extra_context=extra)
    s = await db.get_settings(owner_id)

    # Kontaktdan kelgan APK — qat'iy rejimda doim o'chiriladi (egasining o'zi yuborgani bundan mustasno)
    if not outgoing and m.document and s.apk_strict and \
            apk_mod.file_ext(m.document.file_name or "") in (".apk", ".apks", ".xapk", ".apkm"):
        v.policy_block = "noma'lum APK fayl (shaxsiy chatlarda telefonni buzishning eng ko'p usuli)"

    delete = v.level == MALICIOUS or bool(v.policy_block) or (v.level == SUSPICIOUS and s.delete_suspicious and not outgoing)
    await db.bump(owner_id, delete)
    if not delete:
        return

    who = mention(m.from_user)
    deleted = False
    if can_delete:
        try:
            await bot.delete_business_messages(business_connection_id=m.business_connection_id,
                                               message_ids=[m.message_id])
            deleted = True
        except Exception as e:  # noqa: BLE001
            log.warning("business delete failed: %s", e)

    # Chatdagi ikkala tomonga ko'rinadigan ogohlantirish
    sent = None
    if deleted:
        try:
            sent = await bot.send_message(m.chat.id, "🤖 <i>Avtomatik himoya:</i>\n"
                                          + group_warning(v, who, private=True, pending=v.fast),
                                          business_connection_id=m.business_connection_id)
            await delete_later(bot, m.chat.id, sent.message_id, s.warn_ttl, m.business_connection_id)
        except Exception as e:  # noqa: BLE001
            log.info("business warn not sent: %s", e)

    if v.fast:  # sandbox orqali aniq ma'lumot
        v = await scan_message(bot, m, extra_context=extra, allow_fast=False)
        if sent:
            try:
                await bot.edit_message_text("🤖 <i>Avtomatik himoya:</i>\n" + group_warning(v, who, private=True),
                                            chat_id=m.chat.id, message_id=sent.message_id,
                                            business_connection_id=m.business_connection_id)
            except Exception as e:  # noqa: BLE001
                log.debug("business edit: %s", e)

    # Egasiga batafsil hisobot
    chat_name = html.escape(m.chat.full_name or str(m.chat.id))
    status = "o'chirildi ✅" if deleted else "O'CHIRILMADI — botga «Barcha xabarlarni o'chirish» huquqini bering ❗️"
    note = ("\n\n⚠️ Bu xabarni <b>sizning akkauntingiz</b> yuborgan. Agar siz yubormagan bo'lsangiz — akkauntingiz "
            "buzilgan! Darhol: Sozlamalar → Qurilmalar → «Boshqa seanslarni yakunlash», 2 bosqichli parolni yoqing.") \
        if outgoing else ("\n\n💡 Yuboruvchining akkaunti buzilgan bo'lishi mumkin — unga boshqa yo'l bilan xabar bering.")
    try:
        await send_report(bot, owner_chat, (f"🛡 <b>{chat_name}</b> bilan chatda xavfli xabar {status}\n\n"
                                            + report_text(v) + note)[:4096], best_screenshot(v))
    except Exception:  # noqa: BLE001
        pass
    w = v.worst
    if w:
        await db.log_event(owner_id, m.from_user.id if m.from_user else None, w.target, v.level, w.score, w.reasons,
                           report_text(v))
