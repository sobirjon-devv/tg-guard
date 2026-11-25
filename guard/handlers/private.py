"""Bot bilan shaxsiy chat: /start, qo'llanma va qo'lda tekshirish."""
from __future__ import annotations

from aiogram import Bot, F, Router
from aiogram.enums import ChatType
from aiogram.filters import Command, CommandObject, CommandStart
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup, Message

from .. import db
from ..branding import asset
from ..actions import best_screenshot, report_text, send_report
from ..config import config
from ..scanner.engine import scan_message, scan_url_text

router = Router(name="private")
router.message.filter(F.chat.type == ChatType.PRIVATE)

BUSINESS_HOWTO = (
    "📱 <b>Shaxsiy chatlarni himoyalash</b> (Telegram Premium kerak):\n"
    "1. Telegram → <b>Sozlamalar → Telegram Business → Chatbotlar</b>\n"
    "2. Botning username'ini kiriting: <code>@{username}</code>\n"
    "3. «Barcha chatlar»ni tanlang (kerakli istisnolarni qo'shishingiz mumkin)\n"
    "4. Huquqlarda <b>«Xabarlarga javob berish»</b> va <b>«Barcha xabarlarni o'chirish»</b>ni yoqing\n\n"
    "Shundan so'ng kontaktlardan kelgan xavfli havola/APK avtomatik o'chiriladi va o'rniga ogohlantirish yoziladi."
)


START_TEXT = (
    "🛡 <b>Salom! Men TG Guard — Telegram'dagi firibgarlardan himoya botiman.</b>\n\n"
    "• Guruh, kanal va shaxsiy chatlardagi har bir havola, post tugmasi va faylni tekshiraman\n"
    "• Soxta bank, «sovg'a», «ovoz bering», soxta Telegram login saytlarini va zararli APK'larni aniqlayman\n"
    "• Xavflisini darhol o'chirib, o'rniga <b>«Xavfli havola o'chirildi»</b> deb hammani ogohlantiraman\n\n"
    "🔬 Havolalar mening serverimda, yopiq brauzerda ochiladi — sizning akkauntingiz ishtirok etmaydi.\n\n"
    "🔎 <b>Qo'lda tekshirish:</b> menga havola, fayl yoki shubhali xabarni yuboring/forward qiling."
)


def start_kb(username: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="➕ Guruhga qo'shish",
                              url=f"https://t.me/{username}?startgroup=guard&admin=delete_messages+restrict_members")],
        [InlineKeyboardButton(text="➕ Kanalga qo'shish",
                              url=f"https://t.me/{username}?startchannel=guard&admin=delete_messages+post_messages")],
        [InlineKeyboardButton(text="📱 Shaxsiy chatlarni himoyalash", callback_data="howto_business")],
    ])


@router.message(CommandStart())
async def start(m: Message, bot: Bot, command: CommandObject):
    await db.upsert_user(m.from_user.id, m.from_user.full_name, m.from_user.username)
    arg = command.args or ""
    if arg.startswith("r_") and arg[2:].isdigit():  # guruhdagi «Batafsil hisobot» tugmasi
        row = await db.get_event(int(arg[2:]))
        return await m.answer(row[6] if row and row[6] else "Hisobot topilmadi yoki eskirgan.",
                              disable_web_page_preview=True)
    me = await bot.me()
    banner = asset("banner_start.jpg")
    if banner:
        try:
            return await m.answer_photo(banner, caption=START_TEXT, reply_markup=start_kb(me.username))
        except Exception:  # noqa: BLE001
            pass
    await m.answer(START_TEXT, reply_markup=start_kb(me.username), disable_web_page_preview=True)


@router.callback_query(F.data == "howto_business")
async def howto(c, bot: Bot):
    me = await bot.me()
    text = BUSINESS_HOWTO.format(username=me.username)
    banner = asset("banner_business.jpg")
    if banner and len(text) <= 1024:
        await c.message.answer_photo(banner, caption=text)
    else:
        await c.message.answer(text)
    await c.answer()


@router.message(Command("help", "yordam"))
async def help_(m: Message, bot: Bot):
    me = await bot.me()
    await m.answer(BUSINESS_HOWTO.format(username=me.username) +
                   "\n\n👥 <b>Guruh uchun:</b> botni guruhga qo'shing va admin qiling "
                   "(«Xabarlarni o'chirish», «Foydalanuvchilarni cheklash»). Sozlash: guruhda /sozlamalar")


@router.message(Command("check", "tekshir"))
async def check_cmd(m: Message):
    arg = (m.text or "").split(maxsplit=1)
    if len(arg) < 2:
        return await m.answer("Foydalanish: <code>/check https://misol.uz</code> yoki havolani shunchaki yuboring.")
    wait = await m.answer("🔬 Havola xavfsiz muhitda (sandbox brauzer) ochilmoqda...")
    v = await scan_url_text(arg[1])
    await wait.delete()
    await send_report(m.bot, m.chat.id, report_text(v), best_screenshot(v))


@router.message(Command("stat"))
async def stat(m: Message):
    if m.from_user.id not in config.owner_ids:
        return
    scanned, deleted = await db.get_stats()
    await m.answer(f"Jami tekshirilgan: {scanned}\nJami o'chirilgan: {deleted}")


@router.message()
async def any_private(m: Message, bot: Bot):
    if not (m.entities or m.caption_entities or m.reply_markup or m.document or m.text or m.caption):
        return await m.answer("Tekshirish uchun havola, fayl yoki shubhali xabarni yuboring/forward qiling.")
    wait = await m.answer("🔬 Havola va fayllar xavfsiz muhitda (sandbox) tekshirilmoqda...")
    v = await scan_message(bot, m, allow_fast=False)
    await wait.delete()
    await send_report(bot, m.chat.id, report_text(v), best_screenshot(v))
