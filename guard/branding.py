"""Bot profili: nom, bio (qisqa tavsif), tavsif, avatar. Ishga tushganda bir marta o'rnatiladi."""
from __future__ import annotations

import logging
from pathlib import Path

from aiogram.types import FSInputFile, InputProfilePhotoStatic

from . import db

log = logging.getLogger(__name__)
ASSETS = Path(__file__).parent / "assets"
BRAND_VERSION = "3"

NAME = "TG Guard 🛡 Anti-Fishing"

# Profildagi «bio» (≤120 belgi)
SHORT_DESCRIPTION = ("🛡 Guruh va chatlarni fishing havola va zararli APK'lardan 24/7 himoya qiladi. "
                     "Xavfli linkni darhol o'chiradi.")

# Bo'sh chatda ko'rinadigan «Bu bot nima qila oladi?» matni (≤512 belgi)
DESCRIPTION = (
    "🛡 TG Guard — Telegram'dagi firibgarlardan himoya.\n\n"
    "✅ Guruh, kanal va shaxsiy chatlardagi har bir havola, post tugmasi va faylni tekshiradi\n"
    "✅ Soxta bank, «sovg'a», «ovoz bering» va soxta Telegram login saytlarini aniqlaydi\n"
    "✅ Zararli APK'larni o'rnatmasdan tahlil qiladi\n"
    "✅ Xavflisini darhol o'chirib, hammani ogohlantiradi\n\n"
    "🔬 Havolalar bot serverida, yopiq brauzerda ochiladi — sizning akkauntingiz ishtirok etmaydi.\n\n"
    "Boshlash uchun START tugmasini bosing 👇"
)


def asset(name: str) -> FSInputFile | None:
    p = ASSETS / name
    return FSInputFile(p) if p.exists() else None


async def apply_profile(bot):
    if await db.meta_get("brand_version") == BRAND_VERSION:
        return
    steps = [
        ("name", bot.set_my_name(name=NAME)),
        ("short_description", bot.set_my_short_description(short_description=SHORT_DESCRIPTION)),
        ("description", bot.set_my_description(description=DESCRIPTION)),
    ]
    logo = asset("logo.jpg")
    if logo:
        steps.append(("photo", bot.set_my_profile_photo(photo=InputProfilePhotoStatic(photo=logo))))
    ok = True
    for what, coro in steps:
        try:
            await coro
        except Exception as e:  # noqa: BLE001
            ok = False
            log.warning("profil (%s) o'rnatilmadi: %s", what, e)
    if ok:
        await db.meta_set("brand_version", BRAND_VERSION)
        log.info("Bot profili (nom, bio, tavsif, avatar) o'rnatildi")
