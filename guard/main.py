import asyncio
import logging
import sys

from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.types import (BotCommand, BotCommandScopeAllGroupChats, BotCommandScopeAllPrivateChats,
                           BotCommandScopeChat)

from . import db
from .config import config
from .branding import apply_profile
from .web import start_web
from .handlers import admin, business, group, private
from .scanner import engine
from .scanner.url import refresh_feeds


async def maintenance():
    """Maxfiylik siyosatidagi saqlash muddatlarini ta'minlaydi."""
    import time
    from .actions import purge_recent
    from .privacy import RETENTION_DAYS
    from .scanner import url as url_mod
    tick = 0
    while True:
        try:
            purge_recent()                                   # 3 daqiqalik kontekst
            now = time.time()
            for k in [k for k, (ts, _) in url_mod._cache.items() if now - ts > url_mod._CACHE_TTL]:
                url_mod._cache.pop(k, None)                  # 6 soatlik URL kesh (skrinshotlar bilan)
            if tick % 360 == 0:
                n = await db.purge_old_events(RETENTION_DAYS)  # 90 kunlik hodisalar
                if n:
                    logging.info("Eski hodisalar o'chirildi: %d", n)
        except Exception as e:  # noqa: BLE001
            logging.warning("maintenance: %s", e)
        tick += 1
        await asyncio.sleep(60)


async def main():
    logging.basicConfig(level=logging.INFO, stream=sys.stdout,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    if not config.bot_token:
        sys.exit("BOT_TOKEN o'rnatilmagan")
    await db.init()
    bot = Bot(config.bot_token, default=DefaultBotProperties(parse_mode=ParseMode.HTML,
                                                             link_preview_is_disabled=True))
    dp = Dispatcher()
    dp.include_routers(admin.router, private.router, business.router, group.router)

    await bot.set_my_commands([BotCommand(command="start", description="Bot haqida"),
                               BotCommand(command="check", description="Havolani tekshirish"),
                               BotCommand(command="help", description="Shaxsiy chatlarni ulash"),
                               BotCommand(command="privacy", description="Maxfiylik siyosati"),
                               BotCommand(command="deletemydata", description="Ma'lumotlarimni o'chirish")],
                              scope=BotCommandScopeAllPrivateChats())
    await bot.set_my_commands([BotCommand(command="sozlamalar", description="Himoya sozlamalari (adminlar)"),
                               BotCommand(command="holat", description="Statistika")],
                              scope=BotCommandScopeAllGroupChats())
    for oid in config.owner_ids:
        try:
            await bot.set_my_commands([BotCommand(command="admin", description="Admin panel"),
                                       BotCommand(command="start", description="Bot haqida"),
                                       BotCommand(command="check", description="Havolani tekshirish")],
                                      scope=BotCommandScopeChat(chat_id=oid))
        except Exception:  # noqa: BLE001
            pass
    asyncio.create_task(refresh_feeds(await engine.session()))
    asyncio.create_task(apply_profile(bot))
    asyncio.create_task(maintenance())
    web_runner = await start_web()
    if config.sandbox:
        from .scanner.sandbox import sandbox
        asyncio.create_task(sandbox._ensure())  # brauzerni oldindan ishga tushirish
    logging.info("Bot ishga tushdi. VT=%s GSB=%s URLhaus=%s", bool(config.vt_api_key),
                 bool(config.gsb_api_key), bool(config.urlhaus_key))
    try:
        await dp.start_polling(bot, allowed_updates=dp.resolve_used_update_types())
    finally:
        await web_runner.cleanup()
        await engine.close()
        if config.sandbox:
            from .scanner.sandbox import sandbox
            await sandbox.close()
        await db.close()


if __name__ == "__main__":
    asyncio.run(main())
