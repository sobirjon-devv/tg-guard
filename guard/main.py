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
from .handlers import admin, business, group, private
from .scanner import engine
from .scanner.url import refresh_feeds


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
                               BotCommand(command="help", description="Shaxsiy chatlarni ulash")],
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
    if config.sandbox:
        from .scanner.sandbox import sandbox
        asyncio.create_task(sandbox._ensure())  # brauzerni oldindan ishga tushirish
    logging.info("Bot ishga tushdi. VT=%s GSB=%s URLhaus=%s", bool(config.vt_api_key),
                 bool(config.gsb_api_key), bool(config.urlhaus_key))
    try:
        await dp.start_polling(bot, allowed_updates=dp.resolve_used_update_types())
    finally:
        await engine.close()
        if config.sandbox:
            from .scanner.sandbox import sandbox
            await sandbox.close()
        await db.close()


if __name__ == "__main__":
    asyncio.run(main())
