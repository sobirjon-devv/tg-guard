"""Kichik veb-server: maxfiylik siyosati sahifasi va health-check."""
from __future__ import annotations

import logging
import os

from aiohttp import web

from .branding import ASSETS
from .privacy import web_page

log = logging.getLogger(__name__)


async def start_web() -> web.AppRunner:
    app = web.Application()
    page = web_page()

    async def privacy(_):
        return web.Response(text=page, content_type="text/html", charset="utf-8")

    async def health(_):
        return web.Response(text="ok")

    async def logo(_):
        return web.FileResponse(ASSETS / "logo.jpg")

    app.add_routes([web.get("/", privacy), web.get("/privacy", privacy), web.get("/health", health),
                    web.get("/logo.jpg", logo)])
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    port = int(os.getenv("PORT", "8080"))
    await web.TCPSite(runner, "0.0.0.0", port).start()
    log.info("Veb-server: :%d (/privacy)", port)
    return runner
