"""Izolyatsiyalangan sandbox brauzer.

Har bir havola BOT SERVERIDA, bir martalik yopiq brauzer kontekstida ochiladi:
  • foydalanuvchi akkaunti/telefoni ishtirok etmaydi, cookie/sessiya yo'q, har safar toza profil;
  • ichki tarmoq (localhost, 10.x, 192.168.x ...) ga so'rovlar bloklanadi;
  • yuklab olinadigan fayllar (APK) ushlanadi va o'rnatilmasdan statik tahlil qilinadi;
  • JavaScript bajariladi — JS orqali yashirilgan fishing sahifalari ham ko'rinadi;
  • sahifa skrinshoti olinadi (foydalanuvchi o'zi ochmasdan ko'rishi uchun).
"""
from __future__ import annotations

import asyncio
import logging
import os
import tempfile
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from ..config import config

log = logging.getLogger(__name__)

MOBILE_UA = ("Mozilla/5.0 (Linux; Android 14; SM-A546E) AppleWebKit/537.36 (KHTML, like Gecko) "
             "Chrome/131.0.0.0 Mobile Safari/537.36")
# Fishing to'plamlari haqiqiy Telegram serverlariga proksi qiladi (kodni o'g'irlab, akkauntga kiradi)
TG_API_MARKERS = ("web.telegram.org/apiws", "web.telegram.org/apiw", ".web.telegram.org", "149.154.167.",
                  "149.154.175.", "91.108.56.", "/api/sendcode", "/api/auth", "sendcode", "signin")

DOM_PROBE = """() => {
  const q = s => Array.from(document.querySelectorAll(s));
  const inputs = q('input, textarea').filter(e => e.type !== 'hidden').slice(0, 40).map(e => ({
     type: (e.type||'').toLowerCase(), name: (e.name||'').toLowerCase(), id: (e.id||'').toLowerCase(),
     ph: (e.placeholder||'').toLowerCase(), ac: (e.autocomplete||'').toLowerCase(),
     ml: e.maxLength || 0, im: (e.inputMode||'').toLowerCase()}));
  const forms = q('form').slice(0, 10).map(f => f.action || '');
  const links = q('a[href]').slice(0, 300).map(a => a.href);
  const text = (document.body ? document.body.innerText : '').slice(0, 8000);
  return {inputs, forms, links, text, iframes: q('iframe').length, title: document.title || ''};
}"""


@dataclass
class SandboxReport:
    ok: bool = False
    error: str = ""
    final_url: str = ""
    chain: list[str] = field(default_factory=list)
    status: int | None = None
    ip: str = ""
    title: str = ""
    text: str = ""
    html: str = ""
    inputs: list[dict] = field(default_factory=list)
    forms: list[str] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    iframes: int = 0
    request_hosts: set[str] = field(default_factory=set)
    tg_api_calls: list[str] = field(default_factory=list)
    downloads: list[dict] = field(default_factory=list)   # {name, size, data}
    screenshot: bytes | None = None


class Sandbox:
    def __init__(self):
        self._pw = None
        self._browser = None
        self._lock = asyncio.Lock()
        self._sem = asyncio.Semaphore(int(os.getenv("SANDBOX_PAGES", "3")))

    async def _ensure(self):
        async with self._lock:
            if self._browser and self._browser.is_connected():
                return
            from playwright.async_api import async_playwright
            self._pw = self._pw or await async_playwright().start()
            kw = {"args": ["--disable-dev-shm-usage", "--no-first-run", "--disable-extensions",
                           "--disable-background-networking", "--disable-sync", "--mute-audio"]}
            kw["args"] += [a for a in os.getenv("SANDBOX_ARGS", "").split("||") if a.strip()]
            exe = os.getenv("CHROME_PATH")
            if exe:
                kw["executable_path"] = exe
            self._browser = await self._pw.chromium.launch(**kw)
            log.info("Sandbox brauzer ishga tushdi")

    async def close(self):
        try:
            if self._browser:
                await self._browser.close()
            if self._pw:
                await self._pw.stop()
        except Exception:  # noqa: BLE001
            pass

    async def visit(self, url: str, timeout: float = 10.0) -> SandboxReport:
        from .url import _host_is_public  # aylanma importdan qochish
        rep = SandboxReport(chain=[url])
        async with self._sem:
            try:
                await self._ensure()
            except Exception as e:  # noqa: BLE001
                rep.error = f"sandbox ishga tushmadi: {e}"
                return rep
            ctx = await self._browser.new_context(
                user_agent=MOBILE_UA, viewport={"width": 412, "height": 860}, is_mobile=True, has_touch=True,
                locale="uz-UZ", accept_downloads=True, service_workers="block", ignore_https_errors=True,
                java_script_enabled=True, permissions=[])
            page = None
            dl_dir = tempfile.mkdtemp(prefix="sbx_")
            try:
                public_cache: dict[str, bool] = {}

                async def guard(route):
                    req_url = route.request.url
                    p = urlsplit(req_url)
                    if p.scheme not in ("http", "https", "ws", "wss"):
                        return await route.abort()
                    host = p.hostname or ""
                    low = req_url.lower()
                    if any(mk in low for mk in TG_API_MARKERS):
                        rep.tg_api_calls.append(req_url[:150])
                    if host not in public_cache:
                        public_cache[host] = await _host_is_public(host)
                    if not public_cache[host]:
                        return await route.abort("blockedbyclient")
                    rep.request_hosts.add(host)
                    await route.continue_()

                await ctx.route("**/*", guard)
                ctx.on("websocket", lambda ws: rep.tg_api_calls.append(ws.url[:150])
                       if any(mk in ws.url.lower() for mk in TG_API_MARKERS) else None)
                page = await ctx.new_page()
                page.on("dialog", lambda d: asyncio.create_task(d.dismiss()))

                def on_nav(frame):
                    if frame == page.main_frame and frame.url not in rep.chain and frame.url.startswith("http"):
                        rep.chain.append(frame.url)
                page.on("framenavigated", on_nav)

                async def on_download(d):
                    try:
                        path = os.path.join(dl_dir, "f")
                        await asyncio.wait_for(d.save_as(path), timeout=25)
                        size = os.path.getsize(path)
                        data = open(path, "rb").read() if size <= config.max_file_mb * 1048576 else None
                        rep.downloads.append({"name": d.suggested_filename, "size": size, "data": data})
                    except Exception as e:  # noqa: BLE001
                        rep.downloads.append({"name": d.suggested_filename, "size": None, "data": None})
                        log.debug("download: %s", e)
                dl_tasks = []
                page.on("download", lambda d: dl_tasks.append(asyncio.create_task(on_download(d))))

                resp = None
                try:
                    resp = await page.goto(url, wait_until="domcontentloaded", timeout=timeout * 1000)
                except Exception as e:  # noqa: BLE001
                    msg = str(e).split("\n")[0]
                    if "Download is starting" not in msg:
                        rep.error = msg[:200]
                if resp:
                    rep.status = resp.status
                    try:
                        sa = await resp.server_addr()
                        rep.ip = sa["ipAddress"] if sa else ""
                    except Exception:  # noqa: BLE001
                        pass
                # JS redirect/render uchun qisqa kutish
                try:
                    await page.wait_for_load_state("networkidle", timeout=3500)
                except Exception:  # noqa: BLE001
                    pass
                if dl_tasks:
                    await asyncio.wait(dl_tasks, timeout=25)
                try:
                    rep.final_url = page.url if page.url.startswith("http") else rep.chain[-1]
                    probe = await page.evaluate(DOM_PROBE)
                    rep.title, rep.text = probe["title"][:200], probe["text"]
                    rep.inputs, rep.forms, rep.links, rep.iframes = (probe["inputs"], probe["forms"],
                                                                     probe["links"], probe["iframes"])
                    rep.html = (await page.content())[:400_000]
                    rep.screenshot = await page.screenshot(type="jpeg", quality=55, timeout=5000)
                    rep.ok = resp is not None or len(rep.chain) > 1 or bool(rep.inputs or rep.text.strip())
                    if not page.url.startswith("http"):  # chrome-error:// — sayt ochilmadi
                        rep.ok, rep.screenshot = False, None
                except Exception as e:  # noqa: BLE001
                    rep.error = rep.error or str(e).split("\n")[0][:200]
                    rep.ok = bool(rep.downloads)
            finally:
                await ctx.close()
                for fn in os.listdir(dl_dir):
                    os.remove(os.path.join(dl_dir, fn))
                os.rmdir(dl_dir)
        return rep


sandbox = Sandbox()
