"""Sozlamalar — hammasi environment o'zgaruvchilaridan olinadi."""
import os
from dataclasses import dataclass, field


def _ids(raw: str) -> set[int]:
    return {int(x) for x in raw.replace(" ", "").split(",") if x.strip().lstrip("-").isdigit()}


@dataclass(frozen=True)
class Config:
    bot_token: str = os.getenv("BOT_TOKEN", "")
    # Ixtiyoriy tashqi tekshiruv xizmatlari (kalit bo'lmasa — o'tkazib yuboriladi)
    vt_api_key: str = os.getenv("VT_API_KEY", "")            # VirusTotal
    gsb_api_key: str = os.getenv("GSB_API_KEY", "")          # Google Safe Browsing
    urlhaus_key: str = os.getenv("URLHAUS_KEY", "")          # abuse.ch URLhaus API
    # Bot ishlashi
    db_path: str = os.getenv("DB_PATH", "data/guard.db")
    log_chat_id: int | None = int(os.getenv("LOG_CHAT_ID")) if os.getenv("LOG_CHAT_ID", "").lstrip("-").isdigit() else None
    owner_ids: set[int] = field(default_factory=lambda: _ids(os.getenv("OWNER_IDS", "")))
    # Tezlik/aniqlik
    scan_timeout: float = float(os.getenv("SCAN_TIMEOUT", "25"))        # bitta xabar uchun maksimal vaqt (s)
    vt_submit_wait: float = float(os.getenv("VT_SUBMIT_WAIT", "8"))     # VT yangi URLni tahlil qilishini kutish (s)
    sandbox: bool = os.getenv("SANDBOX", "1") == "1"                   # havolalarni izolyatsiyalangan brauzerda ochish
    fetch_pages: bool = os.getenv("FETCH_PAGES", "1") == "1"           # sahifa mazmunini tahlil qilish
    feeds_enabled: bool = os.getenv("FEEDS", "1") == "1"               # OpenPhish/URLhaus ochiq ro'yxatlari
    malicious_threshold: int = int(os.getenv("MALICIOUS_THRESHOLD", "70"))
    suspicious_threshold: int = int(os.getenv("SUSPICIOUS_THRESHOLD", "40"))
    max_file_mb: int = 20  # Bot API yuklab olish chegarasi


config = Config()

PRIVACY_URL = os.getenv("PRIVACY_URL", "https://tg-guard-bot-production-a5fecc5c.up.railway.app/privacy")
