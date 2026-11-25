"""SQLite: chat sozlamalari, statistika, Business ulanishlar."""
from __future__ import annotations

import os
from dataclasses import dataclass

import aiosqlite

from .config import config

_db: aiosqlite.Connection | None = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings(
  chat_id INTEGER PRIMARY KEY,
  apk_strict INTEGER DEFAULT 1,       -- 1: adminlardan boshqa hamma APK o'chiriladi
  delete_suspicious INTEGER DEFAULT 1,-- shubhali havolalar ham o'chiriladi
  mute_sender INTEGER DEFAULT 0,      -- xavfli havola yuborganni 1 soatga cheklash
  warn_ttl INTEGER DEFAULT 0          -- ogohlantirishni N daqiqadan keyin o'chirish (0 = qoldirish)
);
CREATE TABLE IF NOT EXISTS stats(
  chat_id INTEGER PRIMARY KEY, scanned INTEGER DEFAULT 0, deleted INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS business(
  conn_id TEXT PRIMARY KEY, user_id INTEGER, user_chat_id INTEGER, can_delete INTEGER, enabled INTEGER
);
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER DEFAULT (strftime('%s','now')),
  chat_id INTEGER, user_id INTEGER, target TEXT, level TEXT, score INTEGER, reasons TEXT, report TEXT
);
CREATE TABLE IF NOT EXISTS chats(
  chat_id INTEGER PRIMARY KEY, title TEXT, type TEXT, is_admin INTEGER DEFAULT 0, active INTEGER DEFAULT 1,
  added_ts INTEGER DEFAULT (strftime('%s','now'))
);
CREATE TABLE IF NOT EXISTS users(
  user_id INTEGER PRIMARY KEY, name TEXT, username TEXT, ts INTEGER DEFAULT (strftime('%s','now')), blocked INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
"""


@dataclass
class ChatSettings:
    apk_strict: bool = True
    delete_suspicious: bool = True
    mute_sender: bool = False
    warn_ttl: int = 0


async def init():
    global _db
    os.makedirs(os.path.dirname(config.db_path) or ".", exist_ok=True)
    _db = await aiosqlite.connect(config.db_path)
    await _db.executescript(SCHEMA)
    await _db.commit()


async def close():
    if _db:
        await _db.close()


async def get_settings(chat_id: int) -> ChatSettings:
    async with _db.execute("SELECT apk_strict, delete_suspicious, mute_sender, warn_ttl FROM settings WHERE chat_id=?",
                           (chat_id,)) as c:
        row = await c.fetchone()
    return ChatSettings(*[bool(row[0]), bool(row[1]), bool(row[2]), row[3]]) if row else ChatSettings()


async def set_setting(chat_id: int, key: str, value: int):
    assert key in {"apk_strict", "delete_suspicious", "mute_sender", "warn_ttl"}
    await _db.execute("INSERT OR IGNORE INTO settings(chat_id) VALUES(?)", (chat_id,))
    await _db.execute(f"UPDATE settings SET {key}=? WHERE chat_id=?", (value, chat_id))
    await _db.commit()


async def bump(chat_id: int, deleted: bool):
    await _db.execute("INSERT OR IGNORE INTO stats(chat_id) VALUES(?)", (chat_id,))
    await _db.execute("UPDATE stats SET scanned=scanned+1, deleted=deleted+? WHERE chat_id=?", (int(deleted), chat_id))
    await _db.commit()


async def get_stats(chat_id: int | None = None) -> tuple[int, int]:
    q = "SELECT COALESCE(SUM(scanned),0), COALESCE(SUM(deleted),0) FROM stats" + (" WHERE chat_id=?" if chat_id else "")
    async with _db.execute(q, (chat_id,) if chat_id else ()) as c:
        return tuple(await c.fetchone())


async def log_event(chat_id, user_id, target, level, score, reasons, report: str = "") -> int:
    cur = await _db.execute("INSERT INTO events(chat_id,user_id,target,level,score,reasons,report) VALUES(?,?,?,?,?,?,?)",
                            (chat_id, user_id, target[:500], level, score, " | ".join(reasons)[:2000], report[:4000]))
    await _db.commit()
    return cur.lastrowid


async def update_event_report(event_id: int, report: str):
    await _db.execute("UPDATE events SET report=? WHERE id=?", (report[:4000], event_id))
    await _db.commit()


async def get_event(event_id: int):
    async with _db.execute("SELECT id, ts, chat_id, target, level, score, report FROM events WHERE id=?",
                           (event_id,)) as c:
        return await c.fetchone()


async def recent_events(limit: int = 10):
    async with _db.execute("SELECT e.id, e.ts, e.chat_id, COALESCE(c.title, ''), e.target, e.level, e.score "
                           "FROM events e LEFT JOIN chats c ON c.chat_id=e.chat_id ORDER BY e.id DESC LIMIT ?",
                           (limit,)) as c:
        return await c.fetchall()


async def upsert_chat(chat_id: int, title: str, ctype: str, is_admin: bool | None = None, active: bool = True):
    await _db.execute("INSERT INTO chats(chat_id,title,type,active) VALUES(?,?,?,?) "
                      "ON CONFLICT(chat_id) DO UPDATE SET title=excluded.title, active=excluded.active",
                      (chat_id, title, ctype, int(active)))
    if is_admin is not None:
        await _db.execute("UPDATE chats SET is_admin=? WHERE chat_id=?", (int(is_admin), chat_id))
    await _db.commit()


async def list_chats(limit: int = 30):
    async with _db.execute("SELECT c.chat_id, c.title, c.type, c.is_admin, COALESCE(s.scanned,0), COALESCE(s.deleted,0) "
                           "FROM chats c LEFT JOIN stats s ON s.chat_id=c.chat_id WHERE c.active=1 "
                           "ORDER BY COALESCE(s.deleted,0) DESC, c.added_ts DESC LIMIT ?", (limit,)) as c:
        return await c.fetchall()


async def upsert_user(user_id: int, name: str, username: str | None):
    await _db.execute("INSERT INTO users(user_id,name,username) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET "
                      "name=excluded.name, username=excluded.username, blocked=0", (user_id, name, username))
    await _db.commit()


async def set_user_blocked(user_id: int):
    await _db.execute("UPDATE users SET blocked=1 WHERE user_id=?", (user_id,))
    await _db.commit()


async def all_ids(kind: str) -> list[int]:
    q = ("SELECT user_id FROM users WHERE blocked=0" if kind == "users"
         else "SELECT chat_id FROM chats WHERE active=1 AND type IN ('group','supergroup')")
    async with _db.execute(q) as c:
        return [r[0] for r in await c.fetchall()]


async def overview() -> dict:
    out = {}
    for key, q in {
        "groups": "SELECT COUNT(*) FROM chats WHERE active=1 AND type IN ('group','supergroup')",
        "channels": "SELECT COUNT(*) FROM chats WHERE active=1 AND type='channel'",
        "no_admin": "SELECT COUNT(*) FROM chats WHERE active=1 AND is_admin=0",
        "users": "SELECT COUNT(*) FROM users WHERE blocked=0",
        "business": "SELECT COUNT(*) FROM business WHERE enabled=1",
        "scanned": "SELECT COALESCE(SUM(scanned),0) FROM stats",
        "deleted": "SELECT COALESCE(SUM(deleted),0) FROM stats",
        "today": "SELECT COUNT(*) FROM events WHERE ts >= strftime('%s','now','start of day')",
        "week": "SELECT COUNT(*) FROM events WHERE ts >= strftime('%s','now','-7 days')",
    }.items():
        async with _db.execute(q) as c:
            out[key] = (await c.fetchone())[0]
    return out


async def meta_get(k: str) -> str | None:
    async with _db.execute("SELECT v FROM meta WHERE k=?", (k,)) as c:
        r = await c.fetchone()
    return r[0] if r else None


async def meta_set(k: str, v: str):
    await _db.execute("INSERT OR REPLACE INTO meta VALUES(?,?)", (k, v))
    await _db.commit()


async def save_business(conn_id: str, user_id: int, user_chat_id: int, can_delete: bool, enabled: bool):
    await _db.execute("INSERT OR REPLACE INTO business VALUES(?,?,?,?,?)",
                      (conn_id, user_id, user_chat_id, int(can_delete), int(enabled)))
    await _db.commit()


async def get_business(conn_id: str):
    async with _db.execute("SELECT user_id, user_chat_id, can_delete, enabled FROM business WHERE conn_id=?",
                           (conn_id,)) as c:
        return await c.fetchone()


async def purge_old_events(days: int) -> int:
    cur = await _db.execute("DELETE FROM events WHERE ts < strftime('%s','now') - ?", (days * 86400,))
    await _db.commit()
    return cur.rowcount


async def delete_user_data(user_id: int) -> int:
    """Foydalanuvchiga tegishli barcha yozuvlarni o'chiradi (/deletemydata)."""
    n = 0
    for q in ("DELETE FROM events WHERE user_id=?", "DELETE FROM events WHERE chat_id=?",
              "DELETE FROM users WHERE user_id=?", "DELETE FROM business WHERE user_id=?",
              "DELETE FROM settings WHERE chat_id=?", "DELETE FROM stats WHERE chat_id=?"):
        cur = await _db.execute(q, (user_id,))
        n += max(cur.rowcount, 0)
    await _db.commit()
    return n
