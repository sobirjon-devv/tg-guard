"""APK va boshqa xavfli fayllarni tahlil qilish (statik tahlil + VirusTotal xesh tekshiruvi)."""
from __future__ import annotations

import hashlib
import io
import logging
import re
import zipfile

import aiohttp

from ..config import config
from .data import ARCHIVE_EXTS, DANGEROUS_EXTS
from .result import Finding

log = logging.getLogger(__name__)

# (ruxsat, og'irlik, izoh)
PERMS = [
    ("RECEIVE_SMS", 25, "kelgan SMS'larni o'qiydi (bank/Telegram kodlarini o'g'irlash)"),
    ("READ_SMS", 25, "SMS'larni o'qiydi"),
    ("SEND_SMS", 20, "sizning nomingizdan SMS yuboradi"),
    ("BIND_ACCESSIBILITY_SERVICE", 30, "Accessibility orqali telefonni masofadan boshqaradi"),
    ("BIND_NOTIFICATION_LISTENER_SERVICE", 20, "bildirishnomalardagi kodlarni o'qiydi"),
    ("BIND_DEVICE_ADMIN", 20, "qurilma administratori huquqini so'raydi (o'chirishni qiyinlashtiradi)"),
    ("REQUEST_INSTALL_PACKAGES", 15, "boshqa ilovalarni yashirincha o'rnatadi"),
    ("SYSTEM_ALERT_WINDOW", 10, "boshqa ilovalar ustidan soxta oyna chiqaradi"),
    ("READ_CONTACTS", 10, "kontaktlaringizni o'qiydi (keyingi qurbonlarga tarqatish)"),
    ("READ_CALL_LOG", 10, "qo'ng'iroqlar tarixini o'qiydi"),
    ("CALL_PHONE", 8, "qo'ng'iroq qila oladi"),
    ("READ_PHONE_STATE", 4, "telefon ma'lumotlarini o'qiydi"),
    ("QUERY_ALL_PACKAGES", 5, "o'rnatilgan bank ilovalarini aniqlaydi"),
    ("RECEIVE_BOOT_COMPLETED", 4, "telefon yoqilganda avtomatik ishga tushadi"),
    ("REQUEST_IGNORE_BATTERY_OPTIMIZATIONS", 4, "doimiy fonda ishlaydi"),
    ("FOREGROUND_SERVICE", 2, "fonda ishlaydi"),
]
_BOT_TOKEN_RE = re.compile(rb"\d{8,10}:AA[A-Za-z0-9_-]{33}")
DEX_MARKERS = [
    (b"api.telegram.org", 40, "o'g'irlangan ma'lumotlarni Telegram botga yuboradi (api.telegram.org)"),
    (b"content://sms", 20, "SMS bazasiga to'g'ridan-to'g'ri murojaat qiladi"),
    (b"getMessageBody", 15, "SMS matnini o'qiydi"),
    (b"sendTextMessage", 15, "SMS yuborish kodi bor"),
    (b"DexClassLoader", 10, "yashirin kodni keyinroq yuklaydi (packer/dropper)"),
    (b"setComponentEnabledSetting", 10, "ikonkasini yashiradi"),
    (b"performGlobalAction", 10, "ekranni masofadan bosadi"),
]
LURE_NAMES = re.compile(r"rasm|surat|foto|photo|image|img|video|yangi|tabrik|otkritka|открытк|фото|видео|"
                        r"posilka|pochta|почта|посылк|hujjat|document|scan|skan|file|fayl|gift|sovg|bonus|"
                        r"premium|yutuq|telegram|whatsapp|instagram|update|yangilanish", re.I)


def file_ext(name: str) -> str:
    m = re.search(r"(\.[a-z0-9]{1,5})$", (name or "").lower())
    return m.group(1) if m else ""


def name_check(name: str, f: Finding):
    name = name or ""
    ext = file_ext(name)
    if ext in DANGEROUS_EXTS:
        kind = "Android ilova (APK)" if ext.startswith(".ap") or ext == ".aab" else "bajariladigan dastur"
        f.add(DANGEROUS_EXTS[ext], f"{kind} fayli — telefon/kompyuterga o'rnatilsa nazoratni olishi mumkin")
    if re.search(r"\.(jpg|jpeg|png|mp4|pdf|docx?|gif|mov)\.[a-z0-9]{2,5}$", name, re.I) and ext in DANGEROUS_EXTS:
        f.add(30, "ikki kengaytmali nom (rasm/hujjat qilib ko'rsatilgan dastur)", strong=True)
    if ext in DANGEROUS_EXTS and LURE_NAMES.search(name):
        f.add(15, "aldovchi nom («rasm», «video», «posilka» va h.k.)")
    if "‮" in name:
        f.add(50, "fayl nomida kengaytmani yashiruvchi maxsus belgi (RTLO)", strong=True)


def is_risky_file(name: str, mime: str | None) -> bool:
    ext = file_ext(name)
    return ext in DANGEROUS_EXTS or ext in ARCHIVE_EXTS or (mime or "") == "application/vnd.android.package-archive"


def analyze_apk_bytes(data: bytes, f: Finding):
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        f.add(20, "fayl buzilgan yoki niqoblangan (tahlil qilib bo'lmadi)")
        return
    names = z.namelist()
    if any(i.flag_bits & 0x1 for i in z.infolist()):
        f.add(20, "APK ichi shifrlangan (tahlildan yashirishga urinish)")
    try:
        manifest = z.read("AndroidManifest.xml")
    except KeyError:
        manifest = b""
    perm_pts, perm_why = 0, []
    for perm, w, why in PERMS:
        p = f"android.permission.{perm}"
        if p.encode("utf-16-le") in manifest or p.encode() in manifest or \
           perm.encode("utf-16-le") in manifest:
            perm_pts += w
            perm_why.append(why)
    if perm_pts:
        f.add(min(perm_pts, 60), "xavfli ruxsatlar: " + "; ".join(perm_why[:4]), strong=perm_pts >= 45)
    dex_pts = 0
    for n in names:
        if not re.match(r"classes\d*\.dex$", n):
            continue
        try:
            dex = z.read(n)
        except Exception:  # noqa: BLE001
            continue
        if _BOT_TOKEN_RE.search(dex):
            f.add(50, "ilova ichiga Telegram bot tokeni yashirilgan (ma'lumot o'g'irlovchi)", strong=True)
        for marker, w, why in DEX_MARKERS:
            if marker in dex and why not in f.reasons:
                f.add(w, why)
                dex_pts += w
    # Kichik hajm + SMS ruxsatlari — o'zbek segmentidagi SMS-o'g'ri troyanlar uchun tipik
    if len(data) < 3_000_000 and perm_pts >= 45:
        f.add(15, "kichik hajmli, ammo SMS/boshqaruv ruxsatlari ko'p — SMS-troyanga xos")
    # Ichida yana APK (dropper)
    if any(n.lower().endswith(".apk") for n in names):
        f.add(25, "APK ichida boshqa APK yashirilgan (dropper)")


def analyze_archive(data: bytes, f: Finding) -> bytes | None:
    """ZIP ichidagi xavfli fayllarni topadi; birinchi APKni qaytaradi."""
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return None
    for n in z.namelist()[:500]:
        ext = file_ext(n)
        if ext in DANGEROUS_EXTS:
            f.add(DANGEROUS_EXTS[ext], f"arxiv ichida xavfli fayl: {n[-60:]}")
            if ext in (".apk", ".apks", ".xapk"):
                try:
                    return z.read(n)
                except Exception:  # noqa: BLE001
                    return None
    return None


async def vt_hash(session: aiohttp.ClientSession, sha256: str) -> tuple[int, int] | None:
    if not config.vt_api_key:
        return None
    try:
        async with session.get(f"https://www.virustotal.com/api/v3/files/{sha256}",
                               headers={"x-apikey": config.vt_api_key},
                               timeout=aiohttp.ClientTimeout(total=6)) as r:
            if r.status != 200:
                return None
            st = (await r.json())["data"]["attributes"]["last_analysis_stats"]
            return st.get("malicious", 0), st.get("suspicious", 0)
    except Exception as e:  # noqa: BLE001
        log.debug("vt hash: %s", e)
        return None


async def analyze_file(session, name: str, data: bytes | None, size: int | None) -> Finding:
    f = Finding(target=name or "fayl", kind="file")
    name_check(name, f)
    if data is None:
        if size and size > config.max_file_mb * 1024 * 1024:
            f.add(10, f"fayl juda katta ({size // 1048576} MB) — ichini tekshirib bo'lmadi")
        return f
    sha = hashlib.sha256(data).hexdigest()
    ext = file_ext(name)
    inner = None
    if ext in ARCHIVE_EXTS:
        inner = analyze_archive(data, f)
    looks_apk = data[:2] == b"PK" and b"AndroidManifest.xml" in data  # nomi o'zgartirilgan APK
    if ext in (".apk", ".apks", ".xapk", ".apkm") or (inner is None and looks_apk):
        apk_bytes = data
        if looks_apk and ext not in DANGEROUS_EXTS:
            f.add(60, "fayl aslida Android ilova (APK), lekin boshqa kengaytma bilan niqoblangan", strong=True)
    else:
        apk_bytes = inner
    if apk_bytes:
        analyze_apk_bytes(apk_bytes, f)
    res = await vt_hash(session, sha)
    if res:
        mal, sus = res
        if mal >= 3:
            f.mark_hard(f"VirusTotal: {mal} ta antivirus zararli dastur deb topdi")
        elif mal or sus:
            f.add(30, f"VirusTotal: {mal + sus} ta antivirus shubhali deb topdi")
    return f
