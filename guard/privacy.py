"""Maxfiylik siyosati: Telegram (/privacy) va veb-sahifa (/privacy) uchun yagona manba.

MUHIM: bu yerda yozilganlar kodning haqiqiy xatti-harakatiga mos bo'lishi shart.
Kod o'zgarsa (yangi ma'lumot saqlansa, yangi xizmatga yuborilsa) — siyosatni ham yangilang.
"""
from __future__ import annotations

import html

UPDATED = "25.11.2026"
BOT = "@endixavfsiz_bot"
CONTACT = "@sobirjon_sharipov"
RETENTION_DAYS = 90

# (sarlavha, [paragraflar yoki ro'yxat bandlari («• » bilan boshlanadi)])
SECTIONS: list[tuple[str, list[str]]] = [
    ("1. Umumiy qoidalar", [
        f"Ushbu siyosat {BOT} Telegram boti (keyingi o'rinlarda — «Bot») qanday ma'lumotlarni qayta ishlashi, "
        "saqlashi va himoya qilishini tushuntiradi. Botdan foydalanish, uni guruh yoki kanalga qo'shish yoki "
        "Telegram Business orqali shaxsiy chatlarga ulash orqali siz ushbu siyosatga rozilik bildirasiz.",
        "Botning yagona maqsadi — Telegram foydalanuvchilarini fishing havolalar va zararli fayllardan himoya qilish. "
        "Ma'lumotlar reklama, profillash yoki sotish uchun ishlatilmaydi.",
    ]),
    ("2. Qanday ma'lumotlar qayta ishlanadi", [
        "• <b>Botdan foydalanuvchilar:</b> Telegram ID, ism va username (/start bosilganda saqlanadi).",
        "• <b>Guruh va kanallar:</b> chat ID, nomi, turi va botning admin huquqi bor-yo'qligi.",
        "• <b>Xabarlar:</b> bot himoya qilayotgan chatlardagi xabarlar faqat havola, tugma va fayllarni topish "
        "uchun avtomatik tekshiriladi. Oddiy xabarlar matni <b>saqlanmaydi</b>. Yuboruvchining oxirgi xabari "
        "kontekst sifatida faqat operativ xotirada 3 daqiqa turadi, keyin o'chadi.",
        "• <b>Aniqlangan xavflar:</b> xavfli deb topilgan xabar bo'yicha chat ID, yuboruvchi ID, xavfli havola yoki "
        "fayl nomi, xavf bali, sabablar va tekshiruv hisoboti saqlanadi.",
        "• <b>Fayllar:</b> chatlarda yuborilgan xavfli kengaytmali fayllar (APK va h.k.) faqat operativ xotirada "
        "tekshiriladi. Sandbox'dagi sayt avtomatik yuklatgan fayl tekshiruv vaqtida vaqtinchalik faylga yoziladi "
        "va darhol o'chiriladi. Fayllar o'rnatilmaydi va saqlanmaydi.",
        "• <b>Telegram Business:</b> ulanish ID, akkaunt egasining ID'si va botga berilgan huquqlar.",
        "• <b>Sozlamalar va statistika:</b> guruh sozlamalari, tekshirilgan va o'chirilgan xabarlar soni.",
    ]),
    ("3. Havolalar qanday tekshiriladi", [
        "Havolalar <b>bot serverida</b>, har safar yangi ochiladigan izolyatsiyalangan brauzerda (sandbox) "
        "tekshiriladi. Foydalanuvchining Telegram akkaunti, telefoni yoki brauzeri bunda ishtirok etmaydi; "
        "tekshirilayotgan sayt foydalanuvchining emas, serverning IP manzilini ko'radi.",
        "Sandbox cookie va sessiyalarsiz ishlaydi, tekshiruvdan keyin to'liq o'chiriladi. Sahifa skrinshoti va "
        "tekshiruv natijasi takroriy tekshiruvni tezlashtirish uchun operativ xotirada 6 soatgacha saqlanadi.",
    ]),
    ("4. Uchinchi tomon xizmatlari", [
        "Xavfni aniqlash uchun xabarning o'zi emas, <b>faqat havola manzili</b> (yoki fayl xeshi) quyidagi "
        "xizmatlarga yuborilishi mumkin:",
        "• rdap.org — domen ro'yxatdan o'tgan sanani aniqlash (faqat domen nomi);",
        "• ip-api.com — tekshirilayotgan sayt serverining joylashuvi (sayt IP manzili, foydalanuvchiniki emas);",
        "• Google Safe Browsing, VirusTotal, URLhaus — agar bot egasi ularni ulagan bo'lsa. VirusTotal'ga "
        "yuborilgan havolalar uning xavfsizlik hamjamiyatiga ko'rinishi mumkin;",
        "• OpenPhish va URLhaus ochiq ro'yxatlari bot tomonidan yuklab olinadi — ularga hech qanday ma'lumot "
        "yuborilmaydi.",
        "Bot Railway (AQSh) bulut serverida ishlaydi. Telegram bilan aloqa rasmiy Telegram Bot API orqali amalga "
        "oshiriladi va Telegram'ning o'z maxfiylik siyosatiga bo'ysunadi.",
    ]),
    ("5. Ma'lumotlardan foydalanish", [
        "• xavfli xabarlarni aniqlash, o'chirish va ogohlantirish chiqarish;",
        "• «Batafsil hisobot» va guruh statistikasini ko'rsatish;",
        "• bot egasi uchun umumiy statistika va xizmat sifatini nazorat qilish;",
        "• /start bosgan foydalanuvchilarga va bot qo'shilgan guruhlarga vaqti-vaqti bilan xizmat e'lonlarini "
        "yuborish.",
        "Guruh va kanallarda aniqlangan xavflar haqidagi hisobot bot egasining yopiq log kanaliga yuborilishi "
        "mumkin. Shaxsiy chatlardagi (Business) xabarlar haqidagi ma'lumot esa faqat akkaunt egasiga yuboriladi "
        "va log kanalga yuborilmaydi.",
    ]),
    ("6. Saqlash muddati", [
        f"Aniqlangan xavflar haqidagi yozuvlar {RETENTION_DAYS} kundan keyin avtomatik o'chiriladi. "
        "Foydalanuvchi, guruh va sozlamalar ma'lumotlari bot ishlatilayotgan muddat davomida yoki o'chirish "
        "so'ralgunga qadar saqlanadi. Bot guruhdan chiqarilsa, guruh faol emas deb belgilanadi.",
    ]),
    ("7. Sizning huquqlaringiz", [
        "• <b>/deletemydata</b> — botga yozing, sizga tegishli ma'lumotlar (profil va siz yuborgan xabarlar "
        "bo'yicha hodisalar) darhol o'chiriladi;",
        "• botni bloklash orqali xizmat e'lonlarini olishni to'xtatishingiz mumkin;",
        "• guruh adminlari botni guruhdan chiqarish yoki /sozlamalar orqali uning ishini o'zgartirishi mumkin;",
        "• Telegram Business ulanishini istalgan vaqtda Sozlamalar → Telegram Business → Chatbotlar bo'limida "
        "uzishingiz mumkin.",
    ]),
    ("8. Xavfsizlik", [
        "Ma'lumotlar himoyalangan serverda saqlanadi, bot tokeni va kalitlar kodda emas, maxfiy sozlamalarda "
        "turadi. Shunga qaramay, internet orqali uzatish va saqlashning hech bir usuli 100% xavfsiz emas.",
        "Bot hech qachon sizdan parol, SMS-kod, Telegram kodi yoki karta ma'lumotini so'ramaydi.",
    ]),
    ("9. O'zgarishlar va aloqa", [
        f"Siyosat yangilanishi mumkin; yangi versiya shu sahifada va {BOT} ichidagi /privacy buyrug'ida "
        f"e'lon qilinadi. Savollar bo'yicha: {CONTACT}.",
    ]),
]


def telegram_text() -> str:
    """Telegram HTML (<4096 belgi)."""
    out = [f"🔒 <b>Maxfiylik siyosati</b>\n<i>Yangilangan: {UPDATED}</i>\n"]
    for title, paras in SECTIONS:
        out.append(f"\n<b>{title}</b>")
        out += paras
    text = "\n".join(out)
    return text if len(text) <= 4096 else text[:4000] + "…"


def telegram_parts() -> list[str]:
    """Uzun matnni 4096 belgidan oshmaydigan bo'laklarga ajratadi."""
    parts, cur = [], f"🔒 <b>Maxfiylik siyosati</b>\n<i>Yangilangan: {UPDATED}</i>\n"
    for title, paras in SECTIONS:
        block = f"\n<b>{title}</b>\n" + "\n".join(paras) + "\n"
        if len(cur) + len(block) > 3900:
            parts.append(cur)
            cur = ""
        cur += block
    parts.append(cur)
    return parts


def web_page() -> str:
    def p(x: str) -> str:
        # Telegram HTML (<b>, <i>) veb uchun ham to'g'ri; qolganini ekranlash
        safe = html.escape(x, quote=False).replace("&lt;b&gt;", "<b>").replace("&lt;/b&gt;", "</b>")
        return f"<li>{safe[2:]}</li>" if x.startswith("• ") else f"<p>{safe}</p>"

    body = ""
    for title, paras in SECTIONS:
        items, html_paras = [], []
        for x in paras:
            if x.startswith("• "):
                items.append(p(x))
            else:
                if items:
                    html_paras.append("<ul>" + "".join(items) + "</ul>")
                    items = []
                html_paras.append(p(x))
        if items:
            html_paras.append("<ul>" + "".join(items) + "</ul>")
        body += f"<section><h2>{html.escape(title)}</h2>{''.join(html_paras)}</section>"
    return f"""<!DOCTYPE html>
<html lang="uz"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Maxfiylik siyosati — {BOT}</title>
<style>
:root{{--bg:#070f24;--card:#0e1d44;--tx:#dce6fa;--mut:#9fb3da;--acc:#34f5b4;--acc2:#4da3ff}}
*{{box-sizing:border-box}}body{{margin:0;background:radial-gradient(circle at 20% 0,#16306b,var(--bg) 60%) fixed;
color:var(--tx);font:16px/1.65 Inter,system-ui,-apple-system,Segoe UI,Roboto,sans-serif}}
main{{max-width:760px;margin:0 auto;padding:48px 20px 80px}}
header{{display:flex;gap:16px;align-items:center;margin-bottom:28px}}
header img{{width:64px;height:64px;border-radius:16px}}
h1{{margin:0;font-size:28px;background:linear-gradient(90deg,var(--acc),var(--acc2));-webkit-background-clip:text;color:transparent}}
.meta{{color:var(--mut);font-size:14px}}
section{{background:rgba(14,29,68,.72);border:1px solid rgba(77,163,255,.18);border-radius:16px;padding:18px 22px;margin:14px 0}}
h2{{font-size:18px;margin:0 0 8px;color:#fff}}p{{margin:8px 0}}ul{{margin:6px 0;padding-left:20px}}li{{margin:4px 0}}
b{{color:#fff}}a{{color:var(--acc)}}footer{{color:var(--mut);font-size:14px;text-align:center;margin-top:28px}}
</style></head><body><main>
<header><img src="/logo.jpg" alt=""><div><h1>Maxfiylik siyosati</h1>
<div class="meta">{BOT} · Yangilangan: {UPDATED}</div></div></header>
{body}
<footer>Botni ochish: <a href="https://t.me/{BOT.lstrip('@')}">{BOT}</a></footer>
</main></body></html>"""
