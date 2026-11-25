# 🛡 TG Guard — Telegram uchun fishing va zararli APK'dan himoya boti

Guruh, kanal va **shaxsiy chatlarni** 24/7 nazorat qiladi. Har bir havola, yashirin havola, inline-tugma va
fayl tekshiriladi. Xavflisi darhol o'chiriladi va o'rniga hammaga ogohlantirish yoziladi.

## Nimalarni ushlaydi
| Hujum turi | Qanday aniqlanadi |
|---|---|
| Soxta bank/«sovg'a» postlari (masalan, @PostBot orqali «NBU 70 000 so'm», «OLING» tugmasi) | tugmadagi URL, inline-bot/forward belgisi, brend taqlidi, «menga ham berishdi» shabloni |
| Soxta Telegram login (akkauntni o'g'irlash) | sahifa mazmuni: telefon/kod formasi, GramJS/MTProto kodi, `tgme_page` dizayni nusxasi |
| «Ovoz bering» fishingi | matn + domen + sahifa tahlili |
| Typosquatting / homoglif (`teIegram`, `tеlegram` kirillcha) | Levenshtein + o'xshash harflar jadvali + punycode |
| Yashirin/qisqa havolalar (bit.ly, redirect, meta-refresh) | xavfsiz redirect zanjiri kuzatuvi |
| Zararli APK (SMS-o'g'ri, «Rasmlar.apk», `photo.jpg.apk`) | ruxsatlar, DEX ichida `api.telegram.org` va bot token, dropper, niqoblangan kengaytma, VirusTotal xesh |
| Ma'lum xavfli saytlar | OpenPhish + URLhaus ochiq bazalari (kalitsiz), Google Safe Browsing, VirusTotal, URLhaus API |
| Yangi ochilgan domenlar | RDAP orqali domen yoshi |

## 🔬 Sandbox: havola foydalanuvchi akkauntida emas, bot serverida ochiladi
Har bir havola (matndagi, yashirin `text_link`, post ostidagi tugmalar, redirect oxiridagi manzil) bot serverida
**bir martalik, yopiq Chromium brauzerda** ochiladi: cookie/sessiya yo'q, har safar toza profil, ichki tarmoqqa
so'rovlar bloklangan, yuklanadigan fayllar o'rnatilmasdan tahlil qilinadi. Foydalanuvchi akkaunti va telefoni
umuman ishtirok etmaydi. JavaScript bajariladi, shuning uchun JS bilan yashirilgan fishing ham ko'rinadi.

Hisobotda aniq ma'lumot: yakuniy manzil va redirectlar soni, server IP/davlat/provayder, domen yoshi, sahifa
sarlavhasi, sahifa nimani so'rayapti (telefon, kod, parol, karta, CVV), yuklatadigan fayl, har bir baza natijasi,
tahdid turi, xavf bali va sahifa skrinshoti (spoiler ostida — ochmasdan ko'rish uchun).

**Tezlik:** lokal evristika millisekundlarda ishlaydi — aniq xavfli havola tarmoq tekshiruvini kutmasdan o'chiriladi.
Qolgan tekshiruvlar parallel, umumiy chegara `SCAN_TIMEOUT` (12 s).

**Aniqlik:** faqat matn (havolasiz) hech qachon o'chirilmaydi. Rasmiy domenlar (nbu.uz, payme.uz, t.me, ...)
oq ro'yxatda. Ball: ≥70 — xavfli (o'chiriladi), 40–69 — shubhali (sozlamaga qarab), ishonchli baza tasdig'i — darhol xavfli.

## Ulash
**Guruh:** botni qo'shing → admin qiling («Xabarlarni o'chirish», «Foydalanuvchilarni cheklash»). Sozlamalar: `/sozlamalar`.
Kanal izohlari (kommentlar) bog'langan muhokama guruhiga botni qo'shish orqali himoyalanadi.

**Shaxsiy chatlar** (Telegram Premium kerak): Sozlamalar → Telegram Business → Chatbotlar → `@bot_username` →
«Barcha xabarlarni o'chirish» va «Javob berish» huquqlarini yoqing.

## Ishga tushirish
```
cp .env.example .env   # BOT_TOKEN va ixtiyoriy kalitlar
pip install -r requirements.txt
python -m guard.main
```
Railway: repo'ni ulang, `BOT_TOKEN` (va kalitlarni) Variables'ga qo'shing, `/data` ga Volume ulang.

Testlar: `python -m pytest -q`
