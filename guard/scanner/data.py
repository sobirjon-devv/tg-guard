"""Brendlar, ishonchli domenlar, shubhali belgilar ro'yxati."""

# brend -> (matndagi kalit so'zlar, rasmiy domenlar, domen ichidagi tokenlar)
BRANDS: dict[str, dict] = {
    "NBU (Milliy bank)": {
        "kw": ["nbu", "milliy bank", "milliy banki", "national bank", "нбу", "национальный банк", "миллий банк"],
        "domains": ["nbu.uz"], "tokens": ["nbu", "milliybank", "nationalbank"],
    },
    "Payme": {"kw": ["payme", "пейми"], "domains": ["payme.uz", "paycom.uz"], "tokens": ["payme", "paycom"]},
    "Click": {"kw": ["click.uz", "click up", "click evolution"], "domains": ["click.uz"], "tokens": ["clickuz", "click"]},
    "Uzcard": {"kw": ["uzcard", "узкард"], "domains": ["uzcard.uz"], "tokens": ["uzcard"]},
    "Humo": {"kw": ["humo karta", "humo card", "humocard", "хумо"], "domains": ["humocard.uz", "humo.uz"], "tokens": ["humo", "humocard"]},
    "Kapitalbank": {"kw": ["kapitalbank", "kapital bank", "капиталбанк"], "domains": ["kapitalbank.uz"], "tokens": ["kapitalbank", "kapital"]},
    "Agrobank": {"kw": ["agrobank", "агробанк"], "domains": ["agrobank.uz"], "tokens": ["agrobank"]},
    "Xalq banki": {"kw": ["xalq banki", "xalqbank", "халк банк", "халқ банки"], "domains": ["xb.uz"], "tokens": ["xalqbank", "xalqbanki"]},
    "Ipoteka bank": {"kw": ["ipoteka bank", "ipotekabank", "ипотека банк"], "domains": ["ipotekabank.uz"], "tokens": ["ipotekabank", "ipoteka"]},
    "Uzum": {"kw": ["uzum bank", "uzum market", "uzum nasiya", "узум"], "domains": ["uzum.uz", "uzumbank.uz", "uzum.com", "uzummarket.com"], "tokens": ["uzum", "uzumbank"]},
    "Anorbank": {"kw": ["anorbank", "anor bank", "анорбанк"], "domains": ["anorbank.uz"], "tokens": ["anorbank"]},
    "TBC Bank": {"kw": ["tbc bank", "tbcbank"], "domains": ["tbcbank.uz"], "tokens": ["tbcbank", "tbc"]},
    "Hamkorbank": {"kw": ["hamkorbank", "hamkor bank", "хамкорбанк"], "domains": ["hamkorbank.uz"], "tokens": ["hamkorbank", "hamkor"]},
    "Aloqabank": {"kw": ["aloqabank", "aloqa bank"], "domains": ["aloqabank.uz"], "tokens": ["aloqabank"]},
    "SQB": {"kw": ["sanoatqurilishbank", "sqb bank"], "domains": ["sqb.uz"], "tokens": ["sqb", "sqbbank"]},
    "Asakabank": {"kw": ["asakabank", "asaka bank"], "domains": ["asakabank.uz"], "tokens": ["asakabank", "asaka"]},
    "Davlat xizmatlari": {"kw": ["my.gov", "davlat xizmatlari", "yagona interaktiv", "egov", "госуслуг"], "domains": ["gov.uz"], "tokens": ["mygov", "govuz", "egov"]},
    "Soliq": {"kw": ["soliq qo'mitasi", "soliq.uz", "налоговая"], "domains": ["soliq.uz"], "tokens": ["soliq"]},
    "Telegram": {
        "kw": ["telegram", "телеграм", "телеграмм"],
        "domains": ["telegram.org", "t.me", "telegram.me", "telegra.ph", "telegram.dog", "tdesktop.com", "telesco.pe", "fragment.com"],
        "tokens": ["telegram", "telegramm", "tgram", "telegrarn", "teiegram", "tlgrm", "tgpremium"],
    },
    "Instagram": {"kw": ["instagram", "инстаграм"], "domains": ["instagram.com", "cdninstagram.com"], "tokens": ["instagram", "lnstagram", "instagran"]},
    "OLX": {"kw": ["olx", "олх"], "domains": ["olx.uz"], "tokens": ["olx"]},
    "Beeline": {"kw": ["beeline", "билайн"], "domains": ["beeline.uz"], "tokens": ["beeline"]},
    "Ucell": {"kw": ["ucell", "юселл"], "domains": ["ucell.uz"], "tokens": ["ucell"]},
    "Uzmobile": {"kw": ["uzmobile", "uztelecom"], "domains": ["uztelecom.uz", "uzmobile.uz"], "tokens": ["uzmobile", "uztelecom"]},
    "Mobiuz": {"kw": ["mobiuz"], "domains": ["mobi.uz"], "tokens": ["mobiuz"]},
    "Paynet": {"kw": ["paynet"], "domains": ["paynet.uz"], "tokens": ["paynet"]},
    "Google": {"kw": [], "domains": ["google.com", "google.co.uz", "youtube.com", "youtu.be", "goo.gl", "g.co", "gstatic.com"], "tokens": ["google", "gogle", "googie"]},
}

# Rasmiy brend domenlari — tekshiruvsiz xavfsiz (lekin quyidagi istisnolar bundan mustasno)
SAFE_DOMAINS = {d for b in BRANDS.values() for d in b["domains"]} | {
    "wikipedia.org", "github.com", "apple.com", "microsoft.com", "linkedin.com", "facebook.com",
    "x.com", "twitter.com", "tiktok.com", "whatsapp.com", "kun.uz", "daryo.uz", "gazeta.uz",
    "uza.uz", "lex.uz", "president.uz", "spot.uz", "stackoverflow.com", "medium.com",
}
# Ishonchli domen bo'lsa ham ichida fishing joylashtirish mumkin bo'lgan manzillar
UNSAFE_SUBPATHS = (
    "docs.google.com/forms", "forms.gle", "sites.google.com", "script.google.com",
    "drive.google.com", "github.com/", "telegra.ph/",
)
# Ishonchli domen, lekin kontentni foydalanuvchi joylashtiradi — kontent tahlil qilinadi
USER_CONTENT_HOSTS = {"telegra.ph", "sites.google.com", "drive.google.com", "github.com", "docs.google.com"}

SUSPICIOUS_TLDS = {
    "xyz", "top", "icu", "click", "buzz", "shop", "online", "site", "live", "fun", "monster", "cfd",
    "sbs", "rest", "lol", "quest", "tk", "ml", "ga", "cf", "gq", "pw", "cc", "su", "bond", "cyou",
    "zip", "mov", "win", "bid", "loan", "work", "men", "today", "space", "store", "vip", "life",
    "pro", "asia", "click", "link", "gift", "help", "support", "info", "biz", "ru.com", "my.id",
}

FREE_HOSTING = (
    "vercel.app", "netlify.app", "github.io", "pages.dev", "workers.dev", "web.app", "firebaseapp.com",
    "glitch.me", "repl.co", "replit.app", "weebly.com", "wixsite.com", "000webhostapp.com", "ngrok-free.app",
    "ngrok.io", "ngrok.app", "trycloudflare.com", "serveo.net", "onrender.com", "blogspot.com",
    "herokuapp.com", "surge.sh", "tilda.ws", "webflow.io", "framer.website", "carrd.co", "square.site",
    "yolasite.com", "ucoz.net", "ucoz.ru", "narod.ru", "tiiny.site", "ipfs.io", "dweb.link", "r2.dev",
    "appspot.com", "azurewebsites.net", "cloudfront.net", "amplifyapp.com", "loca.lt", "duckdns.org",
)

SHORTENERS = {
    "bit.ly", "tinyurl.com", "cutt.ly", "is.gd", "clck.ru", "goo.su", "shorturl.at", "t.ly", "rebrand.ly",
    "u.to", "ow.ly", "buff.ly", "tiny.cc", "rb.gy", "v.gd", "qps.ru", "bitly.com", "shorturl.asia",
    "s.id", "lnk.to", "linktr.ee", "surl.li", "urlz.fr", "kurl.ru", "vk.cc", "t.co", "goo.gl",
}

URL_KEYWORDS = {
    # yuqori og'irlik
    "login": 10, "signin": 10, "verify": 10, "verification": 10, "auth": 8, "secure": 6, "account": 6,
    "gift": 12, "sovga": 15, "sovgа": 15, "bonus": 10, "prize": 12, "yutuq": 15, "aksiya": 12, "akciya": 12,
    "vote": 12, "ovoz": 15, "golos": 12, "premium": 10, "free": 6, "bepul": 12, "tasdiq": 12, "kod": 6,
    "konkurs": 12, "subsidiya": 12, "kompensatsiya": 12, "grant": 6, "nafaqa": 12, "payment": 6, "karta": 8,
    "wallet": 6, "airdrop": 12, "claim": 10, "reward": 10, "promo": 8, "apk": 15, "download": 4,
}

# Matndagi firibgarlik belgilari: (regex, og'irlik, izoh)
SCAM_TEXT_PATTERNS: list[tuple[str, int, str]] = [
    (r"sovg'?a|совға|совга|подар(о|к)|gift", 12, "«sovg'a» va'dasi"),
    (r"bepul|бесплатн|tekinga|текин", 8, "«bepul» va'dasi"),
    (r"yutu(q|b)|yutib ?ol|выигр|приз|mukofot|мукофот", 12, "yutuq/mukofot va'dasi"),
    (r"aksiya|акци(я|и)|konkurs|конкурс|розыгрыш", 8, "aksiya/konkurs"),
    (r"ovoz ber|овоз бер|голосу(й|йте)|проголосу|vote for", 18, "«ovoz bering» (mashhur fishing usuli)"),
    (r"qo'lga kirit|olib qoling|\boling(lar)?\b|забер(и|ите)|получи(те)? сейчас", 10, "«tez oling» chaqiruvi"),
    (r"menga ham (berishdi|berdi|tushdi)|men ham oldim|мне тоже (дали|пришл)|я тоже получил", 20, "«menga ham berishdi» (buzilgan akkaunt shabloni)"),
    (r"tasdiqlash kod|sms ?kod|код подтвержд|kodni (yubor|ayt|kirit)", 18, "tasdiqlash kodi so'ralmoqda"),
    (r"karta raqam|номер карт|cvv|amal qilish muddat", 15, "karta ma'lumoti so'ralmoqda"),
    (r"kompensatsiya|компенсац|subsidiya|субсид|nafaqa|нафақа|davlat yordami", 12, "soxta to'lov/kompensatsiya"),
    (r"telegram premium.{0,20}(bepul|tekin|sovg)|бесплатн.{0,15}premium|free premium", 18, "bepul Premium va'dasi"),
    (r"shoshiling|faqat bugun|cheklangan vaqt|успей|только сегодня|osta qoldi", 6, "shoshiltirish"),
    (r"\b\d{2,3}[ .,]?000\s*(so'm|сўм|сум|sum|ming|uzs)", 10, "aniq pul summasi va'dasi"),
    (r"(rasm|foto|photo|video|surat|сурат|фото)(lar|ni)?.{0,25}(ko'r|qara|кўр|смотр|ochib)", 8, "«rasmlarni ko'ring» (APK hiyla)"),
    (r"obuna bo'l(ing|ib)|подпиш(ись|итесь)", 4, "obuna chaqiruvi"),
    (r"pochta|posilka|посылк|yetkazib berish|доставк", 6, "pochta/posilka bahonasi"),
]

DANGEROUS_EXTS = {
    ".apk": 60, ".apks": 60, ".xapk": 60, ".apkm": 60, ".aab": 40,
    ".exe": 55, ".scr": 70, ".bat": 55, ".cmd": 55, ".msi": 50, ".js": 45, ".vbs": 60, ".jar": 45,
    ".lnk": 60, ".hta": 70, ".ps1": 55, ".com": 40, ".pif": 70, ".wsf": 60, ".dll": 40,
}
ARCHIVE_EXTS = {".zip", ".rar", ".7z"}
