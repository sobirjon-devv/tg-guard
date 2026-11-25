from __future__ import annotations

from dataclasses import dataclass, field

SAFE, SUSPICIOUS, MALICIOUS = "safe", "suspicious", "malicious"
_RANK = {SAFE: 0, SUSPICIOUS: 1, MALICIOUS: 2}


@dataclass
class Finding:
    target: str                 # URL yoki fayl nomi
    kind: str                   # "url" | "file"
    score: int = 0
    reasons: list[str] = field(default_factory=list)
    hard: bool = False          # ishonchli manba tasdiqladi (VT/GSB/URLhaus/blocklist)
    trusted: bool = False       # rasmiy/ishonchli domen
    final_url: str | None = None
    # Aniq hisobot uchun
    details: dict = field(default_factory=dict)   # chain, ip, country, age_days, title, asks, downloads...
    checks: dict = field(default_factory=dict)    # manba -> natija ("toza", "XAVFLI", "5/94"...)
    tags: set = field(default_factory=set)        # tahdid turi: tg_steal, card, apk, brand, known
    screenshot: bytes | None = None

    def copy(self) -> "Finding":
        import copy as _c
        shot, self.screenshot = self.screenshot, None
        f = _c.deepcopy(self)
        self.screenshot = f.screenshot = shot
        return f

    weights: dict = field(default_factory=dict)  # sabab -> ball (eng muhimini birinchi ko'rsatish uchun)

    strong: bool = False   # kuchli dalil bor (brend taqlidi, yangi domen, Telegram infratuzilmasi, zararli fayl...)

    def add(self, pts: int, why: str, strong: bool = False):
        if strong:
            self.strong = True
        if why not in self.reasons:
            self.reasons.append(why)
            self.weights[why] = pts
            self.score += pts

    def mark_hard(self, why: str, tag: str = "known"):
        self.hard = True
        self.tags.add(tag)
        if why not in self.reasons:
            self.reasons.insert(0, why)
        self.weights[why] = 1000
        self.score = max(self.score, 100)

    def top_reasons(self, n: int) -> list[str]:
        return sorted(self.reasons, key=lambda r: -self.weights.get(r, 5))[:n]

    def level(self, mal: int, sus: int) -> str:
        # Kuchli dalilsiz (faqat taxminiy belgilar bilan) hech bir sayt «xavfli» deb topilmaydi
        if not self.hard and not self.strong and self.score >= mal:
            return SUSPICIOUS
        if self.hard or self.score >= mal:
            return MALICIOUS
        if self.score >= sus:
            return SUSPICIOUS
        return SAFE


@dataclass
class Verdict:
    level: str = SAFE
    findings: list[Finding] = field(default_factory=list)
    policy_block: str | None = None   # siyosat bo'yicha bloklash sababi (masalan, qat'iy APK rejimi)
    elapsed: float = 0.0
    fast: bool = False                # lokal tekshiruvda darhol aniqlandi (sandbox keyin boyitadi)

    @property
    def worst(self) -> Finding | None:
        return max(self.findings, key=lambda f: (f.hard, f.score), default=None)

    def bump(self, level: str):
        if _RANK[level] > _RANK[self.level]:
            self.level = level
