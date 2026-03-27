import re
from dataclasses import dataclass
from typing import Any, Dict, List, Pattern, Tuple


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    description: str
    points: int
    patterns: Tuple[Pattern[str], ...]
    suggestions: Tuple[str, ...] = ()
    keywords: Tuple[str, ...] = ()


def _compile_rules() -> List[Rule]:
    # These are intentionally conservative heuristics designed to be explainable.
    # They aim to catch common scam behaviors, not to blacklist legitimate offers.
    return [
        Rule(
            rule_id="gift_cards_or_wire",
            title="Upfront payments / gift cards",
            description="Scammers often request payment via gift cards, wire transfers, or similar methods.",
            points=45,
            patterns=(
                re.compile(r"\bgift\s*cards?\b"),
                re.compile(r"\bwire\s*transfer\b"),
                re.compile(r"\bwestern\s*union\b"),
                re.compile(r"\bpay\s*pal\s*(friends|family)\b"),
                re.compile(r"\bcrypto(?!\s+trading)\b"),
                re.compile(r"\bcryptocurrency\b"),
                re.compile(r"\bbitcoin\b"),
                re.compile(r"\bbtc\b"),
                re.compile(r"\bbank\s*transfer\b"),
                re.compile(r"\bdeposit\s*to\b"),
                re.compile(r"\bprocessing\s*fee\b"),
            ),
            suggestions=(
                "Never pay deposits or 'processing fees' to receive a job offer.",
                "Verify the employer and payment instructions via official channels.",
            ),
            keywords=("gift card", "wire transfer", "crypto", "processing fee", "bank transfer"),
        ),
        Rule(
            rule_id="telegram_or_whatsapp_only",
            title="Only contact via chat apps",
            description="Some fake postings push candidates to communicate via Telegram/WhatsApp/Signal instead of formal channels.",
            points=35,
            patterns=(
                re.compile(r"\btelegram\b"),
                re.compile(r"\bwhatsapp\b"),
                re.compile(r"\bsignal\b"),
                re.compile(r"\btext\s+me\b"),
                re.compile(r"\bmessage\s+me\s+on\b"),
            ),
            suggestions=(
                "Be cautious if the employer refuses standard application methods.",
                "Prefer official email domains and the company careers page.",
            ),
            keywords=("Telegram", "WhatsApp", "Signal", "text me"),
        ),
        Rule(
            rule_id="urgency_pressure",
            title="Urgency / pressure tactics",
            description="Scams often create deadlines to prevent verification.",
            points=32,
            patterns=(
                re.compile(r"\burgent\b"),
                re.compile(r"\bimmediately\b"),
                re.compile(r"\bas\s*soon\s*as\s*possible\b"),
                re.compile(r"\btoday\b"),
                re.compile(r"\b24\s*/\s*7\b"),
                re.compile(r"\bacting\s+now\b"),
            ),
            suggestions=("Take time to verify the posting; legitimate roles rarely require instant action.",),
            keywords=("urgent", "immediately", "as soon as possible"),
        ),
        Rule(
            rule_id="no_interview_or_instant_offer",
            title="No interview / instant offer",
            description="Some scams offer roles without screening or interviews.",
            points=38,
            patterns=(
                re.compile(r"\bno\s*interview\b"),
                re.compile(r"\binstant\s*(offer|hire)\b"),
                re.compile(r"\boffer\s*letter\s*today\b"),
                re.compile(r"\bguaranteed\s*(job|employment)\b"),
                re.compile(r"\bno\s*experience\s*required\b"),
            ),
            suggestions=(
                "Be skeptical of hiring processes that bypass interviews and standard checks.",
                "Research the company and look for consistent employment signals (team, location, benefits).",
            ),
            keywords=("instant offer", "guaranteed job", "no experience required"),
        ),
        Rule(
            rule_id="too_good_to_be_true",
            title="Unrealistic promises",
            description="Overly positive guarantees like '100%' or 'risk-free' can indicate scams.",
            points=30,
            patterns=(
                re.compile(r"\b100\s*%\b"),
                re.compile(r"\brisk[-\s]*free\b"),
                re.compile(r"\bhigh\s*income\b"),
                re.compile(r"\bguaranteed\s*income\b"),
                re.compile(r"\boutstanding\s*pay\b"),
            ),
            suggestions=("Treat extreme guarantees as a red flag; verify compensation and requirements.",),
            keywords=("100%", "risk-free", "guaranteed income"),
        ),
        Rule(
            rule_id="work_from_home_no_experience",
            title="Remote + no experience angle",
            description="A common scam pattern is remote work plus claims of needing no experience.",
            points=33,
            patterns=(
                re.compile(r"\bwork\s*from\s*home\b"),
                re.compile(r"\bremote\b"),
                re.compile(r"\bno\s*experience\b"),
                re.compile(r"\btrain\s*you\b"),
            ),
            suggestions=(
                "Remote jobs can be real, but scams often bundle 'no experience' and rapid onboarding.",
            ),
            keywords=("work from home", "remote", "no experience"),
        ),
        Rule(
            rule_id="unusual_salary_bands",
            title="Suspicious compensation wording",
            description="Certain salary formats and unusually broad numbers can correlate with scams.",
            points=34,
            patterns=(
                re.compile(r"(?:\bcompensation\b|\bsalary\b).{0,40}\$\s?\d{2,3}(?:[,\d]{0,3})+(?:\s*(?:/)?\s*(?:month|year|week))?"),
                re.compile(r"\$\s?\d{2,3}(?:[,\d]{0,3})\s*(?:/)?\s*(?:month|year|week)"),
                re.compile(r"\b(?:earn|income)\s*\$\s?\d{2,3}(?:[,\d]{0,3})\b"),
            ),
            suggestions=("Confirm salary ranges and tax/benefits details with the employer’s official HR contact.",),
            keywords=("salary", "compensation", "earn $"),
        ),
        Rule(
            rule_id="training_or_course_fee",
            title="Pays for training / course fees",
            description="Scams may ask candidates to pay for training, onboarding, or materials before employment.",
            points=40,
            patterns=(
                re.compile(r"\btraining\s*fee\b"),
                re.compile(r"\bcourse\s*fee\b"),
                re.compile(r"\bpay\s*for\s*training\b"),
                re.compile(r"\bpay\s*to\s*start\b"),
                re.compile(r"\bmaterials\s*fee\b"),
                re.compile(r"\bonboarding\s*fee\b"),
            ),
            suggestions=("Legitimate training is normally paid by the employer; avoid paying fees to start.",),
            keywords=("training fee", "course fee", "materials fee"),
        ),
        Rule(
            rule_id="generic_email_domain",
            title="Generic or mismatched email",
            description="Legit companies usually use their own domain; generic inboxes can be a warning signal.",
            points=27,
            patterns=(
                re.compile(r"\b[\w\.-]+@(gmail|yahoo|outlook|hotmail)\.com\b"),
                re.compile(r"\bcontact@(gmail|yahoo|outlook|hotmail)\.com\b"),
            ),
            suggestions=("Verify the sender and domain; look up the company’s official email format.",),
            keywords=("gmail.com", "outlook.com", "hotmail.com"),
        ),
    ]


RULES: List[Rule] = _compile_rules()


def analyze_rules(text: str) -> Tuple[int, List[Dict[str, Any]], List[str], List[str]]:
    """
    Returns:
      rule_score (0-100),
      matches (explainable rule matches),
      suspicious_keywords (for UI highlighting),
      suggestions (deduped, aggregated)
    """
    if not text or not text.strip():
        return 0, [], [], []

    lowered = text.lower()

    raw_score = 0
    matches: List[Dict[str, Any]] = []
    suspicious_keywords: List[str] = []
    suggestions: List[str] = []

    for rule in RULES:
        matched_phrases: List[str] = []
        # Keep matches limited so explanations stay readable.
        for pattern in rule.patterns:
            try:
                for m in pattern.finditer(lowered):
                    phrase = m.group(0).strip()
                    if phrase:
                        matched_phrases.append(phrase)
                    if len(matched_phrases) >= 6:
                        break
            except re.error:
                # If a regex fails (shouldn't happen after compilation), ignore it.
                continue

        if not matched_phrases:
            continue

        raw_score += rule.points
        uniq_phrases = list(dict.fromkeys(matched_phrases))[:6]

        matches.append(
            {
                "rule_id": rule.rule_id,
                "title": rule.title,
                "description": rule.description,
                "points": rule.points,
                "matched_phrases": uniq_phrases,
            }
        )

        # Keywords are used for highlighting; include both rule keywords and matched phrases.
        for k in rule.keywords:
            suspicious_keywords.append(k)
        for p in uniq_phrases:
            suspicious_keywords.append(p)

        for s in rule.suggestions:
            suggestions.append(s)

    rule_score = max(0, min(100, int(round(raw_score))))

    # Deduplicate while preserving order.
    suspicious_keywords = list(dict.fromkeys([k for k in suspicious_keywords if k]))
    suggestions = list(dict.fromkeys([s for s in suggestions if s]))

    return rule_score, matches, suspicious_keywords, suggestions


def risk_band_from_score(score: int) -> str:
    if score >= 85:
        return "Critical"
    if score >= 65:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"

