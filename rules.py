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
    # Streamlined rules for efficient scam detection
    return [
        Rule(
            rule_id="payment_requests",
            title="Payment requests",
            description="Scammers often request upfront payments via gift cards, wire transfers, or crypto.",
            points=45,
            patterns=(
                re.compile(r"\bgift\s*cards?\b"),
                re.compile(r"\bwire\s*transfer\b"),
                re.compile(r"\bwestern\s*union\b"),
                re.compile(r"\bcrypto(?:currency)?\b"),
                re.compile(r"\bbitcoin\b"),
                re.compile(r"\bbtc\b"),
                re.compile(r"\bbank\s*transfer\b"),
                re.compile(r"\bprocessing\s*fee\b"),
                re.compile(r"\bregistration\s*fee\b"),
                re.compile(r"\bsecurity\s*deposit\b"),
                re.compile(r"\bupfront\s*payment\b"),
                re.compile(r"\bpay\s*before\s*starting\b"),
                re.compile(r"\btraining\s*fee\b"),
                re.compile(r"\bcourse\s*fee\b"),
                re.compile(r"\bpay\s*to\s*start\b"),
            ),
            suggestions=(
                "Never pay deposits or 'processing fees' to receive a job offer.",
                "Verify the employer and payment instructions via official channels.",
            ),
            keywords=("gift card", "wire transfer", "crypto", "processing fee", "registration fee"),
        ),
        Rule(
            rule_id="chat_app_only",
            title="Chat app communication only",
            description="Fake postings push candidates to communicate via Telegram/WhatsApp instead of formal channels.",
            points=30,
            patterns=(
                re.compile(r"\btelegram\b"),
                re.compile(r"\bwhatsapp\b"),
                re.compile(r"\bsignal\b"),
                re.compile(r"\btext\s+me\b"),
                re.compile(r"\bmessage\s+me\s+on\b"),
                re.compile(r"\bcontact\s+(?:me\s+)?on\s+(?:telegram|whatsapp|signal)\b"),
                re.compile(r"\badd\s+me\s+on\s+(?:telegram|whatsapp)\b"),
                re.compile(r"\bdm\s+me\b"),
            ),
            suggestions=(
                "Be cautious if the employer refuses standard application methods.",
                "Prefer official email domains and the company careers page.",
            ),
            keywords=("Telegram", "WhatsApp", "Signal", "text me", "DM me"),
        ),
        Rule(
            rule_id="urgency_pressure",
            title="Urgency and pressure tactics",
            description="Scams create deadlines to prevent verification.",
            points=25,
            patterns=(
                re.compile(r"\burgent\b"),
                re.compile(r"\bimmediately\b"),
                re.compile(r"\bas\s*soon\s*as\s*possible\b"),
                re.compile(r"\bapply\s+now\b"),
                re.compile(r"\blimited\s+(?:slots?|positions?|openings?)\b"),
                re.compile(r"\burgent\s+hiring\b"),
                re.compile(r"\bimmediate\s+(?:start|joining|hire)\b"),
                re.compile(r"\bhurry\b"),
                re.compile(r"\bdon'?t\s+miss\b"),
                re.compile(r"\blast\s+chance\b"),
            ),
            suggestions=("Take time to verify the posting; legitimate roles rarely require instant action.",),
            keywords=("urgent", "immediately", "apply now", "limited slots"),
        ),
        Rule(
            rule_id="no_interview_instant_hire",
            title="No interview or instant hire",
            description="Scams offer roles without screening or interviews.",
            points=35,
            patterns=(
                re.compile(r"\bno\s*interview\b"),
                re.compile(r"\binstant\s*(?:offer|hire)\b"),
                re.compile(r"\bguaranteed\s*(?:job|employment)\b"),
                re.compile(r"\bno\s*experience\s*required\b"),
                re.compile(r"\bhired\s+immediately\b"),
                re.compile(r"\bstart\s+(?:today|tomorrow|immediately)\b"),
                re.compile(r"\bno\s+screening\b"),
                re.compile(r"\bskip\s+(?:the\s+)?interview\b"),
            ),
            suggestions=(
                "Be skeptical of hiring processes that bypass interviews and standard checks.",
                "Research the company and look for consistent employment signals.",
            ),
            keywords=("instant offer", "guaranteed job", "no experience required", "no interview"),
        ),
        Rule(
            rule_id="unrealistic_promises",
            title="Unrealistic promises",
            description="Overly positive guarantees and unrealistic income claims.",
            points=30,
            patterns=(
                re.compile(r"\b100\s*%\b"),
                re.compile(r"\brisk[-\s]*free\b"),
                re.compile(r"\bguaranteed\s*income\b"),
                re.compile(r"\beasy\s+money\b"),
                re.compile(r"\bget\s+rich\b"),
                re.compile(r"\bpassive\s+income\b"),
                re.compile(r"\bearn\s+\$?\d{3,5}\s*(?:per|/|a)\s*day\b"),
                re.compile(r"\b\$\d{3,5}\s*(?:per|/|a)\s*day\b"),
                re.compile(r"\bhigh\s+income\s+potential\b"),
                re.compile(r"\bunlimited\s+(?:earning|income)\b"),
            ),
            suggestions=("Treat extreme guarantees as a red flag; verify compensation and requirements.",),
            keywords=("100%", "risk-free", "guaranteed income", "easy money", "earn per day"),
        ),
        Rule(
            rule_id="remote_no_experience",
            title="Remote work with no experience",
            description="Common scam pattern: remote work plus claims of needing no experience.",
            points=25,
            patterns=(
                re.compile(r"\bwork\s*from\s*home\b"),
                re.compile(r"\bremote\b"),
                re.compile(r"\bno\s*experience\b"),
                re.compile(r"\btrain\s*you\b"),
                re.compile(r"\bwe'?ll\s+train\b"),
                re.compile(r"\bno\s+skills\s+required\b"),
                re.compile(r"\banyone\s+can\s+apply\b"),
                re.compile(r"\bbeginners?\s+welcome\b"),
            ),
            suggestions=(
                "Remote jobs can be real, but scams often bundle 'no experience' and rapid onboarding.",
            ),
            keywords=("work from home", "remote", "no experience", "no skills required"),
        ),
        Rule(
            rule_id="suspicious_salary",
            title="Suspicious salary formats",
            description="Unusual salary formats and unrealistic compensation claims.",
            points=30,
            patterns=(
                re.compile(r"\bearn\s+\$?\d{3,4}\s*(?:per|/)\s*day\b"),
                re.compile(r"\b\$\d{3,4}\s*(?:per|/)\s*day\b"),
                re.compile(r"\bmake\s+\$?\d+\s*(?:per|/)\s*hour\b"),
                re.compile(r"\b\d+k?\s*(?:per|/)\s*(?:month|week)\b"),
                re.compile(r"\bsalary\s+range\s*\$\d+.*\$\d+\b"),
            ),
            suggestions=("Confirm salary ranges and tax/benefits details with the employer's official HR contact.",),
            keywords=("earn $", "per day", "salary range"),
        ),
        Rule(
            rule_id="identity_theft_risk",
            title="Identity theft risk",
            description="Requests for sensitive personal information early in the process.",
            points=35,
            patterns=(
                re.compile(r"\bssn\b"),
                re.compile(r"\bsocial\s+security\s+(?:number|#)\b"),
                re.compile(r"\bdriver'?s?\s+license\b"),
                re.compile(r"\bpassport\s+(?:number|#)\b"),
                re.compile(r"\bbank\s+(?:account|routing)\b"),
                re.compile(r"\bcredit\s+card\b"),
                re.compile(r"\bsend\s+(?:me\s+)?(?:your\s+)?(?:id|identification)\b"),
            ),
            suggestions=(
                "Never share sensitive personal information before verifying the employer.",
                "Legitimate employers request this information only after formal job offers.",
            ),
            keywords=("SSN", "social security", "driver's license", "bank account", "credit card"),
        ),
        Rule(
            rule_id="crypto_investment_scam",
            title="Crypto or investment scam",
            description="Job postings that are actually cryptocurrency or investment scams.",
            points=40,
            patterns=(
                re.compile(r"\b(?:trade|trading)\s+(?:crypto|bitcoin|ethereum)\b"),
                re.compile(r"\bcrypto\s+(?:investment|trading)\b"),
                re.compile(r"\bbitcoin\s+(?:mining|investment)\b"),
                re.compile(r"\bforex\s+trading\b"),
                re.compile(r"\bbinary\s+options?\b"),
                re.compile(r"\binvestment\s+(?:opportunity|scheme)\b"),
                re.compile(r"\bhigh\s+(?:roi|return)\b"),
            ),
            suggestions=(
                "These are typically investment scams disguised as job offers.",
                "Never invest money based on a job posting.",
            ),
            keywords=("crypto trading", "bitcoin mining", "forex trading", "binary options"),
        ),
        Rule(
            rule_id="generic_email",
            title="Generic email domains",
            description="Legit companies usually use their own domain; generic inboxes can be a warning signal.",
            points=15,
            patterns=(
                re.compile(r"\b[\w\.-]+@(?:gmail|yahoo|outlook|hotmail)\.com\b"),
                re.compile(r"\bcontact@(?:gmail|yahoo|outlook|hotmail)\.com\b"),
                re.compile(r"\bhr@(?:gmail|yahoo|outlook|hotmail)\.com\b"),
            ),
            suggestions=("Verify the sender and domain; look up the company's official email format.",),
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
    
    # Track strong rule matches for minimum score enforcement
    strong_rule_matches = 0
    STRONG_RULES = {
        "payment_requests", "crypto_investment_scam", "identity_theft_risk", "no_interview_instant_hire"
    }

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
                continue

        if not matched_phrases:
            continue

        # Track strong rule matches
        if rule.rule_id in STRONG_RULES:
            strong_rule_matches += 1

        # AGGRESSIVE SCORING: Amplify score for multiple matches in same rule
        base_points = rule.points
        match_count = len(matched_phrases)
        
        # If multiple matches in same rule, amplify the score
        if match_count >= 3:
            amplified_points = int(base_points * 1.5)  # 50% boost for 3+ matches
        elif match_count >= 2:
            amplified_points = int(base_points * 1.25)  # 25% boost for 2 matches
        else:
            amplified_points = base_points
        
        raw_score += amplified_points
        uniq_phrases = list(dict.fromkeys(matched_phrases))[:6]

        matches.append(
            {
                "rule_id": rule.rule_id,
                "title": rule.title,
                "description": rule.description,
                "points": amplified_points,
                "base_points": base_points,
                "matched_phrases": uniq_phrases,
                "match_count": match_count,
            }
        )

        # Keywords are used for highlighting; include both rule keywords and matched phrases.
        for k in rule.keywords:
            suspicious_keywords.append(k)
        for p in uniq_phrases:
            suspicious_keywords.append(p)

        for s in rule.suggestions:
            suggestions.append(s)

    # ENHANCED MINIMUM RULE SCORE ENFORCEMENT
    # If ANY strong rule matches → minimum rule_score = 35
    # If 2+ strong rules → minimum rule_score = 55
    if strong_rule_matches >= 2:
        raw_score = max(raw_score, 55)
    elif strong_rule_matches >= 1:
        raw_score = max(raw_score, 35)
    # If ANY suspicious keyword exists, minimum score is 25
    elif suspicious_keywords and raw_score < 25:
        raw_score = 25

    rule_score = max(0, min(100, int(round(raw_score))))

    # Deduplicate while preserving order.
    suspicious_keywords = list(dict.fromkeys([k for k in suspicious_keywords if k]))
    suggestions = list(dict.fromkeys([s for s in suggestions if s]))

    return rule_score, matches, suspicious_keywords, suggestions


def risk_band_from_score(score: int) -> str:
    # Updated risk bands for stricter detection
    if score >= 76:
        return "Critical"
    if score >= 51:
        return "High"
    if score >= 21:
        return "Medium"
    return "Low"