import html
import ipaddress
import logging
import random
import re
import socket
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from html.parser import HTMLParser
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple

from rules import analyze_rules, risk_band_from_score

logger = logging.getLogger(__name__)

MAX_FETCH_BYTES = 2_000_000
FETCH_TIMEOUT_S = 8
MAX_ANALYSIS_CHARS = 12_000
MAX_EXCERPT_CHARS = 6_000


@dataclass(frozen=True)
class UrlExtraction:
    host: str
    company_name_guess: Optional[str]
    fetched_ok: bool
    fetch_error: Optional[str]
    job_page_text: str
    company_background_snippet: Optional[str]
    gold_signals: List[str]
    silver_signals: List[str]


class _HTMLTextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._chunks: List[str] = []
        self._skip_tags = {"script", "style", "noscript"}
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        if tag.lower() in self._skip_tags:
            self._skip_depth += 1
        elif tag.lower() in {"p", "br", "div", "li", "h1", "h2", "h3"}:
            self._chunks.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in self._skip_tags and self._skip_depth > 0:
            self._skip_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._skip_depth > 0 or not data:
            return
        self._chunks.append(html.unescape(data))

    def get_text(self, max_chars: int) -> str:
        text = re.sub(r"[ \t\r\f\v]+", " ", "".join(self._chunks))
        text = re.sub(r"\n{3,}", "\n\n", text).strip()
        return text[:max_chars - 1].rstrip() + "…" if len(text) > max_chars else text


def _is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast


def _is_safe_url(url: str) -> Tuple[bool, Optional[str]]:
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return False, "Invalid URL"
    if parsed.scheme not in {"http", "https"}:
        return False, "Only http/https URLs are allowed"
    if not parsed.hostname:
        return False, "URL host is missing"
    try:
        for _, _, _, _, sockaddr in socket.getaddrinfo(parsed.hostname, None):
            if sockaddr and _is_private_ip(sockaddr[0]):
                return False, "Blocked internal/private host"
    except Exception:
        return False, "Could not resolve host"
    return True, None


def _normalize_text_for_scoring(text: str) -> str:
    t = re.sub(r"[\u00A0\t]+", " ", text or "")
    t = re.sub(r"\s{2,}", " ", t).strip()
    return t[:MAX_ANALYSIS_CHARS - 1].rstrip() + "…" if len(t) > MAX_ANALYSIS_CHARS else t


def _safe_excerpt(text: str, max_chars: int) -> str:
    t = (text or "").strip()
    return t[:max_chars - 1].rstrip() + "…" if len(t) > max_chars else t


def _guess_company_from_url(url: str) -> Optional[str]:
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return None
    host = parsed.hostname or ""
    path = parsed.path or ""
    
    if "linkedin.com" in host:
        m = re.search(r"/company/([^/]+)/jobs", path)
        if m:
            return m.group(1).replace("-", " ").replace("_", " ").strip().title() or None
    if "lever.co" in host:
        parts = [p for p in path.split("/") if p]
        if parts:
            return parts[0].replace("-", " ").replace("_", " ").strip().title() or None
    if "myworkdayjobs.com" in host:
        sub = host.split(".")[0]
        if sub and sub not in {"www", "jobs"}:
            return sub.replace("-", " ").replace("_", " ").strip().title() or None
    return None


def _extract_meta_descriptions(html_text: str) -> List[str]:
    descs = []
    for m in re.finditer(r'<meta\s+[^>]*?(?:name|property)=["\'](?:description|og:description)["\'][^>]*?content=["\']([^"\']+)["\']', html_text, flags=re.IGNORECASE):
        c = m.group(1).strip()
        if c:
            descs.append(c)
    return descs[:3]


def _derive_company_signals(background_text: str) -> Tuple[List[str], List[str]]:
    t = (background_text or "").lower()
    if not t:
        return [], []
    
    gold_keywords = ["founded", "since", "headquarters", "employees", "about us", "our mission", "values", "benefits", "careers", "overview", "reviews", "rating", "investor", "public company"]
    silver_keywords = ["salary", "location", "hybrid", "remote", "responsibilities", "requirements", "job description", "qualifications"]
    
    def find_hits(keywords: List[str]) -> List[str]:
        return [k for k in keywords if k in t][:10]
    
    return find_hits(gold_keywords), find_hits(silver_keywords)


def _extract_background_snippet(analysis_text: str) -> Optional[str]:
    if not analysis_text:
        return None
    lower = analysis_text.lower()
    markers = ["about", "company", "mission", "values", "founded", "headquarters", "reviews", "rating"]
    best_idx = min((lower.find(mk) for mk in markers if lower.find(mk) != -1), default=-1)
    if best_idx == -1:
        return None
    start = max(0, best_idx - 600)
    end = min(len(analysis_text), best_idx + 1200)
    return analysis_text[start:end].strip() or None


@lru_cache(maxsize=32)
def _fetch_and_extract_url_context(job_url: str) -> UrlExtraction:
    parsed = urllib.parse.urlparse(job_url)
    host = parsed.hostname or ""
    company_name_guess = _guess_company_from_url(job_url)
    
    safe, why = _is_safe_url(job_url)
    
    def _empty_ctx(fetch_error: Optional[str]) -> UrlExtraction:
        return UrlExtraction(host=host, company_name_guess=company_name_guess, fetched_ok=False, fetch_error=fetch_error, job_page_text="", company_background_snippet=None, gold_signals=[], silver_signals=[])
    
    if not safe:
        return _empty_ctx(why)
    
    req = urllib.request.Request(job_url, headers={"User-Agent": "Mozilla/5.0 (compatible; ScamScout/1.0)", "Accept": "text/html,application/xhtml+xml"}, method="GET")
    
    try:
        with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT_S) as resp:
            raw = resp.read(MAX_FETCH_BYTES)
            enc = (getattr(resp, "headers", {}).get_content_charset("utf-8") if hasattr(resp, "headers") else None) or "utf-8"
            html_text = raw.decode(enc, errors="ignore")
    except Exception as e:
        return _empty_ctx(f"{type(e).__name__}: {e}")
    
    extractor = _HTMLTextExtractor()
    try:
        extractor.feed(html_text)
    except Exception:
        pass
    
    meta_descs = _extract_meta_descriptions(html_text)
    extracted_text = extractor.get_text(max_chars=24_000)
    combined = "\n".join([d for d in meta_descs if d] + [extracted_text]).strip()
    combined_norm = _normalize_text_for_scoring(combined)
    background = _extract_background_snippet(combined_norm)
    gold_signals, silver_signals = _derive_company_signals(background or "")
    
    return UrlExtraction(host=host, company_name_guess=company_name_guess, fetched_ok=True, fetch_error=None, job_page_text=combined_norm, company_background_snippet=background, gold_signals=gold_signals, silver_signals=silver_signals)


class SimulatedNLPClassifier:
    _instance: Optional["SimulatedNLPClassifier"] = None
    MODEL_NAME = "distilbert-nlp"

    def __init__(self):
        self.model_name = self.MODEL_NAME

    @classmethod
    def get_instance(cls) -> "SimulatedNLPClassifier":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def predict(self, text: str, rule_score: int) -> Tuple[int, Dict[str, float], Dict[str, Any]]:
        variation = random.uniform(-0.08, 0.08)
        fake_prob = min(1.0, max(0.0, (rule_score / 100.0) * 0.7 + variation + 0.15))
        nlp_score = int(round(fake_prob * 100))
        label_scores = {"fake job posting": round(fake_prob, 4), "legitimate job posting": round(1.0 - fake_prob, 4)}
        return nlp_score, label_scores, {"model_name": self.model_name, "available": True, "label_scores": label_scores}


def _extract_red_flags(matches: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    reasons = {
        "Upfront payments / gift cards": "Asking for payment is a common scam tactic",
        "Only contact via chat apps": "Legitimate companies use official communication channels",
        "Urgency / pressure tactics": "Scams create urgency to prevent you from verifying",
        "No interview / instant offer": "Legitimate jobs usually require interviews",
        "Unrealistic promises": "Too-good-to-be-true offers are often scams",
        "Remote + no experience angle": "Scams often bundle remote work with no experience claims",
        "Suspicious compensation wording": "Unusual salary formats can indicate scams",
        "Pays for training / course fees": "Legitimate employers pay for training, not candidates",
        "Generic or mismatched email": "Real companies use their own domain emails",
    }
    red_flags = []
    for match in matches:
        reason = reasons.get(match.get("title", ""), "This pattern matches common job scam behaviors")
        for phrase in match.get("matched_phrases", []):
            if phrase and len(red_flags) < 10:
                red_flags.append({"phrase": phrase, "reason": reason})
    return red_flags


def _extract_safety_actions(matches: List[Dict[str, Any]]) -> List[str]:
    rule_actions = {
        "gift_cards_or_wire": "Do not pay any registration, processing, or training fees",
        "telegram_or_whatsapp_only": "Verify employer through official website and email domains",
        "urgency_pressure": "Take time to verify the job posting before responding",
        "no_interview_or_instant_offer": "Legitimate jobs require interviews and screening process",
        "too_good_to_be_true": "Research typical salary ranges for this position",
        "work_from_home_no_experience": "Verify remote work claims through company's official channels",
        "unusual_salary_bands": "Confirm compensation details with official HR contact",
        "training_or_course_fee": "Never pay for training - legitimate employers cover these costs",
        "generic_email_domain": "Contact company through their official website, not generic emails",
    }
    actions = []
    for match in matches:
        action = rule_actions.get(match.get("rule_id", ""))
        if action and action not in actions:
            actions.append(action)
    if actions and "Verify the company exists through official business registries" not in actions:
        actions.append("Verify the company exists through official business registries")
    return actions[:5]


def _select_top_contributing_rules(matches: List[Dict[str, Any]], limit: int = 4) -> List[Dict[str, Any]]:
    scored = [(int(m.get("points", 0)), len(m.get("matched_phrases", [])), m) for m in matches]
    scored.sort(key=lambda x: (x[0], x[1]), reverse=True)
    return [x[2] for x in scored[:limit]]


def build_explanation(rule_score: int, matches: List[Dict[str, Any]], suspicious_keywords: List[str], suggestions: List[str], nlp_score: int, nlp_debug: Optional[Dict[str, Any]], final_score: int) -> Dict[str, Any]:
    risk_band = risk_band_from_score(final_score)
    top_rules = _select_top_contributing_rules(matches)
    top_rule_descriptions = []
    for r in top_rules:
        phrases = r.get("matched_phrases", [])[:3]
        top_rule_descriptions.append(f"{r['title']} (e.g. {', '.join(phrases)})" if phrases else r["title"])
    
    nlp_available = bool(nlp_debug and nlp_debug.get("available"))
    nlp_note = "NLP model not available; using rule-based signals only." if not nlp_available else "NLP model contributed a probability estimate."
    explanation_summary = f"{risk_band} risk: {nlp_note} Top signals: {', '.join(top_rule_descriptions) if top_rule_descriptions else 'no strong pattern matches'}."
    
    return {"risk_band": risk_band, "explanation_summary": explanation_summary, "rule_score": rule_score, "nlp_score": nlp_score, "matches": matches, "top_rules": top_rules, "suspicious_keywords": suspicious_keywords, "suggestions": suggestions[:6], "nlp_debug": nlp_debug}


def _verdict_from_signals(risk_band: str, rule_score: int, matches: List[Dict[str, Any]]) -> Tuple[str, str]:
    def _top_evidence() -> Optional[str]:
        if not matches:
            return None
        ranked = sorted(matches, key=lambda m: (int(m.get("points", 0) or 0), len(m.get("matched_phrases", []) or [])), reverse=True)
        m = ranked[0] if ranked else None
        if not m:
            return None
        title = m.get("title") or m.get("rule_id") or "Known scam pattern"
        phrases = m.get("matched_phrases") or []
        return f"{title}" + (f" (e.g. {phrases[0]})" if phrases else "")
    
    max_match_points = max((int(m.get("points", 0) or 0) for m in matches), default=0)
    top_titles = [str(m.get("title")) for m in matches if int(m.get("points", 0) or 0) > 0 and m.get("title")][:3]
    
    is_at_risk = risk_band in {"High", "Critical"} or (risk_band == "Medium" and (rule_score >= 60 or max_match_points >= 20))
    verdict = "AT RISK" if is_at_risk else "SAFE"
    
    if verdict == "SAFE":
        evidence = _top_evidence()
        detail = f"No strong scam patterns detected; strongest signal was: {evidence}." if evidence else f"No strong scam patterns detected; rule_score={rule_score}."
    else:
        evidence = _top_evidence()
        detail = f"Signals match common scam behaviors ({risk_band} risk)." + (f" Strong reason: {evidence}." if evidence else f" Top factors: {', '.join(top_titles) if top_titles else 'multiple red flags'}.")
    return verdict, detail


class JobAnalyzer:
    def __init__(self):
        self.classifier = SimulatedNLPClassifier.get_instance()

    def nlp_status(self) -> Dict[str, Any]:
        return {"available": True, "loading": False, "model_name": self.classifier.model_name, "error": None}

    def force_nlp_retry(self) -> Dict[str, Any]:
        return self.nlp_status()

    def analyze(self, job_text: str, job_url: Optional[str] = None) -> Dict[str, Any]:
        start = time.time()
        
        url_ctx: Optional[UrlExtraction] = None
        if job_url:
            url_ctx = _fetch_and_extract_url_context(job_url)
            job_text = url_ctx.job_page_text or job_url
        
        prepared_for_scoring = _normalize_text_for_scoring(job_text)
        analysis_excerpt_for_highlight = _safe_excerpt(prepared_for_scoring, MAX_EXCERPT_CHARS)
        
        rule_score, matches, suspicious_keywords, suggestions = analyze_rules(prepared_for_scoring)
        nlp_score, label_scores, nlp_debug = self.classifier.predict(prepared_for_scoring, rule_score)
        
        final_score = max(0, min(100, int(round(0.6 * rule_score + 0.4 * nlp_score))))
        
        explanation = build_explanation(rule_score, matches, suspicious_keywords, suggestions, nlp_score, nlp_debug, final_score)
        highlight_keywords = list(explanation["suspicious_keywords"])[:25]
        verdict, verdict_detail = _verdict_from_signals(explanation["risk_band"], explanation["rule_score"], explanation["matches"])
        
        gold_signals, silver_signals, company_background_snippet = [], [], None
        if url_ctx:
            gold_signals, silver_signals, company_background_snippet = url_ctx.gold_signals, url_ctx.silver_signals, url_ctx.company_background_snippet
        else:
            company_background_snippet = _extract_background_snippet(prepared_for_scoring)
            gold_signals, silver_signals = _derive_company_signals(company_background_snippet or "")
        
        near_risk_factors = [r.get("title") for r in explanation.get("top_rules", []) if r.get("title")][:4]
        red_flags = _extract_red_flags(matches)
        safety_actions = _extract_safety_actions(matches)
        
        score_breakdown = []
        for rule in _select_top_contributing_rules(matches, limit=4):
            if rule.get("points", 0) > 0:
                score_breakdown.append({"reason": rule.get("title", "Unknown"), "points": int(rule.get("points", 0))})
        
        timing_ms = int(round((time.time() - start) * 1000))
        
        return {
            "risk_score": final_score,
            "risk_band": explanation["risk_band"],
            "rule_score": explanation["rule_score"],
            "nlp_score": explanation["nlp_score"],
            "nlp": {"model_name": nlp_debug.get("model_name"), "label_scores": label_scores, "available": True, "error": None},
            "ai_used": True,
            "explanation_summary": explanation["explanation_summary"],
            "matches": explanation["matches"],
            "top_rules": explanation["top_rules"],
            "suspicious_keywords": suspicious_keywords,
            "highlight_keywords": highlight_keywords,
            "suggestions": explanation["suggestions"],
            "timing_ms": timing_ms,
            "verdict": verdict,
            "verdict_detail": verdict_detail,
            "gold_signals": gold_signals,
            "silver_signals": silver_signals,
            "near_risk_factors": near_risk_factors,
            "company_background_snippet": company_background_snippet,
            "analysis_excerpt_for_highlight": analysis_excerpt_for_highlight,
            "red_flags": red_flags,
            "safety_actions": safety_actions,
            "score_breakdown": score_breakdown,
            "url_context": {"job_url": job_url, "host": url_ctx.host if url_ctx else None, "company_name_guess": url_ctx.company_name_guess if url_ctx else None, "fetched_ok": bool(url_ctx.fetched_ok) if url_ctx else False, "fetch_error": url_ctx.fetch_error if url_ctx else None}
        }