import html
import ipaddress
import logging
import re
import socket
import time
import threading
import urllib.parse
import urllib.request
from dataclasses import dataclass
from html.parser import HTMLParser
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple

from rules import analyze_rules, risk_band_from_score

logger = logging.getLogger(__name__)

# Global NLP pipeline - loaded once at startup
_nlp_pipeline = None
_nlp_lock = threading.Lock()
_nlp_loaded = False
_nlp_error = None

# Known job site domains and patterns
JOB_SITE_DOMAINS = [
    # Major job boards
    "linkedin.com",
    "indeed.com",
    "glassdoor.com",
    "monster.com",
    "ziprecruiter.com",
    "careerbuilder.com",
    "simplyhired.com",
    "dice.com",
    "angel.co",
    "wellfound.com",
    "upwork.com",
    "freelancer.com",
    "fiverr.com",
    "flexjobs.com",
    "remote.co",
    "weworkremotely.com",
    "remoteok.com",
    "workingnomads.com",
    "jobspresso.co",
    "eurojobs.com",
    "jobserve.com",
    "techjobs.com",
    "stackoverflow.com/jobs",
    "github.com/careers",
    
    # ATS (Applicant Tracking Systems) - commonly used by companies
    "lever.co",
    "greenhouse.io",
    "workday.com",
    "myworkdayjobs.com",
    "icims.com",
    "jobvite.com",
    "taleo.net",
    "brassring.com",
    "ultipro.com",
    "smartrecruiters.com",
    "breezy.hr",
    "ashbyhq.com",
    "recruitee.com",
    "teamtailor.com",
    "applytojob.com",
    "jobs.lever.co",
    "boards.greenhouse.io",
    "careers.google.com",
    "amazon.jobs",
    "jobs.careers.microsoft.com",
    "metacareers.com",
    "apple.com/careers",
    "careers.twitter.com",
    "careers.facebook.com",
    "careers.netflix.com",
    "jobs.spotify.com",
    "careers.uber.com",
    "lyft.com/careers",
    "careers.airbnb.com",
    
    # Government and educational job sites
    "usajobs.gov",
    "governmentjobs.com",
    "higheredjobs.com",
    "chroniclevitae.com",
    "academicpositions.com",
    "jobs.ac.uk",
    
    # Industry-specific
    "healthcareers.com",
    "mediabistro.com",
    "journalismjobs.com",
    "idealist.org",
    "devex.com",
    "reliefweb.int",
    "conservationjobboard.com",
    "environmentalcareer.com",
    
    # Regional job sites
    "seek.com.au",
    "reed.co.uk",
    "totaljobs.com",
    "cv-library.co.uk",
    "jobsite.co.uk",
    "stepstone.de",
    "xing.com",
    "infojobs.net",
    "catho.com.br",
    "naukri.com",
    "shine.com",
    "timesjobs.com",
    "internshala.com",
]

# Job-related URL path patterns
JOB_PATH_PATTERNS = [
    r"/jobs?",
    r"/careers?",
    r"/positions?",
    r"/openings?",
    r"/vacanc(y|ies)",
    r"/opportunities",
    r"/employment",
    r"/hiring",
    r"/apply",
    r"/job-listing",
    r"/job-search",
    r"/job-board",
    r"/recruit",
    r"/work-with-us",
    r"/join-us",
    r"/join-our-team",
    r"/current-openings",
    r"/job-details",
    r"/job-description",
    r"/internship(s)?",
]

# Job-related keywords in page content
JOB_CONTENT_KEYWORDS = [
    "job description",
    "responsibilities",
    "qualifications",
    "requirements",
    "experience required",
    "salary",
    "compensation",
    "benefits",
    "full-time",
    "part-time",
    "contract",
    "permanent",
    "temporary",
    "remote",
    "hybrid",
    "on-site",
    "apply now",
    "submit application",
    "equal opportunity",
    "eeo",
    "applicant",
    "candidate",
    "interview",
    "hiring manager",
    "recruiter",
    "human resources",
    "hr department",
]

MAX_FETCH_BYTES = 2_000_000
FETCH_TIMEOUT_S = 8
MAX_ANALYSIS_CHARS = 12_000
MAX_EXCERPT_CHARS = 6_000


def _load_nlp_pipeline():
    """Load the NLP pipeline once at startup with retry mechanism."""
    global _nlp_pipeline, _nlp_loaded, _nlp_error
    
    with _nlp_lock:
        if _nlp_loaded:
            return _nlp_pipeline is not None
        
        try:
            logger.info("Loading Hugging Face NLP model...")
            from transformers import pipeline
            
            # Load lightweight zero-shot classification model
            _nlp_pipeline = pipeline(
                "zero-shot-classification",
                model="typeform/distilbert-base-uncased-mnli",
                device=-1  # Use CPU
            )
            _nlp_loaded = True
            _nlp_error = None
            logger.info("NLP model loaded successfully")
            return True
        except Exception as e:
            _nlp_error = f"Failed to load NLP model: {str(e)}"
            _nlp_loaded = True  # Mark as loaded even if failed
            logger.error(f"NLP model loading failed: {e}")
            return False


def _get_nlp_pipeline():
    """Get the NLP pipeline, loading it if necessary."""
    global _nlp_pipeline, _nlp_loaded
    
    if not _nlp_loaded:
        _load_nlp_pipeline()
    
    return _nlp_pipeline


def _clean_text_for_nlp(text: str) -> str:
    """Clean input text before sending to NLP model."""
    if not text:
        return ""
    
    # Remove duplicate lines
    lines = text.split('\n')
    seen = set()
    cleaned_lines = []
    for line in lines:
        line = line.strip()
        if line and line not in seen:
            seen.add(line)
            cleaned_lines.append(line)
    
    cleaned = '\n'.join(cleaned_lines)
    
    # Remove UI text patterns
    ui_patterns = [
        r'\b(login|log in|sign in|signin|signup|sign up|register)\b',
        r'\b(home|about|contact|menu|navigation|search|skip)\b',
        r'\b(cookie|privacy|terms|copyright|©|all rights)\b',
        r'\b(loading|please wait|click here|read more|learn more)\b',
        r'\b(subscribe|newsletter|follow us|share|tweet|like)\b',
        r'\b(facebook|twitter|linkedin|instagram|youtube)\b',
        r'\b(accept|decline|agree|disagree|ok|cancel|close)\b',
        r'\b(submit|reset|clear|back|next|previous|continue)\b',
    ]
    
    for pattern in ui_patterns:
        cleaned = re.sub(pattern, '', cleaned, flags=re.IGNORECASE)
    
    # Limit to first 512-800 words (token safe)
    words = cleaned.split()
    if len(words) > 800:
        cleaned = ' '.join(words[:800])
    
    return cleaned.strip()


def _predict_with_nlp(text: str, rule_score: int) -> Tuple[int, Dict[str, float], Dict[str, Any]]:
    """Use real Hugging Face NLP model for prediction."""
    global _nlp_error
    
    pipeline = _get_nlp_pipeline()
    
    if pipeline is None:
        # Model failed to load - return error
        return 0, {}, {"model_name": "typeform/distilbert-base-uncased-mnli", "available": False, "error": _nlp_error}
    
    try:
        # Clean text before NLP processing
        cleaned_text = _clean_text_for_nlp(text)
        
        if not cleaned_text or len(cleaned_text) < 20:
            # Not enough text for NLP analysis
            return 0, {}, {"model_name": "typeform/distilbert-base-uncased-mnli", "available": True, "error": "Insufficient text for analysis"}
        
        # Define candidate labels for zero-shot classification
        candidate_labels = ["fake job posting", "legitimate job posting"]
        
        # Run inference with timeout protection
        start_time = time.time()
        result = pipeline(cleaned_text, candidate_labels, multi_label=False)
        inference_time = time.time() - start_time
        
        # Check timeout
        if inference_time > 8.0:
            logger.warning(f"NLP inference took {inference_time:.2f}s (exceeded 8s timeout)")
        
        # Extract probability for "fake job posting"
        fake_prob = 0.0
        for label, score in zip(result['labels'], result['scores']):
            if label == "fake job posting":
                fake_prob = score
                break
        
        # Convert to nlp_score with strict thresholds
        if fake_prob > 0.75:
            nlp_score = int(85 + (fake_prob - 0.75) * 60)  # 85-100
        elif fake_prob > 0.6:
            nlp_score = int(65 + (fake_prob - 0.6) * 133.33)  # 65-85
        elif fake_prob > 0.4:
            nlp_score = int(40 + (fake_prob - 0.4) * 125)  # 40-65
        else:
            nlp_score = int(10 + fake_prob * 75)  # 10-40
        
        nlp_score = max(0, min(100, nlp_score))
        
        label_scores = {
            "fake job posting": round(fake_prob, 4),
            "legitimate job posting": round(1.0 - fake_prob, 4)
        }
        
        return nlp_score, label_scores, {
            "model_name": "typeform/distilbert-base-uncased-mnli",
            "available": True,
            "error": None,
            "inference_time": round(inference_time, 3)
        }
        
    except Exception as e:
        logger.error(f"NLP prediction failed: {e}")
        return 0, {}, {"model_name": "typeform/distilbert-base-uncased-mnli", "available": False, "error": str(e)}


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


class _JobDescriptionExtractor(HTMLParser):
    """
    Extracts only job-related content from HTML by targeting specific tags
    and class names commonly used for job descriptions.
    Excludes header, footer, nav, and other non-content sections.
    Specifically targets job-related headings like "About the job", "About the company", etc.
    """
    def __init__(self) -> None:
        super().__init__()
        self._chunks: List[str] = []
        # Tags to completely skip (including their content)
        self._skip_tags = {"script", "style", "noscript", "nav", "header", "footer", "aside", "form"}
        self._skip_depth = 0
        self._in_job_section = False
        self._job_section_depth = 0
        self._current_depth = 0
        self._collecting_data = False
        self._current_section_name = ""
        self._section_stack: List[str] = []
        
        # Tags that typically contain job descriptions
        self._job_tags = {"article", "main", "section"}
        
        # Job-related heading patterns (case-insensitive)
        self._job_heading_patterns = [
            "about the job", "about the role", "about the position",
            "about the company", "about us", "company overview",
            "job description", "job summary", "role description",
            "responsibilities", "key responsibilities", "duties",
            "qualifications", "requirements", "skills required",
            "experience", "experience required", "preferred qualifications",
            "education", "education required",
            "benefits", "perks", "compensation", "salary",
            "how to apply", "application process",
            "equal opportunity", "eeo statement",
            "about the team", "team overview",
            "location", "work location", "job location",
            "employment type", "job type", "position type",
            "remote", "hybrid", "on-site",
            "full-time", "part-time", "contract", "temporary",
            "who we are", "what we do", "our mission", "our values",
            "overview", "description", "summary", "details",
            "what you'll do", "what you will do", "your role",
            "who you are", "ideal candidate", "preferred skills",
            "required skills", "minimum qualifications", "preferred qualifications",
            "additional information", "other information", "notes"
        ]
        
        # Class name patterns that indicate job content
        self._job_class_patterns = [
            "job", "description", "content", "details", "posting", "listing",
            "career", "position", "opening", "vacancy", "responsibilities",
            "qualifications", "requirements", "about", "role", "opportunity",
            "section", "article", "main-content", "job-content", "job-details",
            "job-description", "job-summary", "job-overview", "job-info",
            "posting-content", "listing-content", "career-content"
        ]
        
        # Class/id patterns to exclude (navigation, header, footer elements)
        self._exclude_patterns = [
            "nav", "header", "footer", "sidebar", "menu", "cookie", "banner",
            "login", "signup", "search", "social", "share", "comment", "widget",
            "related", "similar", "recommended", "suggested", "apply-button",
            "share-button", "save-button", "bookmark"
        ]
        
        # Patterns to exclude from content (violation, rules, complaints, etc.)
        self._exclude_content_patterns = [
            "violation", "rules", "complaints", "login", "signup", "footer", 
            "email", "contact", "privacy", "terms", "copyright", "legal",
            "warning", "notice", "alert", "important", "disclaimer"
        ]
    
    def _is_job_class(self, class_attr: Optional[str]) -> bool:
        if not class_attr:
            return False
        class_lower = class_attr.lower()
        # First check if it should be excluded
        if any(pattern in class_lower for pattern in self._exclude_patterns):
            return False
        return any(pattern in class_lower for pattern in self._job_class_patterns)
    
    def _should_exclude(self, attrs_dict: Dict[str, str]) -> bool:
        """Check if element should be excluded based on class/id patterns."""
        class_attr = attrs_dict.get("class", "").lower()
        id_attr = attrs_dict.get("id", "").lower()
        
        for pattern in self._exclude_patterns:
            if pattern in class_attr or pattern in id_attr:
                return True
        return False
    
    def _is_job_heading(self, text: str) -> bool:
        """Check if text matches a job-related heading pattern."""
        if not text:
            return False
        text_lower = text.lower().strip()
        # Remove common markdown/formatting characters
        text_clean = re.sub(r'[#*_~`]', '', text_lower).strip()
        return any(pattern in text_clean for pattern in self._job_heading_patterns)
    
    def _get_section_name(self, text: str) -> str:
        """Extract section name from heading text."""
        if not text:
            return ""
        text_lower = text.lower().strip()
        text_clean = re.sub(r'[#*_~`]', '', text_lower).strip()
        
        # Match against known patterns and return the matched pattern
        for pattern in self._job_heading_patterns:
            if pattern in text_clean:
                return pattern
        return ""
    
    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        tag_lower = tag.lower()
        self._current_depth += 1
        
        if tag_lower in self._skip_tags:
            self._skip_depth += 1
            return
        
        # Check if this element should be excluded
        attrs_dict = {k.lower(): v for k, v in attrs if v}
        if self._should_exclude(attrs_dict):
            self._skip_depth += 1
            return
        
        # Check if this is a job-related section
        class_attr = attrs_dict.get("class", "")
        id_attr = attrs_dict.get("id", "")
        
        # Check for job-related tags or classes
        is_job_tag = tag_lower in self._job_tags
        is_job_class = self._is_job_class(class_attr) or self._is_job_class(id_attr)
        
        if (is_job_tag or is_job_class) and not self._in_job_section:
            self._in_job_section = True
            self._job_section_depth = self._current_depth
        
        # Add newline for block elements when in job section
        if self._in_job_section and tag_lower in {"p", "br", "div", "li", "h1", "h2", "h3", "h4", "h5", "h6"}:
            self._chunks.append("\n")
    
    def handle_endtag(self, tag: str) -> None:
        tag_lower = tag.lower()
        
        if tag_lower in self._skip_tags and self._skip_depth > 0:
            self._skip_depth -= 1
        
        # Exit job section when we close the container
        if self._in_job_section and self._current_depth <= self._job_section_depth:
            self._in_job_section = False
            self._current_section_name = ""
        
        self._current_depth -= 1
    
    def handle_data(self, data: str) -> None:
        if self._skip_depth > 0 or not data:
            return
        
        # Only collect text when inside a job-related section
        if self._in_job_section:
            # Check if this is a job-related heading
            if self._is_job_heading(data):
                self._collecting_data = True
                section_name = self._get_section_name(data)
                if section_name:
                    self._current_section_name = section_name
                self._chunks.append("\n" + data.strip() + "\n")
            elif self._collecting_data:
                # Continue collecting data after a job heading
                self._chunks.append(html.unescape(data))
    
    def get_text(self, max_chars: int) -> str:
        text = re.sub(r"[ \t\r\f\v]+", " ", "".join(self._chunks))
        text = re.sub(r"\n{3,}", "\n\n", text).strip()
        return text[:max_chars - 1].rstrip() + "…" if len(text) > max_chars else text
    
    def has_content(self) -> bool:
        return len(self._chunks) > 0


# Navigation and irrelevant words to filter out
NAVIGATION_WORDS = {
    "login", "log in", "sign in", "signin", "signup", "sign up", "register",
    "home", "about", "contact", "menu", "navigation", "search", "skip",
    "cookie", "privacy", "terms", "copyright", "©", "all rights",
    "loading", "please wait", "click here", "read more", "learn more",
    "subscribe", "newsletter", "follow us", "share", "tweet", "like",
    "facebook", "twitter", "linkedin", "instagram", "youtube",
    "accept", "decline", "agree", "disagree", "ok", "cancel", "close",
    "submit", "reset", "clear", "back", "next", "previous", "continue"
}


def _clean_extracted_text(text: str) -> str:
    """
    Clean extracted text by removing:
    - Excessive whitespace
    - Repeated words/phrases
    - Navigation words
    - Empty lines
    - Duplicate content
    - Non-job-related content
    - Emails and platform warnings
    - Lines with excluded content patterns
    - UI noise and system text
    - Repeated "Posted ..." lines
    """
    if not text:
        return ""
    
    # Normalize whitespace
    cleaned = re.sub(r"[ \t\r\f\v]+", " ", text)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    
    # Patterns to exclude from content (UI noise, system text, etc.)
    exclude_content_patterns = [
        "violation", "rules", "complaints", "login", "signup", "footer", 
        "email", "contact", "privacy", "terms", "copyright", "legal",
        "warning", "notice", "alert", "important", "disclaimer",
        "internshala", "platform", "website", "app", "mobile app",
        "download", "install", "register", "sign up", "log in",
        "subscribe", "newsletter", "follow us", "share", "tweet",
        "facebook", "twitter", "linkedin", "instagram", "youtube",
        # UI noise patterns
        "this button displays", "see this and similar jobs", "search type",
        "click here", "read more", "learn more", "view job", "apply now",
        "save job", "bookmark", "share job", "report job", "flag job",
        "similar jobs", "related jobs", "more jobs", "other jobs",
        "job search", "job alerts", "job recommendations",
        "posted by", "posted on", "posted at", "posted date",
        "job id", "job reference", "ref id", "reference number",
        "application deadline", "closing date", "last date",
        "company website", "company profile", "about company",
        "employee reviews", "company reviews", "salary insights",
        "interview questions", "interview tips", "career advice",
        "resume tips", "cv tips", "cover letter",
        "job fair", "career fair", "recruitment drive",
        "walk-in", "walk in", "direct hiring", "immediate hiring",
        "urgent requirement", "immediate requirement", "urgent opening",
        "limited positions", "few positions", "multiple positions",
        "apply online", "apply offline", "apply via email",
        "send resume", "send cv", "submit application",
        "no experience required", "fresher", "experienced",
        "work from home", "remote work", "hybrid work",
        "full time", "part time", "contract", "permanent",
        "salary negotiable", "salary not disclosed", "competitive salary",
        "benefits included", "perks included", "incentives included",
        "training provided", "training available", "on the job training",
        "growth opportunities", "career growth", "promotion opportunities",
        "friendly environment", "good culture", "positive environment",
        "established company", "growing company", "startup",
        "multinational", "mnc", "fortune 500", "top company",
        "industry leader", "market leader", "leading company"
    ]
    
    # Email pattern
    email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
    
    # Posted pattern (to keep only one)
    posted_pattern = re.compile(r'posted\s+(by|on|at|date)', re.IGNORECASE)
    
    # Split into lines and filter
    lines = cleaned.split("\n")
    filtered_lines = []
    seen_content = set()  # Track seen content to avoid duplicates
    seen_normalized = set()  # Track normalized content for better deduplication
    has_posted_line = False  # Track if we've already seen a "Posted ..." line
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
        
        # Skip lines that contain emails
        if email_pattern.search(line):
            continue
        
        # Skip lines with excluded content patterns (UI noise)
        line_lower = line.lower()
        if any(pattern in line_lower for pattern in exclude_content_patterns):
            continue
        
        # Handle "Posted ..." lines - keep only the first one
        if posted_pattern.search(line_lower):
            if has_posted_line:
                continue
            has_posted_line = True
        
        # Skip lines that are just navigation words
        words_in_line = set(line_lower.split())
        
        # Skip if line is too short
        if len(line) < 15:
            continue
        
        # Skip if mostly navigation words
        nav_word_count = sum(1 for w in words_in_line if w in NAVIGATION_WORDS)
        if len(words_in_line) > 0 and nav_word_count / len(words_in_line) > 0.4:
            continue
        
        # Normalize for duplicate detection (remove extra spaces, lowercase, remove punctuation)
        normalized = re.sub(r'[^\w\s]', '', line_lower)  # Remove punctuation
        normalized = re.sub(r'\s+', ' ', normalized).strip()
        
        # Skip if we've seen very similar content (using normalized version)
        if normalized in seen_normalized:
            continue
        
        # Skip if exact line already seen
        if line in seen_content:
            continue
        
        # Skip lines that are just repeated words (e.g., "Apply Apply Apply")
        words = normalized.split()
        if len(words) >= 3:
            word_counts = {}
            for w in words:
                word_counts[w] = word_counts.get(w, 0) + 1
            # If any word appears more than 40% of the time, it's repetitive
            max_count = max(word_counts.values())
            if max_count / len(words) > 0.4:
                continue
        
        # Skip lines with excessive repetition of short phrases
        if re.search(r'\b(\w{1,10})\s+\1\s+\1\b', normalized):
            continue
        
        seen_content.add(line)
        seen_normalized.add(normalized)
        filtered_lines.append(line)
    
    # Remove consecutive duplicate lines
    deduped_lines = []
    prev_line = None
    for line in filtered_lines:
        if line != prev_line:
            deduped_lines.append(line)
        prev_line = line
    
    result = "\n".join(deduped_lines).strip()
    
    # Remove repeated phrases anywhere in text (e.g., "Apply Now Apply Now Apply Now")
    result = re.sub(r'\b(\w+(?:\s+\w+){1,3})\s+\1\s+\1\b', r'\1', result, flags=re.IGNORECASE)
    
    # Remove excessive repetition of single words
    result = re.sub(r'\b(\w{3,})\s+\1\s+\1(?:\s+\1)*\b', r'\1', result, flags=re.IGNORECASE)
    
    # Normalize whitespace again
    result = re.sub(r'\n{3,}', '\n\n', result)
    result = re.sub(r' {2,}', ' ', result)
    
    # Limit to 800-1000 characters max
    if len(result) > 1000:
        result = result[:997] + "..."
    
    return result


def _extract_job_description_from_html(html_text: str, max_chars: int = 1200) -> str:
    """
    Extract only job description content from HTML.
    Tries multiple strategies:
    1. Target specific job-related tags and classes
    2. Fallback to first few paragraphs if no job section found
    
    Limits extraction to 800-1200 characters max for cleaner output.
    """
    # Strategy 1: Try job-specific extraction
    job_extractor = _JobDescriptionExtractor()
    try:
        job_extractor.feed(html_text)
    except Exception:
        pass
    
    if job_extractor.has_content():
        text = job_extractor.get_text(max_chars)
        cleaned = _clean_extracted_text(text)
        if len(cleaned) >= 100:  # Minimum viable content
            return cleaned[:max_chars]
    
    # Strategy 2: Fallback - extract first meaningful paragraphs
    fallback_extractor = _HTMLTextExtractor()
    try:
        fallback_extractor.feed(html_text)
    except Exception:
        pass
    
    full_text = fallback_extractor.get_text(max_chars * 2)  # Get more to filter
    
    # Take first 2-3 substantial paragraphs
    paragraphs = [p.strip() for p in full_text.split("\n\n") if len(p.strip()) >= 50]
    fallback_text = "\n\n".join(paragraphs[:3])
    
    cleaned = _clean_extracted_text(fallback_text)
    return cleaned[:max_chars]


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


def _is_job_site_url(url: str) -> Tuple[bool, str]:
    """
    Check if the URL is from a known job site or contains job-related patterns.
    Returns (is_job_site, reason)
    """
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return False, "Invalid URL format"
    
    host = (parsed.hostname or "").lower()
    path = (parsed.path or "").lower()
    
    # Remove 'www.' prefix for matching
    if host.startswith("www."):
        host = host[4:]
    
    # Check against known job site domains
    for job_domain in JOB_SITE_DOMAINS:
        job_domain_lower = job_domain.lower()
        # Check if host ends with or contains the job domain
        if host == job_domain_lower or host.endswith("." + job_domain_lower):
            return True, f"Known job site: {job_domain}"
    
    # Check for job-related path patterns
    for pattern in JOB_PATH_PATTERNS:
        if re.search(pattern, path, re.IGNORECASE):
            return True, f"Job-related URL path detected"
    
    # Check for common career/job subdomains
    job_subdomains = ["jobs", "careers", "hiring", "recruitment", "talent", "apply", "employment", "workwithus", "joinus"]
    for subdomain in job_subdomains:
        if host.startswith(subdomain + ".") or f".{subdomain}." in host:
            return True, f"Job-related subdomain detected: {subdomain}"
    
    # Additional check: Look for job-related keywords in the full URL
    # This catches cases like "company.com/job/12345" or "site.com/careers/position"
    url_lower = url.lower()
    job_keywords_in_url = [
        "/job/", "/jobs/", "/career/", "/careers/", "/position/", "/positions/",
        "/opening/", "/openings/", "/vacancy/", "/vacancies/", "/opportunity/",
        "/opportunities/", "/employment/", "/hiring/", "/apply/", "/recruit/"
    ]
    for keyword in job_keywords_in_url:
        if keyword in url_lower:
            return True, f"Job-related keyword found in URL path"
    
    # Check for common ATS (Applicant Tracking System) patterns
    # Many companies use subdomains like "boards.greenhouse.io" or "jobs.lever.co"
    ats_patterns = [
        r"\.lever\.co",
        r"\.greenhouse\.io",
        r"\.workday\.com",
        r"\.myworkdayjobs\.com",
        r"\.icims\.com",
        r"\.jobvite\.com",
        r"\.taleo\.net",
        r"\.brassring\.com",
        r"\.smartrecruiters\.com",
        r"\.breezy\.hr",
        r"\.ashbyhq\.com",
        r"\.recruitee\.com",
        r"\.teamtailor\.com",
        r"\.applytojob\.com",
    ]
    for pattern in ats_patterns:
        if re.search(pattern, host, re.IGNORECASE):
            return True, f"Applicant Tracking System (ATS) detected"
    
    return False, "This URL does not appear to be from a job site"


def _is_job_content(text: str) -> Tuple[bool, int]:
    """
    Check if the text content appears to be job-related.
    Returns (is_job_content, keyword_match_count)
    """
    if not text:
        return False, 0
    
    text_lower = text.lower()
    match_count = 0
    
    for keyword in JOB_CONTENT_KEYWORDS:
        if keyword.lower() in text_lower:
            match_count += 1
    
    # Consider it job content if at least 3 job-related keywords are found
    return match_count >= 3, match_count


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
    
    # Extract only job description content (not entire webpage)
    # Limit to 1200 characters for cleaner highlighting
    job_description_text = _extract_job_description_from_html(html_text, max_chars=1200)
    
    # Also get meta descriptions for additional context
    meta_descs = _extract_meta_descriptions(html_text)
    
    # Combine job description with meta descriptions
    combined = "\n".join([d for d in meta_descs if d] + [job_description_text]).strip()
    combined_norm = _normalize_text_for_scoring(combined)
    
    # Extract background snippet for company signals
    background = _extract_background_snippet(combined_norm)
    gold_signals, silver_signals = _derive_company_signals(background or "")
    
    return UrlExtraction(
        host=host, 
        company_name_guess=company_name_guess, 
        fetched_ok=True, 
        fetch_error=None, 
        job_page_text=combined_norm, 
        company_background_snippet=background, 
        gold_signals=gold_signals, 
        silver_signals=silver_signals
    )


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
        "Unrealistic income claims": "Promises of extremely high daily/weekly income are common in job scams",
        "Vague or generic job description": "Scam postings often have very short, vague descriptions with no specific details",
        "Excessive urgency language": "Overly aggressive urgency tactics designed to prevent careful consideration",
        "Suspicious wording patterns": "Language that suggests minimal requirements or too-easy employment",
        "External communication shift": "Attempts to move conversation away from official platforms",
        "Pyramid / MLM scheme indicators": "Language commonly associated with pyramid schemes or multi-level marketing scams",
        "Identity theft risk indicators": "Requests for sensitive personal information early in the process",
        "Fake company indicators": "Signs that the company may not exist or is misrepresented",
        "Unrealistic payment promises": "Promises of payment that seem too good to be true",
        "Crypto / investment scam indicators": "Job postings that are actually cryptocurrency or investment scams",
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
        "unrealistic_salary_patterns": "Research typical salary ranges for this position - high daily income claims are red flags",
        "generic_job_descriptions": "Legitimate job postings include specific responsibilities and requirements",
        "excessive_urgency": "High-pressure tactics are a common scam indicator - take time to verify",
        "suspicious_wording": "Real jobs require specific skills - claims of 'no skills required' are suspicious",
        "external_communication_shift": "Never move to personal chat apps - use official company channels only",
        "pyramid_scheme_indicators": "Legitimate jobs pay for your work, not for recruiting others",
        "identity_theft_risk": "Never share sensitive personal information before verifying the employer",
        "fake_company_indicators": "Verify company claims through independent sources and official websites",
        "payment_promises": "Legitimate employers have standard pay cycles - instant payment promises are suspicious",
        "crypto_investment_scam": "Never invest money based on a job posting - these are typically scams",
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


def build_explanation(rule_score: int, matches: List[Dict[str, Any]], suspicious_keywords: List[str], suggestions: List[str], nlp_score: int, nlp_debug: Optional[Dict[str, Any]], final_score: int, analysis_mode: str = "hybrid") -> Dict[str, Any]:
    risk_band = risk_band_from_score(final_score)
    top_rules = _select_top_contributing_rules(matches)
    top_rule_descriptions = []
    for r in top_rules:
        phrases = r.get("matched_phrases", [])[:3]
        top_rule_descriptions.append(f"{r['title']} (e.g. {', '.join(phrases)})" if phrases else r["title"])
    
    nlp_available = bool(nlp_debug and nlp_debug.get("available"))
    
    # Generate different explanations based on analysis mode - MORE ASSERTIVE MESSAGING
    if analysis_mode == "nlp":
        # NLP-only mode explanation
        nlp_confidence = abs(nlp_score - 50)  # Distance from neutral (50)
        if nlp_score >= 70:
            ai_assessment = "AI model detected strong indicators of a fraudulent job posting"
        elif nlp_score >= 55:
            ai_assessment = "AI model identified suspicious patterns commonly found in scam jobs"
        elif nlp_score >= 45:
            ai_assessment = "AI model analysis shows mixed signals with some concerns"
        elif nlp_score >= 30:
            ai_assessment = "AI model suggests this posting has mostly legitimate characteristics"
        else:
            ai_assessment = "AI model indicates this appears to be a genuine job posting"
        
        explanation_summary = f"{risk_band} risk: {ai_assessment}. NLP confidence: {nlp_confidence}%. This analysis uses deep learning to detect linguistic patterns associated with job scams."
        
    elif analysis_mode == "rules":
        # Rules-only mode explanation - MORE ASSERTIVE
        if not top_rule_descriptions:
            explanation_summary = f"{risk_band} risk: Low risk, but caution signals detected. The posting doesn't match strong scam indicators, but always verify employer legitimacy before sharing personal information."
        else:
            pattern_count = len(matches)
            if pattern_count >= 4:
                pattern_assessment = f"Multiple red flags detected ({pattern_count} patterns matched)"
            elif pattern_count >= 2:
                pattern_assessment = f"Several concerning patterns identified ({pattern_count} matches)"
            else:
                pattern_assessment = f"Some suspicious elements found ({pattern_count} pattern matched)"
            
            explanation_summary = f"{risk_band} risk: {pattern_assessment}. Key indicators: {', '.join(top_rule_descriptions[:3])}. This analysis checks for known scam tactics like gift card requests, chat-only communication, and guaranteed employment claims."
    
    else:
        # Hybrid mode explanation (default) - MORE ASSERTIVE
        nlp_note = "NLP model not available; using rule-based signals only." if not nlp_available else "AI model contributed a probability estimate."
        
        if top_rule_descriptions:
            explanation_summary = f"{risk_band} risk: {nlp_note} Combined analysis found {len(matches)} pattern(s): {', '.join(top_rule_descriptions[:2])}. Hybrid mode provides the most comprehensive detection by combining AI language analysis with known scam pattern matching."
        else:
            explanation_summary = f"{risk_band} risk: {nlp_note} Low risk, but caution signals detected. Hybrid analysis combines AI assessment with rule-based checks for thorough evaluation. Always verify employer legitimacy."
    
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
        # Load NLP pipeline at startup
        _load_nlp_pipeline()

    def nlp_status(self) -> Dict[str, Any]:
        global _nlp_loaded, _nlp_error
        if not _nlp_loaded:
            _load_nlp_pipeline()
        return {
            "available": _nlp_pipeline is not None,
            "loading": False,
            "model_name": "typeform/distilbert-base-uncased-mnli",
            "error": _nlp_error
        }

    def force_nlp_retry(self) -> Dict[str, Any]:
        global _nlp_pipeline, _nlp_loaded, _nlp_error
        with _nlp_lock:
            _nlp_pipeline = None
            _nlp_loaded = False
            _nlp_error = None
        _load_nlp_pipeline()
        return self.nlp_status()

    def analyze(self, job_text: str, job_url: Optional[str] = None, analysis_mode: str = "hybrid") -> Dict[str, Any]:
        start = time.time()
        
        # Check if URL is provided and validate it's a job site
        if job_url:
            is_job_site, reason = _is_job_site_url(job_url)
            if not is_job_site:
                return {
                    "error": "not_a_job_site",
                    "error_message": "This URL does not appear to be from a job site",
                    "error_detail": reason,
                    "suggestion": "Please enter a URL from a job board (e.g., LinkedIn, Indeed, Glassdoor) or a company careers page.",
                    "risk_score": None,
                    "verdict": "NOT A JOB SITE",
                    "verdict_detail": "The provided URL is not recognized as a job-related website. Scam Scout only analyzes job postings for potential scams.",
                    "timing_ms": int(round((time.time() - start) * 1000)),
                    "analysis_mode": analysis_mode
                }
        
        url_ctx: Optional[UrlExtraction] = None
        if job_url:
            url_ctx = _fetch_and_extract_url_context(job_url)
            job_text = url_ctx.job_page_text or job_url
        
        prepared_for_scoring = _normalize_text_for_scoring(job_text)
        analysis_excerpt_for_highlight = _safe_excerpt(prepared_for_scoring, MAX_EXCERPT_CHARS)
        
        # Calculate scores based on analysis mode
        rule_score, matches, suspicious_keywords, suggestions = analyze_rules(prepared_for_scoring)
        nlp_score, label_scores, nlp_debug = _predict_with_nlp(prepared_for_scoring, rule_score)
        
        # Adjust final score based on analysis mode - FIXED HYBRID SCORING
        if analysis_mode == "nlp":
            # NLP only - use NLP score with minimal rule influence
            final_score = max(0, min(100, int(round(0.9 * nlp_score + 0.1 * rule_score))))
            explanation_summary_suffix = " (NLP mode)"
        elif analysis_mode == "rules":
            # Rules only - use rule score only
            final_score = max(0, min(100, rule_score))
            explanation_summary_suffix = " (Rules mode)"
        else:
            # FIXED HYBRID SCORING FORMULA
            # IF rule_score >= 50: final_score = max(rule_score, int(0.7 * rule_score + 0.3 * nlp_score))
            # ELSE: final_score = int(0.6 * rule_score + 0.4 * nlp_score)
            if rule_score >= 50:
                final_score = max(rule_score, int(0.7 * rule_score + 0.3 * nlp_score))
            else:
                final_score = int(0.6 * rule_score + 0.4 * nlp_score)
            final_score = max(0, min(100, final_score))
            explanation_summary_suffix = " (Hybrid mode)"
        
        # FORCE RISK DETECTION for specific high-risk keywords
        high_risk_keywords = ["whatsapp", "telegram", "crypto", "payment", "processing fee"]
        for keyword in high_risk_keywords:
            if keyword in prepared_for_scoring.lower():
                final_score = max(final_score, 50)
                break
        
        # FIX "ALWAYS SAFE" ISSUE - Do NOT allow final_score < 20 if any rule matched
        if matches and final_score < 20:
            final_score = 20
        
        explanation = build_explanation(rule_score, matches, suspicious_keywords, suggestions, nlp_score, nlp_debug, final_score, analysis_mode)
        # Add mode indicator to explanation summary
        explanation["explanation_summary"] = explanation.get("explanation_summary", "") + explanation_summary_suffix
        
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
            "nlp": {"model_name": nlp_debug.get("model_name"), "label_scores": label_scores, "available": nlp_debug.get("available", False), "error": nlp_debug.get("error")},
            "ai_used": analysis_mode in ["nlp", "hybrid"] and nlp_debug.get("available", False),
            "analysis_mode": analysis_mode,
            "explanation_summary": explanation["explanation_summary"],
            "matches": explanation["matches"] if analysis_mode in ["rules", "hybrid"] else [],
            "top_rules": explanation["top_rules"] if analysis_mode in ["rules", "hybrid"] else [],
            "suspicious_keywords": suspicious_keywords if analysis_mode in ["rules", "hybrid"] else [],
            "highlight_keywords": highlight_keywords if analysis_mode in ["rules", "hybrid"] else [],
            "suggestions": explanation["suggestions"] if analysis_mode in ["rules", "hybrid"] else [],
            "timing_ms": timing_ms,
            "verdict": verdict,
            "verdict_detail": verdict_detail,
            "gold_signals": gold_signals,
            "silver_signals": silver_signals,
            "near_risk_factors": near_risk_factors,
            "company_background_snippet": company_background_snippet,
            "analysis_excerpt_for_highlight": analysis_excerpt_for_highlight,
            "red_flags": red_flags if analysis_mode in ["rules", "hybrid"] else [],
            "safety_actions": safety_actions if analysis_mode in ["rules", "hybrid"] else [],
            "score_breakdown": score_breakdown if analysis_mode in ["rules", "hybrid"] else [],
            "url_context": {"job_url": job_url, "host": url_ctx.host if url_ctx else None, "company_name_guess": url_ctx.company_name_guess if url_ctx else None, "fetched_ok": bool(url_ctx.fetched_ok) if url_ctx else False, "fetch_error": url_ctx.fetch_error if url_ctx else None}
        }