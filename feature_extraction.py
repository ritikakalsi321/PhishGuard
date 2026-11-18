"""
Lexical feature extraction for PhishGuard.

Every feature is computed from the URL string alone (no network calls), so
extraction is fast, safe, and works the same at training and prediction time.
"""
import math
import re
from urllib.parse import urlparse

SUSPICIOUS_WORDS = [
    "login", "signin", "verify", "update", "secure", "account", "banking",
    "confirm", "password", "webscr", "suspend", "wallet", "invoice", "payment",
    "billing", "support", "alert", "unlock", "recover", "validate", "kyc", "otp",
]
SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc",
}
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "buzz", "work",
    "club", "info", "icu", "live", "rest", "zip", "mov",
}
IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")


def _normalize(url):
    url = str(url).strip()
    if not SCHEME_RE.match(url):
        url = "http://" + url
    return url


def _entropy(text):
    if not text:
        return 0.0
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def extract_features(url):
    """Return an ordered dict of numeric features for a single URL."""
    full = _normalize(url)
    try:
        parsed = urlparse(full)
        host = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError:
        parsed = urlparse("http://invalid")
        host, port = "", None

    path = parsed.path or ""
    query = parsed.query or ""
    labels = [p for p in host.split(".") if p]
    tld = labels[-1] if len(labels) > 1 else ""
    lowered = full.lower()
    n = max(len(full), 1)

    return {
        "url_length": len(full),
        "host_length": len(host),
        "path_length": len(path),
        "query_length": len(query),
        "count_dots": full.count("."),
        "count_hyphens": full.count("-"),
        "count_hyphens_host": host.count("-"),
        "count_underscores": full.count("_"),
        "count_at": full.count("@"),
        "count_question": full.count("?"),
        "count_equals": full.count("="),
        "count_ampersand": full.count("&"),
        "count_percent": full.count("%"),
        "count_slashes": full.count("/"),
        "count_digits": sum(c.isdigit() for c in full),
        "digit_ratio": sum(c.isdigit() for c in full) / n,
        "digits_in_host": sum(c.isdigit() for c in host),
        "special_char_ratio": sum(not c.isalnum() for c in full) / n,
        "has_ip_host": int(bool(IP_RE.match(host))),
        "uses_https": int(parsed.scheme == "https"),
        "has_port": int(port is not None and port not in (80, 443)),
        "subdomain_count": max(len(labels) - 2, 0),
        "path_depth": len([p for p in path.split("/") if p]),
        "suspicious_word_count": sum(w in lowered for w in SUSPICIOUS_WORDS),
        "is_shortener": int(host in SHORTENERS),
        "suspicious_tld": int(tld in SUSPICIOUS_TLDS),
        "has_punycode": int("xn--" in host),
        "double_slash_in_path": int("//" in path),
        "host_entropy": _entropy(host),
        "url_entropy": _entropy(full),
    }


FEATURE_NAMES = list(extract_features("http://example.com").keys())


def features_to_vector(url):
    feats = extract_features(url)
    return [feats[name] for name in FEATURE_NAMES]


def explain(url):
    """Human-readable red flags found in a URL (for display only)."""
    f = extract_features(url)
    flags = []
    if f["has_ip_host"]:
        flags.append("Uses a raw IP address instead of a domain name")
    if f["count_at"]:
        flags.append("Contains '@' (can hide the real destination)")
    if f["is_shortener"]:
        flags.append("Uses a URL shortener that hides the real destination")
    if f["suspicious_tld"]:
        flags.append("Uses a top-level domain often abused for phishing")
    if f["has_punycode"]:
        flags.append("Contains punycode (possible look-alike characters)")
    if f["suspicious_word_count"] >= 2:
        flags.append(f"Contains {f['suspicious_word_count']} sensitive keywords (login, verify, secure, ...)")
    if f["subdomain_count"] >= 3:
        flags.append("Has many subdomains")
    if f["count_hyphens_host"] >= 2:
        flags.append("Has multiple hyphens in the domain")
    if f["has_port"]:
        flags.append("Uses a non-standard port")
    if not f["uses_https"]:
        flags.append("Does not use HTTPS")
    if f["url_length"] > 75:
        flags.append("Unusually long URL")
    return flags
import difflib

BRANDS = [
    "google", "facebook", "paypal", "amazon", "microsoft", "apple", "netflix",
    "instagram", "whatsapp", "linkedin", "twitter", "youtube", "github",
    "dropbox", "yahoo", "outlook", "ebay", "walmart", "paytm", "flipkart",
    "irctc", "hdfcbank", "icicibank", "wellsfargo", "bankofamerica", "fedex",
]
# Real domains that legitimately contain a brand name
ALLOWED = {
    "microsoftonline", "googleusercontent", "googleapis", "gstatic",
    "googlevideo", "githubusercontent", "githubassets", "amazonaws", "fbcdn",
}
LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s", "@": "a"})
SECOND_LEVEL = {"co", "com", "org", "net", "gov", "ac", "edu"}


def _registered_label(host):
    labels = [l for l in host.split(".") if l]
    if len(labels) < 2:
        return host
    if len(labels) >= 3 and labels[-2] in SECOND_LEVEL and len(labels[-1]) == 2:
        return labels[-3]
    return labels[-2]


def lookalike_flags(url):
    """Rule-based brand impersonation checks (no retraining needed)."""
    flags = []
    try:
        host = (urlparse(_normalize(url)).hostname or "").lower()
    except ValueError:
        return flags
    if not host:
        return flags

    if "_" in host:
        flags.append("Underscore in the domain name (not valid in real website addresses)")

    sld = _registered_label(host)
    if sld in BRANDS or sld in ALLOWED:
        return flags

    cleaned = sld.translate(LEET).replace("_", "").replace("-", "")
    for brand in BRANDS:
        if cleaned == brand:
            flags.append(f"Look-alike of '{brand}' using substituted characters")
            break
        if len(brand) >= 5 and difflib.SequenceMatcher(None, cleaned, brand).ratio() >= 0.82:
            flags.append(f"Domain is a near-copy of '{brand}' (possible typosquatting)")
            break
        if len(brand) >= 5 and brand in host:
            flags.append(f"Mentions '{brand}' but the real domain is '{sld}'")
            break
    return flags
