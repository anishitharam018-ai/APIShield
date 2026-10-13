"""Heuristic classification of URLs and downloads reported by the extension."""
import os
import re
from urllib.parse import urlparse


# ------------------------------------------------------- browser threats ----
# Classifies a URL or a download reported by
# the APIShield browser extension. This is heuristic-based - it looks for
# patterns that are OFTEN associated with risk (raw-IP addresses, abused
# top-level domains, login pages served without HTTPS, pirate/crack-style
# wording, risky file extensions) and combines several of them before
# calling anything more than "low". It never claims a site is confirmed
# malicious - only "suspicious", based on the indicators it lists, because a
# local heuristic check cannot replace a real threat-intelligence feed.
RISKY_TLDS = {"zip", "mov", "top", "xyz", "click", "country", "gq", "tk", "ml", "cf", "work", "support", "link", "surf"}
DOWNLOAD_KEYWORDS = ("torrent", "crack", "keygen", "warez", "pirate", "free-download", "movierulz", "filmyzilla")
LOGIN_KEYWORDS = ("login", "signin", "sign-in", "verify", "secure", "account", "update", "password", "wallet")
RISKY_EXTENSIONS = {
    ".exe": "an executable program", ".scr": "a screensaver file (a common malware disguise)",
    ".bat": "a batch script", ".vbs": "a VBScript file", ".js": "a JavaScript file run outside the browser",
    ".jar": "a Java program", ".msi": "a Windows installer", ".apk": "an Android app package",
    ".ps1": "a PowerShell script", ".cmd": "a batch script",
}
SEVERITY_RANK = {"safe": 0, "medium": 1, "unsafe": 2}


def classify_url(url):
    """Returns {"domain","severity","category","indicators"} for a page visit.
    severity is always one of exactly three values: safe, medium, unsafe."""
    try:
        u = urlparse(url if "://" in url else "http://" + url)
    except Exception:
        return {"domain": url, "severity": "medium", "category": "Could not be parsed", "indicators": ["The URL could not be read"]}
    domain = (u.hostname or url).lower()
    path_q = (u.path + "?" + u.query).lower()
    indicators = []
    hint = None

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        indicators.append("Uses a raw IP address instead of a domain name")
    if domain.startswith("xn--") or ".xn--" in domain:
        indicators.append("Punycode domain (can be used to imitate a trusted name)")
    tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
    if tld in RISKY_TLDS:
        indicators.append("Uses a top-level domain (.%s) that is often abused for scams" % tld)
    if domain.count("-") >= 4:
        indicators.append("Unusually long, hyphenated domain name")
    if domain.count(".") >= 4:
        indicators.append("Unusually deep subdomain chain")
    if any(k in domain or k in path_q for k in DOWNLOAD_KEYWORDS):
        indicators.append("Page text matches wording often used by pirated-content / crack sites")
        hint = "download"
    if u.scheme == "http" and any(k in path_q for k in LOGIN_KEYWORDS):
        indicators.append("A login-style page is served without HTTPS")
        hint = "phishing"

    n = len(indicators)
    if n == 0:
        severity, category = "safe", "Normal browsing"
    elif n <= 2:
        severity, category = "medium", "Suspicious website - some indicators found"
    else:
        severity = "unsafe"
        category = "Suspicious download website" if hint == "download" else ("Possible phishing / login page" if hint == "phishing" else "Suspicious website (multiple indicators)")
    return {"domain": domain, "severity": severity, "category": category,
            "indicators": indicators or ["No suspicious pattern matched"], "hint": hint}


def classify_download(url, filename):
    base = classify_url(url)
    indicators = list(base["indicators"]) if base["indicators"] != ["No suspicious pattern matched"] else []
    ext = os.path.splitext(filename or url or "")[1].lower()
    risky = RISKY_EXTENSIONS.get(ext)
    if risky:
        indicators.append("The download is %s (%s)" % (risky, ext))
    if risky and (base["severity"] in ("medium", "unsafe") or base.get("hint") == "download"):
        severity, category = "unsafe", "Suspicious download"
    elif risky:
        severity, category = "medium", "Executable/script download - verify the source before running it"
    elif base["severity"] == "unsafe":
        severity, category = "unsafe", base["category"]
    elif indicators:
        severity, category = "medium", "Some indicators found - probably fine, worth a glance"
    else:
        severity, category = "safe", "Normal download"
    return {"domain": base["domain"], "severity": severity, "category": category,
            "indicators": indicators or ["No suspicious pattern matched"], "filename": filename}
