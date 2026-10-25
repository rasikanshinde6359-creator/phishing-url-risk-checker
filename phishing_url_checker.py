"""
Phishing URL Risk Checker
Educational cybersecurity project.
Checks a URL using simple, transparent heuristics. It does not visit or open the URL.
"""

import re
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = {
    "login", "verify", "verification", "account", "secure", "update",
    "password", "banking", "wallet", "confirm", "support", "recover"
}
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "shorturl.at",
    "rb.gy", "ow.ly", "buff.ly"
}
SUSPICIOUS_TLDS = {".zip", ".mov", ".click", ".top", ".work", ".country", ".gq", ".tk"}

def assess_url(raw_url: str):
    """Return a risk score, risk label, and reasons without making a network request."""
    raw_url = raw_url.strip()
    if not raw_url:
        raise ValueError("Please enter a URL.")

    candidate = raw_url if "://" in raw_url else "http://" + raw_url
    parsed = urlparse(candidate)
    host = (parsed.hostname or "").lower()
    if not host or "." not in host:
        raise ValueError("That does not look like a valid domain/URL. Try example.com.")

    score = 0
    reasons = []

    if parsed.scheme.lower() != "https":
        score += 1
        reasons.append("The URL does not use HTTPS.")

    if "@" in parsed.netloc:
        score += 2
        reasons.append("The address contains '@', which can obscure the real destination.")

    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host):
        score += 2
        reasons.append("The hostname is an IP address rather than a typical domain.")

    if len(raw_url) >= 75:
        score += 1
        reasons.append("The URL is unusually long.")

    if host.count("-") >= 2:
        score += 1
        reasons.append("The domain contains multiple hyphens.")

    if host.startswith("xn--") or ".xn--" in host:
        score += 2
        reasons.append("The domain uses an internationalized/punycode label.")

    if host in SHORTENERS:
        score += 2
        reasons.append("The domain is a known URL-shortening service.")

    lower_url = raw_url.lower()
    matched = sorted(word for word in SUSPICIOUS_KEYWORDS if word in lower_url)
    if matched:
        score += 1
        reasons.append("Contains words often used in social-engineering links: " + ", ".join(matched) + ".")

    tld = "." + host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        score += 1
        reasons.append(f"The domain uses the {tld} top-level domain, which deserves extra scrutiny.")

    if score >= 5:
        label = "HIGH"
    elif score >= 3:
        label = "MEDIUM"
    else:
        label = "LOW"

    if not reasons:
        reasons.append("No listed warning signs were detected by these basic checks.")

    return score, label, reasons

def main():
    print("=" * 52)
    print("          PHISHING URL RISK CHECKER")
    print("=" * 52)
    print("Educational heuristic only — the URL will NOT be opened.")
    print("Do not enter private tokens or sensitive URLs.\n")

    while True:
        url = input("Enter a URL (or type 'q' to quit): ").strip()
        if url.lower() in {"q", "quit", "exit"}:
            print("Goodbye.")
            break
        try:
            score, label, reasons = assess_url(url)
            print(f"\nRisk level: {label}  |  Heuristic score: {score}")
            for reason in reasons:
                print(f" - {reason}")
            print("\nReminder: This is not proof that a site is safe or malicious.")
            print("When in doubt, don't click the link; visit the official site directly.\n")
        except ValueError as error:
            print(f"Input error: {error}\n")

if __name__ == "__main__":
    main()
