# Phishing URL Risk Checker

## Overview
A beginner-friendly cybersecurity project that checks a URL for common warning signs using transparent, rule-based heuristics. It does **not** open the URL, contact the website, or claim to prove whether a site is malicious.

## Features
- Flags non-HTTPS URLs, IP-address hosts, unusually long URLs, multiple hyphens, punycode labels, URL shorteners, and common social-engineering words.
- Produces LOW, MEDIUM, or HIGH heuristic risk labels.
- Explains which warning signs contributed to the score.
- Runs locally and makes no network requests.

## Requirements
- Python 3.9 or newer
- No third-party packages

## Run
```bash
python phishing_url_checker.py
```
Enter a URL such as `https://example.com`. Type `q` to quit.

## Example
```text
Enter a URL (or type 'q' to quit): http://192.0.2.10/login/verify
Risk level: HIGH  |  Heuristic score: 5
 - The URL does not use HTTPS.
 - The hostname is an IP address rather than a typical domain.
 - Contains words often used in social-engineering links: login, verify.
```
Exact scores may vary if the input differs.

## Limitations
- This is an educational demonstration, not a production anti-phishing tool.
- Heuristics can create false positives and false negatives.
- HTTPS does not guarantee that a website is trustworthy.
- The tool does not check reputation feeds, DNS, certificates, redirects, page content, or live threat intelligence.
- Never paste private links containing access tokens or personal information.

## Suggested future improvements
- Add a graphical interface.
- Add unit tests for each detection rule.
- Add an optional, privacy-conscious reputation API integration.
- Compare results against a labeled dataset and report precision/recall.

## License
For educational use. You may adapt it for coursework; follow your institution's submission and citation rules.
