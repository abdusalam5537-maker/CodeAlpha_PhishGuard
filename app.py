"""
PhishGuard — Phishing Awareness Dashboard backend.

Serves the dashboard and provides two rule-based security tools:
  - /api/analyze-message  — scores pasted text for phishing indicators
  - /api/scan-url         — scores a URL for phishing indicators

Every call updates persisted stats (data/stats.json), which the
dashboard's stat cards and threat-overview chart read from.
"""

import json
import os
import re
import threading
import time
import uuid

from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
STATS_FILE = os.path.join(DATA_DIR, "stats.json")
stats_lock = threading.Lock()

MAX_HISTORY = 50

DEFAULT_STATS = {
    "messages_analyzed": 0,
    "urls_scanned": 0,
    "critical": 0,
    "high": 0,
    "suspicious": 0,
    "low": 0,
    "history": [],
}


def load_stats():
    if not os.path.exists(STATS_FILE):
        os.makedirs(DATA_DIR, exist_ok=True)
        save_stats(dict(DEFAULT_STATS))
    with open(STATS_FILE, "r") as f:
        stats = json.load(f)
    stats.setdefault("history", [])  # backward-compat with older stats.json files
    return stats


def save_stats(stats):
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(STATS_FILE, "w") as f:
        json.dump(stats, f, indent=2)


def record_result(kind, level, input_text, label, score):
    """kind: 'message' or 'url'. level: 'critical'|'high'|'suspicious'|'low'."""
    with stats_lock:
        stats = load_stats()
        if kind == "message":
            stats["messages_analyzed"] += 1
        else:
            stats["urls_scanned"] += 1
        stats[level] += 1

        preview = input_text.strip().replace("\n", " ")
        if len(preview) > 90:
            preview = preview[:90] + "…"

        stats["history"].insert(0, {
            "id": uuid.uuid4().hex[:8],
            "type": kind,
            "preview": preview,
            "level": level,
            "label": label,
            "score": score,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        })
        stats["history"] = stats["history"][:MAX_HISTORY]

        save_stats(stats)
        return stats


def reset_stats():
    with stats_lock:
        save_stats(dict(DEFAULT_STATS))
        return load_stats()


# ---------------------------------------------------------------------
# Message analyzer — rule-based keyword/pattern matching
# ---------------------------------------------------------------------
MESSAGE_RULES = [
    {
        "category": "Urgency / pressure language",
        "weight": 2,
        "pattern": re.compile(
            r"\b(urgent|immediately|act now|right away|as soon as possible|"
            r"within\s+24\s*hours?|expires?\s+(today|soon)|limited time|final notice)\b",
            re.IGNORECASE,
        ),
        "explain": "Manufactured urgency is designed to make you act before you think.",
    },
    {
        "category": "Generic greeting",
        "weight": 2,
        "pattern": re.compile(
            r"\bdear\s+(customer|user|valued customer|account holder|member)\b",
            re.IGNORECASE,
        ),
        "explain": "Legitimate institutions holding your account usually address you by name.",
    },
    {
        "category": "Request for sensitive information",
        "weight": 3,
        "pattern": re.compile(
            r"\b(password|otp|one[- ]time (code|password)|pin\s*(number|code)?|ssn|"
            r"social security|credit card( number)?|cvv|verify your identity|confirm your account)\b",
            re.IGNORECASE,
        ),
        "explain": "Legitimate services rarely ask you to submit credentials or codes via email/SMS.",
    },
    {
        "category": "Threat / consequence language",
        "weight": 2,
        "pattern": re.compile(
            r"\b(suspend(ed)?|terminat(e|ion)|permanently locked|legal action|penalty|"
            r"unauthorized access detected|account (closure|closed))\b",
            re.IGNORECASE,
        ),
        "explain": "Threatening a consequence is a common pressure tactic to prevent careful verification.",
    },
    {
        "category": "Suspicious link pattern",
        "weight": 3,
        "pattern": re.compile(
            r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|bit\.ly|tinyurl\.com|t\.co/|goo\.gl)|"
            r"https?://[^\s]*-(secure|verify|account|login|update)[^\s]*",
            re.IGNORECASE,
        ),
        "explain": "Raw IP addresses, URL shorteners, and hyphenated brand-mimicking domains are common in phishing links.",
    },
    {
        "category": "Generic call-to-action",
        "weight": 1,
        "pattern": re.compile(r"\b(click here|verify now|login here|update now)\b", re.IGNORECASE),
        "explain": "Vague, high-pressure link text is a common way to get a click before the destination is examined.",
    },
]


def score_to_level(score):
    if score >= 10:
        return "critical", "CRITICAL RISK"
    if score >= 6:
        return "high", "HIGH RISK"
    if score >= 1:
        return "suspicious", "SUSPICIOUS"
    return "low", "LOW RISK / CLEAR"


def analyze_message(text):
    flags = []
    score = 0

    for rule in MESSAGE_RULES:
        found = rule["pattern"].search(text)
        if found:
            all_matches = [m.group(0) for m in rule["pattern"].finditer(text)]
            unique = list(dict.fromkeys(m.strip() for m in all_matches))[:3]
            score += rule["weight"]
            flags.append({
                "category": rule["category"],
                "matched": ", ".join(unique),
                "explain": rule["explain"],
            })

    excl = len(re.findall(r"!{2,}", text))
    caps_words = len(re.findall(r"\b[A-Z]{4,}\b", text))
    if excl > 0 or caps_words >= 3:
        score += 1
        flags.append({
            "category": "Unusual formatting",
            "matched": 'repeated "!!"' if excl > 0 else f"{caps_words} ALL-CAPS words",
            "explain": "Excessive punctuation or capitalization is often used to manufacture alarm.",
        })

    level, label = score_to_level(score)
    return {"score": score, "level": level, "label": label, "flags": flags}


# ---------------------------------------------------------------------
# URL scanner — rule-based checks on a single URL
# ---------------------------------------------------------------------
SHORTENER_DOMAINS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly"}
SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "support", "ru"}
BRAND_MIMIC_WORDS = {"secure", "verify", "login", "account", "update", "confirm"}


def scan_url(url):
    flags = []
    score = 0
    url_lower = url.strip().lower()

    if re.match(r"^https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url_lower):
        score += 4
        flags.append({
            "category": "Raw IP address",
            "matched": "IP-based URL instead of a domain name",
            "explain": "Legitimate organizations essentially never link to a raw IP address — this is a strong phishing indicator.",
        })

    if not url_lower.startswith("https://"):
        score += 2
        flags.append({
            "category": "Not using HTTPS",
            "matched": url.split("://")[0] if "://" in url else "(no scheme)",
            "explain": "Unencrypted connections expose any data submitted on the page, and most legitimate sites enforce HTTPS.",
        })

    for dom in SHORTENER_DOMAINS:
        if dom in url_lower:
            score += 3
            flags.append({
                "category": "URL shortener",
                "matched": dom,
                "explain": "Shortened links hide the real destination until after you click.",
            })
            break

    domain_match = re.search(r"://([^/]+)", url_lower)
    domain = domain_match.group(1) if domain_match else url_lower

    if "-" in domain and any(word in domain for word in BRAND_MIMIC_WORDS):
        score += 4
        flags.append({
            "category": "Brand-mimicking domain",
            "matched": domain,
            "explain": "Hyphenated domains combining a real brand name with words like \"secure\" or \"verify\" are a very common phishing pattern.",
        })

    tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
    if tld in SUSPICIOUS_TLDS:
        score += 2
        flags.append({
            "category": "Uncommon top-level domain",
            "matched": f".{tld}",
            "explain": "This TLD is disproportionately used in phishing/spam campaigns relative to legitimate business sites.",
        })

    if domain.count(".") >= 4:
        score += 1
        flags.append({
            "category": "Unusually complex subdomain structure",
            "matched": domain,
            "explain": "Long chains of subdomains are sometimes used to bury a suspicious root domain out of easy view.",
        })

    level, label = score_to_level(score)
    return {"score": score, "level": level, "label": label, "flags": flags}


# ---------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/analyze-message", methods=["POST"])
def api_analyze_message():
    body = request.get_json(silent=True) or {}
    text = (body.get("text") or "").strip()
    if not text:
        return jsonify({"error": "No text provided."}), 400

    result = analyze_message(text)
    stats = record_result("message", result["level"], text, result["label"], result["score"])
    result["stats"] = {k: v for k, v in stats.items() if k != "history"}
    return jsonify(result)


@app.route("/api/scan-url", methods=["POST"])
def api_scan_url():
    body = request.get_json(silent=True) or {}
    url = (body.get("url") or "").strip()
    if not url:
        return jsonify({"error": "No URL provided."}), 400

    result = scan_url(url)
    stats = record_result("url", result["level"], url, result["label"], result["score"])
    result["stats"] = {k: v for k, v in stats.items() if k != "history"}
    return jsonify(result)


@app.route("/api/stats")
def api_stats():
    stats = load_stats()
    threats_detected = stats["critical"] + stats["high"] + stats["suspicious"]
    numeric = {k: v for k, v in stats.items() if k != "history"}
    return jsonify({**numeric, "threats_detected": threats_detected})


@app.route("/api/history")
def api_history():
    stats = load_stats()
    return jsonify(stats["history"])


@app.route("/api/reset", methods=["POST"])
def api_reset():
    stats = reset_stats()
    return jsonify({k: v for k, v in stats.items() if k != "history"})


if __name__ == "__main__":
    load_stats()  # ensure the stats file exists before first request
    print("PhishGuard running at http://localhost:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
