# PhishGuard — Phishing Awareness Dashboard

A full-stack rebuild of the CodeAlpha Cyber Security internship Task 2 deliverable: a security-dashboard-style app with a **Flask backend** doing real, server-side rule-based analysis (not just a static frontend).

## What it does

- **Dashboard** — live stat cards (messages analyzed, threats detected, URLs scanned) and a threat-severity donut chart, all backed by real usage data persisted server-side
- **Message Analyzer** — paste a message, get a server-computed risk verdict (Critical / High / Suspicious / Low) with every matched indicator explained
- **URL Scanner** — same idea, for a single URL: checks for raw IPs, non-HTTPS, shortener domains, brand-mimicking hyphenated domains, and suspicious TLDs
- **Red Flags** — an annotated fake phishing email you click through
- **Phishing Examples** — social engineering tactics + a real-world BEC case study
- **Security Checklist** / **Safety Tips** — practical guidance
- **Test Yourself** — a 5-question scored quiz

## Why there's a backend now

Every analyzer/scanner call is a real `POST` to Flask, which runs the actual rule-matching logic in Python (`app.py`) and persists a running count to `data/stats.json`. The dashboard's numbers are genuine — they go up because you actually used the tools, not because they're hardcoded.

## Running it

```
pip install -r requirements.txt
python app.py
```

Then open **http://localhost:5000**.

## Project structure

```
phishguard-v2/
├── app.py              # Flask backend — analyzer, URL scanner, stats API
├── requirements.txt
├── data/stats.json     # created automatically on first run
├── templates/index.html
└── static/
    ├── style.css
    └── script.js
```

## API

| Method | Route | Description |
|---|---|---|
| `POST` | `/api/analyze-message` | Body: `{"text": "..."}` → risk verdict + matched indicators |
| `POST` | `/api/scan-url` | Body: `{"url": "..."}` → risk verdict + matched indicators |
| `GET` | `/api/stats` | Current dashboard counts (used by the donut chart and stat cards) |

## Honest note on the analysis

Both tools are **rule-based pattern matching** (keyword/regex heuristics), not AI or a trained model — this is stated directly in the UI. It's a genuinely useful heuristic for teaching red-flag recognition, but it can miss well-crafted phishing and can flag legitimate urgent messages. Worth saying plainly in a video walkthrough rather than overstating what it does.
