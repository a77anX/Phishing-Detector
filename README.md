# Phishing Email Detector (Rule-based) — README

**Project:** Rule-based phishing email detector + Streamlit dashboard (upload mode)  
**Location used in examples:** `C:\Python310\phishing`  
**Purpose:** Teach and demo basic phishing detection using simple rules and a lightweight dashboard. Includes safe sample `.eml` generators.

---

## Contents

- `rule_phish_detector.py` — CLI script to scan `.eml` / `.txt` files and produce `results.json`.
- `dashboard.py` — Streamlit app that can load `results.json` or let users upload a single `.eml`/`.txt` to analyze interactively.
- `generate_samples.py` — (optional) Python script that creates multiple safe `.eml` test files in `eml/`.
- `eml/` — directory where sample emails live.
- `results.json` — detector output (UTF-8 JSON array).
- `results-debug.json` — debug info (discovered files, errors).
- `Phishing_Email_Detector_Instructions.docx` — (optional) detailed Word instructions and examples for students.

---

## Prerequisites

- Python 3.8+ (examples use Python 3.10)
- PowerShell (Windows examples)
- Recommended: a virtual environment

Python packages used:
- `streamlit`
- `beautifulsoup4`
- `tldextract`
- `chardet`

Install packages (run once):
```powershell
cd C:\Python310\phishing
.\Scripts\activate            # if using virtualenv
pip install streamlit beautifulsoup4 tldextract chardet
