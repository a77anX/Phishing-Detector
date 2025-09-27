#!/usr/bin/env python3
"""
Verbose rule-based phishing detector (accepts .eml and .txt files).

Usage:
  python rule_phish_detector.py --dir "C:\Python310\phishing\eml" --json-pretty
  python rule_phish_detector.py --file "C:\path\to\one.eml" --json-pretty
  python rule_phish_detector.py --file "C:\path\to\one.txt" --json-pretty
"""

import os
import re
import json
import argparse
import traceback
from email import policy
from email.parser import BytesParser

# ---------- Simple rule-based analysis ----------
SUSPICIOUS_KEYWORDS = [
    "urgent", "verify", "update", "password", "login", "bank", "suspend",
    "click here", "account", "verify now", "confirm", "payment failed"
]

SHORT_URL_PATTERN = re.compile(r"\b(bit\.ly|t\.co|tinyurl\.com|goo\.gl|ow\.ly|rebrand\.ly)\b", re.IGNORECASE)
LINK_REGEX = re.compile(r"https?://[^\s'\"<>]+")

def extract_text_from_msg(msg):
    """Return (plain_text, html_text) best-effort"""
    plain_parts = []
    html_parts = []
    try:
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                try:
                    payload = part.get_content()
                except Exception:
                    payload = part.get_payload(decode=True)
                    if isinstance(payload, bytes):
                        payload = payload.decode(errors="ignore")
                if not payload:
                    continue
                if ctype == "text/plain":
                    plain_parts.append(str(payload))
                elif ctype == "text/html":
                    html_parts.append(str(payload))
        else:
            ctype = msg.get_content_type()
            try:
                payload = msg.get_content()
            except Exception:
                payload = msg.get_payload(decode=True)
                if isinstance(payload, bytes):
                    payload = payload.decode(errors="ignore")
            if ctype == "text/plain":
                plain_parts.append(str(payload))
            elif ctype == "text/html":
                html_parts.append(str(payload))
    except Exception:
        # fallback
        try:
            payload = msg.get_payload(decode=True)
            if isinstance(payload, bytes):
                plain_parts.append(payload.decode(errors="ignore"))
        except Exception:
            pass
    plain = "\n".join(plain_parts).strip()
    html = "\n".join(html_parts).strip()
    return plain, html

def analyze_email_file(path):
    """Analyze a single file path. Returns dict result or raises."""
    with open(path, "rb") as fh:
        raw = fh.read()
    # parse bytes to EmailMessage
    msg = BytesParser(policy=policy.default).parsebytes(raw)

    from_hdr = (msg.get("From") or "").strip()
    to_hdr = (msg.get("To") or "").strip()
    subject = (msg.get("Subject") or "").strip()

    plain, html = extract_text_from_msg(msg)
    combined = (subject or "") + "\n" + (plain or "")

    # links detection (both html + plain)
    links = LINK_REGEX.findall((html or "") + "\n" + (plain or ""))
    num_links = len(links)
    num_short_urls = sum(1 for l in links if SHORT_URL_PATTERN.search(l))

    # suspicious keywords count (sum of occurrences)
    low = (combined or "").lower()
    suspicious_keyword_count = sum(low.count(k) for k in SUSPICIOUS_KEYWORDS)

    # domain mismatch: compare link domains to from-domain (simple heuristic)
    domain_mismatch = 0
    try:
        if "@" in from_hdr and links:
            from_dom = from_hdr.split("@")[-1].replace(">", "").strip().lower()
            link_domains = []
            for l in links:
                m = re.match(r"https?://([^/]+)/?", l, re.IGNORECASE)
                if m:
                    link_domains.append(m.group(1).lower())
            if any(ld and ld not in from_dom for ld in link_domains):
                domain_mismatch = 1
    except Exception:
        domain_mismatch = 0

    # scoring & reasons
    score = 0
    reasons = []
    breakdown = {}
    if suspicious_keyword_count:
        add = suspicious_keyword_count * 2
        score += add
        breakdown["suspicious_keyword"] = add
        reasons.append(f"suspicious_keyword:+{add}")
    if num_short_urls:
        add = num_short_urls * 3
        score += add
        breakdown["short_url"] = add
        reasons.append(f"short_url:+{add}")
    if domain_mismatch:
        add = 3
        score += add
        breakdown["domain_mismatch"] = add
        reasons.append(f"domain_mismatch:+{add}")

    verdict = "phishing" if score >= 6 else "benign"
    severity = "high" if score >= 10 else "medium" if score >= 6 else "low"

    return {
        "from": from_hdr,
        "to": to_hdr,
        "subject": subject,
        "num_links": num_links,
        "num_short_urls": num_short_urls,
        "domain_mismatch": domain_mismatch,
        "suspicious_keyword_count": suspicious_keyword_count,
        "score_breakdown": breakdown,
        "final_score": score,
        "verdict": verdict,
        "severity": severity,
        "reasons": reasons,
        "source_file": path,
    }

# ---------- Main driver with debug output ----------
def main():
    ap = argparse.ArgumentParser()
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument("--file", help="Path to single .eml or .txt file to analyze")
    group.add_argument("--dir", help="Directory with files to analyze (accepts .eml and .txt)")
    group.add_argument("--stdin", action="store_true", help="Read email bytes from stdin")
    ap.add_argument("--json-pretty", action="store_true", help="Pretty write JSON")
    ap.add_argument("--output", default="results.json", help="Output JSON (UTF-8) - default results.json")
    ap.add_argument("--debug-out", default="results-debug.json", help="Debug JSON with discovered files and errors")
    args = ap.parse_args()

    results = []
    debug = {"discovered_files": [], "parsed_count": 0, "errors": []}

    if args.file:
        if not os.path.exists(args.file):
            print(f"Error: file not found: {args.file}")
        else:
            debug["discovered_files"].append(args.file)
            try:
                r = analyze_email_file(args.file)
                results.append(r)
                debug["parsed_count"] += 1
            except Exception as e:
                debug["errors"].append({"file": args.file, "error": str(e), "trace": traceback.format_exc()})
    elif args.dir:
        if not os.path.isdir(args.dir):
            print(f"Error: directory not found: {args.dir}")
        else:
            files = []
            for root, _, filenames in os.walk(args.dir):
                for fn in filenames:
                    low = fn.lower()
                    # Accept both .eml and .txt files
                    if low.endswith(".eml") or low.endswith(".txt"):
                        files.append(os.path.join(root, fn))
            files_sorted = sorted(files)
            debug["discovered_files"] = files_sorted
            print(f"Found {len(files_sorted)} file(s) under {args.dir} (accepting .eml and .txt)")
            for p in files_sorted:
                try:
                    r = analyze_email_file(p)
                    results.append(r)
                    debug["parsed_count"] += 1
                except Exception as e:
                    debug["errors"].append({"file": p, "error": str(e), "trace": traceback.format_exc()})
    elif args.stdin:
        import sys, tempfile
        try:
            data = sys.stdin.buffer.read()
            with tempfile.NamedTemporaryFile(delete=False, suffix=".eml") as tmp:
                tmp.write(data)
                tmp_path = tmp.name
            debug["discovered_files"].append(tmp_path)
            try:
                r = analyze_email_file(tmp_path)
                results.append(r)
                debug["parsed_count"] += 1
            except Exception as e:
                debug["errors"].append({"file": tmp_path, "error": str(e), "trace": traceback.format_exc()})
            finally:
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass
        except Exception as e:
            print("Failed to read stdin:", e)

    # Write results JSON (UTF-8)
    try:
        with open(args.output, "w", encoding="utf-8") as fh:
            if args.json_pretty:
                json.dump(results, fh, indent=2, ensure_ascii=False)
            else:
                json.dump(results, fh, ensure_ascii=False)
    except Exception as e:
        print("Failed to write results file:", e)
        debug["errors"].append({"file": args.output, "error": f"write_failed:{e}"})

    # Write debug file
    debug["saved_results_count"] = len(results)
    try:
        with open(args.debug_out, "w", encoding="utf-8") as fh:
            json.dump(debug, fh, indent=2, ensure_ascii=False)
    except Exception as e:
        print("Failed to write debug file:", e)

    # Print summary
    print(f"✅ Analysis complete. Found {len(debug['discovered_files'])} file(s), parsed {debug['parsed_count']} file(s). Saved {len(results)} result(s) to {args.output}")
    if debug["errors"]:
        print(f"⚠️  Encountered {len(debug['errors'])} error(s). See {args.debug_out} for details.")

if __name__ == "__main__":
    main()
