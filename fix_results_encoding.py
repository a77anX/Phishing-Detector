# fix_results_encoding.py
import chardet, json, sys, os

SRC = "results.json"
OUT = "results-utf8.json"

if not os.path.exists(SRC):
    print(f"Source file not found: {SRC}")
    sys.exit(2)

raw = open(SRC, "rb").read()

det = chardet.detect(raw)
enc = det.get("encoding") or "utf-8"
confidence = det.get("confidence", 0)
print(f"Detected encoding: {enc} (confidence {confidence})")

# try decode with detected encoding, then some common fallbacks
text = None
for attempt in [enc, "utf-8", "utf-16", "utf-16-le", "utf-16-be", "latin-1"]:
    try:
        text = raw.decode(attempt)
        print(f"Decoded successfully with: {attempt}")
        break
    except Exception as e:
        # continue to next
        # print("decode failed with", attempt, e)
        pass

if text is None:
    # as last resort decode with replacement to avoid crash
    text = raw.decode("utf-8", errors="replace")
    print("Decoded with utf-8 (errors=replace)")

# Try parse JSON either as array or line-delimited
data = None
try:
    data = json.loads(text)
    if isinstance(data, dict):
        data = [data]
    print(f"Parsed JSON: {len(data)} object(s)")
except Exception as e:
    # try newline-delimited JSON
    items = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                items.append(obj)
        except Exception:
            pass
    if items:
        data = items
        print(f"Parsed newline-delimited JSON: {len(data)} object(s)")
    else:
        print("ERROR: Could not parse JSON from file after decoding.")
        sys.exit(3)

# Write canonical UTF-8 JSON array
with open(OUT, "w", encoding="utf-8") as fh:
    json.dump(data, fh, indent=2, ensure_ascii=False)
print(f"Wrote UTF-8 JSON to: {OUT}")

