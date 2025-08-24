import os
import time
import requests

# Subconverter HTTP API endpoint; assumes subconverter service is running locally
SUBCONVERTER_BASE = "http://127.0.0.1:25500/sub"

INPUT_FILE = os.path.join("output_iran", "all_valid_proxies_for_iran.txt")
OUTPUT_DIR = os.path.join("output_iran", "converted")
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "clash.yaml")


def ensure_dirs():
    os.makedirs(OUTPUT_DIR, exist_ok=True)


def convert_subscription():
    ensure_dirs()
    if not os.path.isfile(INPUT_FILE):
        raise FileNotFoundError(f"Input subscription not found: {INPUT_FILE}")

    written_any = False
    total = 0
    ok = 0
    fail = 0

    with open(INPUT_FILE, "r", encoding="utf-8") as infile, open(OUTPUT_FILE, "w", encoding="utf-8") as outfile:
        for line in infile:
            node = line.strip()
            if not node:
                continue
            total += 1

            # Use requests params to ensure proper URL-encoding of the node value
            params = {
                "target": "clashmeta",  # use Clash.Meta to support VLESS/Reality
                "url": node,
                "list": "true",
            }

            try:
                resp = requests.get(SUBCONVERTER_BASE, params=params, timeout=30)
            except Exception as e:
                print(f"Request error for node: {node}: {e}")
                fail += 1
                continue

            if resp.ok and resp.text.strip():
                if written_any:
                    outfile.write("\n\n")
                outfile.write(resp.text.strip())
                outfile.write("\n")
                written_any = True
                ok += 1
            else:
                body = (resp.text or "").strip()
                if len(body) > 200:
                    body = body[:200] + "..."
                print(f"Failed to convert (status={getattr(resp, 'status_code', 'N/A')}): {node}\n  Response: {body}")
                fail += 1

            # small delay to be polite and avoid local rate limits
            time.sleep(0.01)

    print(f"Done. Success: {ok}/{total}, Failed: {fail}. Output: {OUTPUT_FILE}")


if __name__ == "__main__":
    convert_subscription()
