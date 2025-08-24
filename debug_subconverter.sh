#!/bin/bash
# debug_subconverter.sh

# Paths
RUN_PATH="/mnt/d/projects/OpenRay/src/subconverter/subconverter"
FILE_PATH="/mnt/d/projects/OpenRay/output/test.txt"
# Minimal config to avoid adding rules
CONFIG_PATH="/mnt/d/projects/OpenRay/src/config.yaml"

# Output files
OUT_API_FILE="clash_file_api.yaml"
OUT_API_VMESS="clash_vmess_api.yaml"
OUT_BIN_FILE="clash_file_bin.yaml"
OUT_BIN_VMESS="clash_vmess_bin.yaml"

# Vmess link
VMESS_LINK="vmess://eyJ2IjoiMiIsInBzIjoiVGVzdCIsImFkZCI6InRlc3QuY29tIiwicG9ydCI6IjQ0MyIsImlkIjoiMTIzNCIsImFpZCI6IjAiLCJuZXQiOiJ3cyIsInBhdGgiOiIvIiwidGxzIjoidGxzIn0="

# --- File info ---
echo "=== File Info ==="
ls -l "$FILE_PATH"
file "$FILE_PATH"
echo "=== File Preview (cat -A) ==="
head -n 5 "$FILE_PATH" | cat -A

# --- Run SubConverter via API ---
echo "=== Running SubConverter API (file input) ==="
curl -s "http://localhost:25500/sub?target=clash&url=file://$FILE_PATH" -o "$OUT_API_FILE"

# --- Generate YAML and save to output/generated_clash.yaml ---
curl "http://127.0.0.1:25500/sub?target=clash&url=file:///mnt/d/projects/OpenRay/output/test.txt" -o output/generated_clash.yaml

echo "=== Running SubConverter API (vmess input) ==="
curl -s "http://localhost:25500/sub?target=clash&url=$VMESS_LINK" -o "$OUT_API_VMESS"

# --- Run SubConverter binary (no rules) ---
echo "=== Running SubConverter Binary (file input) ==="
"$RUN_PATH" -i "$FILE_PATH" -o "$OUT_BIN_FILE" --target clash --config "$CONFIG_PATH" --no-merge

echo "=== Running SubConverter Binary (vmess input) ==="
"$RUN_PATH" -u "$VMESS_LINK" -o "$OUT_BIN_VMESS" --target clash --config "$CONFIG_PATH" --no-merge

# --- Check output files ---
echo "=== Output Files Info ==="
ls -l "$OUT_API_FILE" "$OUT_API_VMESS" "$OUT_BIN_FILE" "$OUT_BIN_VMESS"

echo "=== File Previews ==="
for f in "$OUT_API_FILE" "$OUT_API_VMESS" "$OUT_BIN_FILE" "$OUT_BIN_VMESS"; do
    echo "--- $f ---"
    head -n 10 "$f"
done

# --- Compare outputs ---
echo "=== Comparing API vs Binary Outputs ==="
for pair in \
    "$OUT_API_FILE $OUT_BIN_FILE" \
    "$OUT_API_VMESS $OUT_BIN_VMESS"; do
    f1=$(echo $pair | cut -d' ' -f1)
    f2=$(echo $pair | cut -d' ' -f2)
    echo "Comparing $f1 vs $f2..."
    if diff -q "$f1" "$f2" >/dev/null; then
        echo "✅ Outputs are identical."
    else
        echo "❌ Outputs differ. Showing differences:"
        diff -u "$f1" "$f2"
    fi
done
