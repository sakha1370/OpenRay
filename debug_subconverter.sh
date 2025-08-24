#!/bin/bash
# debug_subconverter.sh

# Path to your file
FILE_PATH="/mnt/d/projects/OpenRay/output/test.txt"

# Show file info
echo "=== File Info ==="
ls -l "$FILE_PATH"
file "$FILE_PATH"

# Show first 5 lines with invisible characters
echo "=== File Preview (cat -A) ==="
head -n 5 "$FILE_PATH" | cat -A

# Curl command with verbose logging for file-based input
echo "=== Running SubConverter (file input) ==="
curl -v "http://localhost:25500/sub?target=clash&url=file://$FILE_PATH" -o clash_file.yaml

# Curl command for direct vmess link
VMESS_LINK="vmess://eyJ2IjoiMiIsInBzIjoiVGVzdCIsImFkZCI6InRlc3QuY29tIiwicG9ydCI6IjQ0MyIsImlkIjoiMTIzNCIsImFpZCI6IjAiLCJuZXQiOiJ3cyIsInBhdGgiOiIvIiwidGxzIjoidGxzIn0="
echo "=== Running SubConverter (vmess input) ==="
curl -v "http://localhost:25500/sub?target=clash&url=$VMESS_LINK" -o clash_vmess.yaml

# Check output files
echo "=== Output Files Info ==="
ls -l clash_file.yaml clash_vmess.yaml
echo "=== File Previews ==="
echo "--- clash_file.yaml ---"
head -n 10 clash_file.yaml
echo "--- clash_vmess.yaml ---"
head -n 10 clash_vmess.yaml

# Compare results
echo "=== Comparing Outputs ==="
if diff -q clash_file.yaml clash_vmess.yaml >/dev/null; then
    echo "✅ Outputs are identical."
else
    echo "❌ Outputs differ. Showing differences:"
    diff -u clash_file.yaml clash_vmess.yaml
fi
