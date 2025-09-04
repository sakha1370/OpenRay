#!/bin/bash
set -e

# Activate virtual environment
source /mnt/d/projects/OpenRay/.venv/bin/activate

# Go to repo
cd /mnt/d/projects/OpenRay

# Try git pull, fallback to merge if it fails
if ! git pull origin main; then
    echo "git pull failed, retrying with merge..."
    git pull origin main --no-rebase
fi

# Run your Python script
python3 -m src.main_for_iran

# Convert subscription to Clash and Singbox formats
echo "Converting Iran subscription to config formats..."
python src/converter/sub2clash_singbox.py ./output_iran/iran_top100_checked.txt src/converter/config.yaml src/converter/singbox.json ./output_iran/converted/iran_top100_clash_config.yaml ./output_iran/converted/iran_top100_singbox_config.json
python src/converter/sub2clash_singbox.py ./output_iran/all_valid_proxies_for_iran.txt src/converter/config.yaml src/converter/singbox.json ./output_iran/converted/iran_all_valid_proxies_clash_config.yaml ./output_iran/converted/iran_all_valid_proxies_singbox_config.json

# Check if there are changes before committing
if [ -n "$(git status --porcelain)" ]; then
    git add .
    git commit -m "Auto update for iran: $(date '+%Y-%m-%d %H:%M:%S')"
    git push origin main
else
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] No changes to commit."
fi
