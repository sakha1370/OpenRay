#!/bin/bash
set -e

# Activate virtual environment
source /mnt/d/projects/OpenRay/.venv/bin/activate

# Go to repo
cd /mnt/d/projects/OpenRay

# Run your Python script
python3 -m src.main_local

# Check if there are changes before committing
if [ -n "$(git status --porcelain)" ]; then
    git add .
    git commit -m "Auto update: $(date '+%Y-%m-%d %H:%M:%S')"
    git push origin main
else
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] No changes to commit."
fi
