#!/usr/bin/env python3
"""
Tested Files Management Script

This script helps manage tested.txt files that can grow large over time.
It provides functionality to:
- Check file sizes
- Rotate files when they exceed 99MB
- View archived files
- Clean up old archives
"""

import os
import sys
import argparse
from datetime import datetime, timedelta
from pathlib import Path

# Add src directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

try:
    from src.io_ops import (
        TESTED_FILE, TESTED_BIN_FILE, STATE_DIR,
        get_storage_stats, get_all_tested_files,
        should_rotate_tested_file, rotate_tested_file,
        get_current_tested_file
    )
    from src.constants import REPO_ROOT
except ImportError as e:
    print(f"Error importing modules: {e}")
    print("Make sure you're running this from the OpenRay root directory")
    sys.exit(1)


def get_file_size_mb(filepath: str) -> float:
    """Get file size in MB."""
    if not os.path.exists(filepath):
        return 0.0
    return os.path.getsize(filepath) / (1024 * 1024)


def list_archive_files(state_dir: str) -> list:
    """List all archived tested.txt files."""
    archives = []
    if os.path.exists(state_dir):
        for file in os.listdir(state_dir):
            if file.startswith('tested.txt.') and file.endswith('.archive'):
                filepath = os.path.join(state_dir, file)
                size_mb = get_file_size_mb(filepath)
                mtime = os.path.getmtime(filepath)
                archives.append((filepath, size_mb, mtime))
    return sorted(archives, key=lambda x: x[2], reverse=True)


def cleanup_old_archives(state_dir: str, days_to_keep: int = 30) -> int:
    """Remove archive files older than specified days. Returns count of removed files."""
    cutoff_date = datetime.now() - timedelta(days=days_to_keep)
    archives = list_archive_files(state_dir)
    removed_count = 0

    for filepath, _, mtime in archives:
        file_date = datetime.fromtimestamp(mtime)
        if file_date < cutoff_date:
            try:
                os.remove(filepath)
                print(f"Removed old archive: {os.path.basename(filepath)}")
                removed_count += 1
            except Exception as e:
                print(f"Failed to remove {filepath}: {e}")

    return removed_count


def show_file_status():
    """Show current status of all tested files."""
    print("=== Tested Files Status (Multi-File System) ===")

    # Main state directory
    main_state_dir = os.path.join(REPO_ROOT, '.state')
    main_tested_files = get_all_tested_files()

    print(f"\n📁 Main State Directory: {main_state_dir}")

    if main_tested_files:
        total_size = 0
        file_count = 0
        for tested_file in main_tested_files:
            if os.path.basename(tested_file).startswith('tested'):
                size_mb = get_file_size_mb(tested_file)
                total_size += size_mb
                file_count += 1
                current_marker = " (CURRENT)" if tested_file == get_current_tested_file() else ""
                print(f"   {os.path.basename(tested_file)}: {size_mb:.1f}MB{current_marker}")

        print(f"   Total: {file_count} files, {total_size:.1f}MB")
        print(f"   Status: {'⚠️ Large files' if total_size >= 80 else '✅ Normal size'}")
    else:
        print("   Status: No tested files found")

    # Iran state directory
    iran_state_dir = os.path.join(REPO_ROOT, '.state_iran')
    iran_tested_file = os.path.join(iran_state_dir, 'tested.txt')

    print(f"\n📁 Iran State Directory: {iran_state_dir}")
    if os.path.exists(iran_tested_file):
        size_mb = get_file_size_mb(iran_tested_file)
        print(f"   tested.txt: {size_mb:.1f}MB")
        print(f"   Status: {'⚠️ Large file' if size_mb >= 80 else '✅ Normal size'}")
    else:
        print("   Status: File does not exist")

    # Show archive files (keeping this for backward compatibility)
    print("\n📦 Archive Files:")
    for state_dir, label in [(main_state_dir, "Main"), (iran_state_dir, "Iran")]:
        archives = list_archive_files(state_dir)
        if archives:
            print(f"\n  {label} Archives:")
            for filepath, size_mb, mtime in archives[:5]:  # Show last 5
                date_str = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M")
                print(f"    {os.path.basename(filepath)} - {size_mb:.1f}MB - {date_str}")
            if len(archives) > 5:
                print(f"    ... and {len(archives) - 5} more")
        else:
            print(f"\n  {label} Archives: None")


def monitor_files():
    """Monitor multi-file system sizes and provide warnings/recommendations."""
    print("=== Multi-File Size Monitoring ===")

    warnings = []

    # Check main multi-file system
    main_tested_files = get_all_tested_files()
    if main_tested_files:
        total_size = 0
        large_files = []

        print("\n📁 Main tested files:")
        for tested_file in main_tested_files:
            if os.path.basename(tested_file).startswith('tested'):
                size_mb = get_file_size_mb(tested_file)
                total_size += size_mb
                current_marker = " (CURRENT)" if tested_file == get_current_tested_file() else ""
                print(f"   {os.path.basename(tested_file)}: {size_mb:.1f}MB{current_marker}")

                if size_mb >= 100:
                    large_files.append(os.path.basename(tested_file))
                    warnings.append(f"Main {os.path.basename(tested_file)}: {size_mb:.1f}MB")

        print(f"   Total across all files: {total_size:.1f}MB")

        if large_files:
            print(f"   ⚠️  Large files detected: {', '.join(large_files)}")
        elif total_size >= 200:  # Warning for total size across all files
            print("   ⚠️  WARNING: Total size across all files is large")
            warnings.append(f"Main total: {total_size:.1f}MB")
        else:
            print("   ✅ All files within normal range")
    # Check Iran file
    iran_tested_file = os.path.join(REPO_ROOT, '.state_iran', 'tested.txt')
    if os.path.exists(iran_tested_file):
        size_mb = get_file_size_mb(iran_tested_file)
        print(f"\n📁 Iran tested.txt: {size_mb:.1f}MB")

        if size_mb >= 100:
            print("   ⚠️  WARNING: File is over 100MB!")
            warnings.append(f"Iran file: {size_mb:.1f}MB")
        elif size_mb >= 80:
            print("   ⚠️  WARNING: File is approaching 100MB limit")
        else:
            print("   ✅ Size is within normal range")
    if warnings:
        print("\n🚨 ACTION REQUIRED:")
        print("   • System will automatically create new files when current file reaches 99MB")
        print("   • All data is preserved across multiple files")
        print("   • Monitor disk space usage")
        print(f"\n📊 Files needing attention: {len(warnings)}")
    else:
        print("\n✅ All files are within acceptable size limits")
        print("   • Multi-file rotation system active")
        print("   • All tested proxy data is preserved")


def main():
    parser = argparse.ArgumentParser(description="Monitor tested.txt multi-file system (all data preserved)")
    parser.add_argument('action', choices=['status', 'monitor', 'cleanup'],
                       help='Action to perform')
    parser.add_argument('--cleanup-days', type=int, default=30,
                       help='Days to keep archives when cleaning up (default: 30)')

    args = parser.parse_args()

    if args.action == 'status':
        show_file_status()
    elif args.action == 'monitor':
        monitor_files()
    elif args.action == 'cleanup':
        print(f"=== Cleaning up archives older than {args.cleanup_days} days ===")

        total_removed = 0
        for state_dir in [os.path.join(REPO_ROOT, '.state'),
                         os.path.join(REPO_ROOT, '.state_iran')]:
            if os.path.exists(state_dir):
                removed = cleanup_old_archives(state_dir, args.cleanup_days)
                total_removed += removed
                print(f"Cleaned {removed} archives from {state_dir}")

        print(f"\n📊 Cleanup Summary: {total_removed} archive(s) removed")


if __name__ == '__main__':
    main()
