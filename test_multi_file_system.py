#!/usr/bin/env python3
"""
Test script to demonstrate the multi-file tested.txt system.
This simulates how the system handles file rotation and data preservation.
"""

import os
import sys
from pathlib import Path

# Add src directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

try:
    from src.io_ops import (
        get_current_tested_file,
        get_all_tested_files,
        should_rotate_tested_file,
        rotate_tested_file,
        append_tested_hashes_optimized
    )
    from src.constants import REPO_ROOT
except ImportError as e:
    print(f"Error importing modules: {e}")
    print("Make sure you're running this from the OpenRay root directory")
    sys.exit(1)


def test_multi_file_system():
    """Test the multi-file system functionality."""
    print("=== Multi-File System Test ===")
    print("Note: This is a demonstration of how the system works.")
    print("Actual rotation occurs when files reach 50MB in production.\n")

    # Show current state
    print("📁 Current tested files:")
    tested_files = get_all_tested_files()
    for file in tested_files:
        size_mb = os.path.getsize(file) / (1024 * 1024) if os.path.exists(file) else 0
        current_marker = " (CURRENT)" if file == get_current_tested_file() else ""
        print(f"   {os.path.basename(file)}: {size_mb:.1f}MB{current_marker}")

    print(f"\n📊 Total files: {len(tested_files)}")

    # Test rotation logic
    if should_rotate_tested_file():
        print("\n🔄 Would rotate: Current file has reached 50MB limit")
        next_file = rotate_tested_file()
        print(f"   New current file would be: {os.path.basename(next_file)}")
    else:
        current_file = get_current_tested_file()
        size_mb = os.path.getsize(current_file) / (1024 * 1024) if os.path.exists(current_file) else 0
        print(f"\n✅ No rotation needed: {os.path.basename(current_file)} is {size_mb:.1f}MB (< 50MB)")

    print("\n🎯 Multi-File System Benefits:")
    print("   • All historical proxy data is preserved")
    print("   • Automatic file rotation when 50MB limit is reached")
    print("   • All files are read when checking proxy status")
    print("   • No data loss during rotation")
    print("   • Efficient storage with multiple manageable files")

    print("\n📝 How it works:")
    print("   1. tested.txt grows until it reaches 50MB")
    print("   2. New file tested_1.txt is created for new data")
    print("   3. tested_1.txt grows until it reaches 50MB")
    print("   4. New file tested_2.txt is created, and so on...")
    print("   5. When reading data, ALL files are checked")


if __name__ == '__main__':
    test_multi_file_system()
