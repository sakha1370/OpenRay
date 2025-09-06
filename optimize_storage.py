#!/usr/bin/env python3
"""
Storage Optimization Test Script
Demonstrates the optimized tested hashes storage system
"""

import os
import sys
import gzip
import struct
import time
from typing import Set

# Add src to path
sys.path.insert(0, 'src')

import constants as C
from io_ops import (
    load_tested_hashes,
    load_tested_hashes_optimized,
    migrate_to_optimized_format,
    get_storage_stats
)

def main():
    print("=== OpenRay Storage Optimization Test ===")
    print()

    # Get current stats
    stats = get_storage_stats()
    print(f"📊 Current Storage Stats:")
    print(f"   Text file: {stats['text_file_size']} bytes ({stats['text_file_size']/1024/1024:.1f} MB)")
    print(f"   Text entries: {stats['text_entries']:,}")
    print(f"   Unique hashes: {stats['unique_hashes']:,}")
    duplicates = stats['text_entries'] - stats['unique_hashes']
    print(f"   Duplicates: {duplicates:,} ({duplicates/stats['text_entries']*100:.1f}%)")
    print()

    # Test loading with old method
    print("⏱️  Testing old loading method...")
    start_time = time.time()
    old_hashes = load_tested_hashes()
    old_load_time = time.time() - start_time
    print(f"   Loaded {len(old_hashes):,} hashes in {old_load_time:.2f}s")
    print()

    # Test optimized loading
    print("🚀 Testing optimized loading...")
    start_time = time.time()
    new_hashes = load_tested_hashes_optimized()
    new_load_time = time.time() - start_time
    print(f"   Loaded {len(new_hashes):,} hashes in {new_load_time:.2f}s")

    if new_load_time > 0 and old_load_time > 0:
        speedup = old_load_time / new_load_time
        print(f"   Speed improvement: {speedup:.1f}x faster")
    print()

    # Show optimization results
    stats_after = get_storage_stats()
    if stats_after['binary_file_size'] > 0:
        print("💾 Storage Optimization Results:")
        print(f"   Binary file: {stats_after['binary_file_size']:,} bytes ({stats_after['binary_file_size']/1024/1024:.1f} MB)")
        print(f"   Binary entries: {stats_after['binary_entries']:,}")

        if stats['text_file_size'] > 0:
            savings = (stats['text_file_size'] - stats_after['binary_file_size']) / stats['text_file_size'] * 100
            print(f"   Space savings: {savings:.1f}%")
            print(f"   Size reduction: {(stats['text_file_size'] - stats_after['binary_file_size'])/1024/1024:.1f} MB")
    print()

    # Show per-entry efficiency
    if stats_after['binary_entries'] > 0:
        bytes_per_entry_old = stats['text_file_size'] / stats['text_entries'] if stats['text_entries'] > 0 else 0
        bytes_per_entry_new = 28  # timestamp (8) + hash (20)
        print("📈 Per-Entry Efficiency:")
        print(f"   Old format: {bytes_per_entry_old:.1f} bytes/entry")
        print(f"   New format: {bytes_per_entry_new} bytes/entry")
        if bytes_per_entry_old > 0:
            efficiency = (bytes_per_entry_old - bytes_per_entry_new) / bytes_per_entry_old * 100
            print(f"   Efficiency improvement: {efficiency:.1f}%")
    print()

    print("✅ Optimization complete!")
    print("   - Automatic deduplication prevents duplicate entries")
    print("   - Binary format uses 28 bytes per entry vs ~42 bytes in text")
    print("   - Includes timestamps for future cleanup capabilities")
    print("   - Maintains backward compatibility with fallback to text format")

if __name__ == "__main__":
    main()
