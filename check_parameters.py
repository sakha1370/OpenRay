#!/usr/bin/env python3
"""
OpenRay Parameter Health Check Script
Run this to validate your current parameter settings and detect potential issues.
"""

import os
import sys
import time
import socket
import multiprocessing
from concurrent.futures import ThreadPoolExecutor

# Add src directory to path so we can import constants
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

try:
    from constants import *
    print("✅ Successfully imported OpenRay constants")
except ImportError as e:
    print(f"❌ Failed to import constants: {e}")
    sys.exit(1)

def check_network_connectivity():
    """Test basic network connectivity."""
    print("\n🌐 NETWORK CONNECTIVITY TEST:")
    test_hosts = [('8.8.8.8', 53), ('1.1.1.1', 443), ('208.67.222.222', 443)]

    for host, port in test_hosts:
        try:
            start = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect((host, port))
            sock.close()
            response_time = (time.time() - start) * 1000
            print(f"✅ {host}:{port} - {response_time:.1f}ms")
        except Exception as e:
            print(f"❌ {host}:{port} - Failed: {str(e)[:50]}")

def check_worker_feasibility():
    """Test if worker pools can be created successfully."""
    print("\n⚙️ WORKER POOL FEASIBILITY:")

    def dummy_task():
        time.sleep(0.01)
        return "success"

    # Test FETCH_WORKERS
    try:
        with ThreadPoolExecutor(max_workers=FETCH_WORKERS) as executor:
            futures = [executor.submit(dummy_task) for _ in range(min(FETCH_WORKERS, 10))]
            results = [f.result() for f in futures]
        print(f"✅ FETCH_WORKERS ({FETCH_WORKERS}) - OK")
    except Exception as e:
        print(f"❌ FETCH_WORKERS ({FETCH_WORKERS}) - Failed: {str(e)[:50]}")

    # Test PING_WORKERS
    try:
        with ThreadPoolExecutor(max_workers=PING_WORKERS) as executor:
            futures = [executor.submit(dummy_task) for _ in range(min(PING_WORKERS, 20))]
            results = [f.result() for f in futures]
        print(f"✅ PING_WORKERS ({PING_WORKERS}) - OK")
    except Exception as e:
        print(f"❌ PING_WORKERS ({PING_WORKERS}) - Failed: {str(e)[:50]}")

def analyze_parameters():
    """Analyze current parameter values for potential issues."""
    print("\n🔍 PARAMETER ANALYSIS:")

    cpu_cores = multiprocessing.cpu_count()
    print(f"System CPU cores: {cpu_cores}")

    # Worker analysis
    issues = []

    if FETCH_WORKERS > cpu_cores * 3:
        issues.append(f"⚠️ FETCH_WORKERS ({FETCH_WORKERS}) very high for {cpu_cores} cores")
    elif FETCH_WORKERS < 1:
        issues.append(f"❌ FETCH_WORKERS ({FETCH_WORKERS}) must be at least 1")

    if PING_WORKERS > cpu_cores * 4:
        issues.append(f"⚠️ PING_WORKERS ({PING_WORKERS}) very high for {cpu_cores} cores")
    elif PING_WORKERS < 1:
        issues.append(f"❌ PING_WORKERS ({PING_WORKERS}) must be at least 1")

    if STAGE3_WORKERS > cpu_cores * 2:
        issues.append(f"⚠️ STAGE3_WORKERS ({STAGE3_WORKERS}) very high for {cpu_cores} cores")
    elif STAGE3_WORKERS < 1:
        issues.append(f"❌ STAGE3_WORKERS ({STAGE3_WORKERS}) must be at least 1")

    # Timeout analysis
    if PING_TIMEOUT_MS < 100:
        issues.append(f"⚠️ PING_TIMEOUT_MS ({PING_TIMEOUT_MS}ms) very low")
    if CONNECT_TIMEOUT_MS < 200:
        issues.append(f"⚠️ CONNECT_TIMEOUT_MS ({CONNECT_TIMEOUT_MS}ms) very low")
    if PROBE_TIMEOUT_MS < 200:
        issues.append(f"⚠️ PROBE_TIMEOUT_MS ({PROBE_TIMEOUT_MS}ms) very low")

    # Limit analysis
    if STAGE3_MAX < 1:
        issues.append(f"❌ STAGE3_MAX ({STAGE3_MAX}) must be at least 1")
    if NEW_URIS_LIMIT < 1:
        issues.append(f"❌ NEW_URIS_LIMIT ({NEW_URIS_LIMIT}) must be at least 1")

    if issues:
        for issue in issues:
            print(issue)
    else:
        print("✅ No parameter issues detected")

def memory_estimate():
    """Provide memory usage estimates."""
    print("\n💾 MEMORY USAGE ESTIMATE:")

    # Rough estimates
    ping_memory = PING_WORKERS * 50  # ~50MB per ping worker
    stage3_memory = STAGE3_WORKERS * 100  # ~100MB per V2Ray process
    fetch_memory = FETCH_WORKERS * 20  # ~20MB per fetch worker
    total_estimate = ping_memory + stage3_memory + fetch_memory

    print(f"Estimated peak memory usage: ~{total_estimate}MB")
    print(f"  • Ping workers: {PING_WORKERS} × 50MB = {ping_memory}MB")
    print(f"  • Stage3 workers: {STAGE3_WORKERS} × 100MB = {stage3_memory}MB")
    print(f"  • Fetch workers: {FETCH_WORKERS} × 20MB = {fetch_memory}MB")

    if total_estimate > 8000:
        print("⚠️ High memory usage - consider reducing worker counts")
    elif total_estimate < 1000:
        print("💡 Memory usage is low - could increase workers for better performance")
    else:
        print("✅ Memory usage looks reasonable")

def show_current_parameters():
    """Display all current parameter values."""
    print("\n🎯 CURRENT PARAMETER VALUES:")
    print("="*60)
    print(f"WORKERS:")
    print(f"  FETCH_WORKERS: {FETCH_WORKERS}")
    print(f"  PING_WORKERS: {PING_WORKERS}")
    print(f"  STAGE3_WORKERS: {STAGE3_WORKERS}")
    print(f"\nTIMEOUTS:")
    print(f"  PING_TIMEOUT_MS: {PING_TIMEOUT_MS}ms")
    print(f"  CONNECT_TIMEOUT_MS: {CONNECT_TIMEOUT_MS}ms")
    print(f"  PROBE_TIMEOUT_MS: {PROBE_TIMEOUT_MS}ms")
    print(f"  FETCH_TIMEOUT: {FETCH_TIMEOUT}s")
    print(f"\nLIMITS:")
    print(f"  STAGE3_MAX: {STAGE3_MAX}")
    print(f"  NEW_URIS_LIMIT: {NEW_URIS_LIMIT}")
    print(f"  CONSECUTIVE_REQUIRED: {CONSECUTIVE_REQUIRED}")
    print("="*60)

def main():
    """Main function to run all checks."""
    print("🔧 OpenRay Parameter Health Check")
    print("==================================")

    show_current_parameters()
    check_network_connectivity()
    check_worker_feasibility()
    analyze_parameters()
    memory_estimate()

    print("\n" + "="*60)
    print("💡 TIPS:")
    print("   • Run with OPENRAY_DEBUG=1 to see debug info")
    print("   • Use environment variables to override parameters:")
    print("     OPENRAY_PING_WORKERS=16 OPENRAY_PING_TIMEOUT_MS=500")
    print("   • Monitor system resources during proxy testing")
    print("   • If you see errors, check system memory and CPU usage")
    print("="*60)

if __name__ == "__main__":
    main()
