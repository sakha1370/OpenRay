#!/usr/bin/env python3
"""
Xray VLESS Proxy Tester - High Performance Version

This script parses VLESS proxy URLs and tests them using Xray with concurrent processing.
It can test single proxies or batch test multiple proxies from files.

Usage:
    python xray_vless_tester.py [vless_url] [--batch] [--max N] [--expected-status N] [--output filename] [--workers N]

Options:
    vless_url    Test a single VLESS proxy URL
    --batch      Test all proxies from files (default behavior when no URL provided)
    --max N      Test only first N proxies when in batch mode
    --expected-status N  Expected status code for successful proxies (default: 404)
    --output filename    Output file for successful proxies (default: working_proxies.txt)
    --workers N  Number of concurrent workers (default: 10)

If no URL is provided, it reads multiple proxies from:
- output_iran/all_valid_proxies_for_iran.txt (preferred)
- output_iran/iran_top100_checked.txt (fallback)
"""

import json
import os
import subprocess
import sys
import time
import urllib.parse
import requests
import threading
import queue
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs
from datetime import datetime
import random
import tempfile


class FastXrayVlessTester:
    def __init__(self, vless_urls=None, test_url="https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent", 
                 expected_status_code=404, output_file="working_proxies_404.txt", max_workers=10):
        """
        Initialize Fast Xray VLESS tester

        Args:
            vless_urls (list): List of VLESS proxy URLs. If None, reads from files
            test_url (str): URL to test through the proxy
            expected_status_code (int): Expected status code for successful proxies
            output_file (str): File to save working proxies
            max_workers (int): Number of concurrent workers
        """
        self.vless_urls = vless_urls or self._read_vless_urls_from_files()
        self.test_url = test_url
        self.expected_status_code = expected_status_code
        self.output_file = output_file
        self.max_workers = max_workers
        
        # Thread-safe file writing
        self.file_lock = threading.Lock()
        self.output_initialized = False
        
        # Performance settings
        self.xray_start_timeout = 3  # Reduced from 2 seconds
        self.test_timeout = 15       # Reduced from 30 seconds
        
    def _read_vless_urls_from_files(self):
        """Read multiple VLESS URLs from files"""
        urls = []

        # Try multiple file paths
        file_paths = [
            "/mnt/d/projects/OpenRay/output_iran/all_valid_proxies_for_iran.txt",
            "/mnt/d/projects/OpenRay/output_iran/iran_top100_checked.txt",  
        ]
        
        for file_path in file_paths:
            try:
                with open(file_path, 'r') as f:
                    content = f.read().strip()
                    for line in content.split('\n'):
                        line = line.strip()
                        if line.startswith('vless://'):
                            urls.append(line)
                if urls:
                    print(f"📁 Found {len(urls)} VLESS URLs in {file_path}")
                    return urls
            except FileNotFoundError:
                continue

        raise FileNotFoundError("No VLESS files found in output_iran/ directory")

    def _parse_vless_url(self, vless_url):
        """Parse VLESS URL and extract components - optimized version"""
        if not vless_url.startswith('vless://'):
            raise ValueError("Invalid VLESS URL format")

        # Remove vless:// prefix
        url_without_scheme = vless_url[8:]

        # Split by @ to separate UUID and server info
        if '@' not in url_without_scheme:
            raise ValueError("Invalid VLESS URL: missing @ separator")

        uuid_part, server_part = url_without_scheme.split('@', 1)

        # Parse server part (server:port?params#name)
        if '?' in server_part:
            server_port, params_part = server_part.split('?', 1)
        else:
            server_port = server_part
            params_part = ""

        # Extract name if present
        name = ""
        if '#' in params_part:
            params_part, name = params_part.split('#', 1)
            name = urllib.parse.unquote(name)

        # Parse server and port
        if ':' not in server_port:
            raise ValueError("Invalid server:port format")
        server, port_str = server_port.rsplit(':', 1)
        port = int(port_str)

        # Parse parameters
        params = {}
        if params_part:
            params = parse_qs(params_part)

        return {
            'uuid': uuid_part,
            'server': server,
            'port': port,
            'params': params,
            'name': name,
            'type': params.get('type', ['tcp'])[0],
            'security': params.get('security', ['none'])[0],
            'encryption': params.get('encryption', ['none'])[0],
            'host': params.get('host', [server])[0],
            'path': urllib.parse.unquote(params.get('path', ['/'])[0])
        }

    def _generate_xray_config(self, parsed_vless, socks_port, http_port):
        """Generate Xray configuration with dynamic ports"""
        config = {
            "log": {"loglevel": "error"},  # Reduced logging for speed
            "inbounds": [
                {
                    "port": socks_port,
                    "protocol": "socks",
                    "settings": {"auth": "noauth", "udp": True},
                    "sniffing": {"enabled": False}  # Disabled for speed
                },
                {
                    "port": http_port,
                    "protocol": "http",
                    "settings": {"auth": "noauth"}
                }
            ],
            "outbounds": [
                {
                    "protocol": "vless",
                    "settings": {
                        "vnext": [{
                            "address": parsed_vless['server'],
                            "port": parsed_vless['port'],
                            "users": [{
                                "id": parsed_vless['uuid'],
                                "encryption": parsed_vless['encryption']
                            }]
                        }]
                    },
                    "streamSettings": {
                        "network": parsed_vless['type'],
                        "security": parsed_vless['security']
                    }
                }
            ]
        }

        # Configure WebSocket settings if type is ws
        if parsed_vless['type'] == 'ws':
            config["outbounds"][0]["streamSettings"]["wsSettings"] = {
                "path": parsed_vless['path'],
                "headers": {"Host": parsed_vless['host']}
            }

        # Configure TLS if security is tls
        if parsed_vless['security'] == 'tls':
            config["outbounds"][0]["streamSettings"]["tlsSettings"] = {
                "serverName": parsed_vless['host'],
                "allowInsecure": True  # Speed up TLS handshake
            }

        return config

    def _get_available_ports(self, base_port=10000):
        """Get two available ports for socks and http"""
        import socket
        
        def is_port_available(port):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                return s.connect_ex(('localhost', port)) != 0
        
        # Find available ports
        socks_port = base_port + random.randint(1, 5000)
        while not is_port_available(socks_port):
            socks_port += 1
            
        http_port = socks_port + 1
        while not is_port_available(http_port):
            http_port += 1
            
        return socks_port, http_port

    def _test_single_proxy_worker(self, vless_url, worker_id):
        """Worker function to test a single proxy - optimized"""
        try:
            # Parse VLESS URL
            parsed = self._parse_vless_url(vless_url)
            
            # Get unique ports for this worker
            socks_port, http_port = self._get_available_ports(10000 + worker_id * 100)
            
            # Generate config
            config = self._generate_xray_config(parsed, socks_port, http_port)
            
            # Create temporary config file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump(config, f)
                config_path = f.name

            try:
                # Start Xray process
                process = subprocess.Popen(
                    ['xray', '-config', config_path],
                    stdout=subprocess.DEVNULL,  # Suppress output for speed
                    stderr=subprocess.DEVNULL
                )

                # Quick start check
                time.sleep(self.xray_start_timeout)
                
                if process.poll() is not None:
                    return {
                        'url': vless_url,
                        'name': parsed['name'],
                        'server': f"{parsed['server']}:{parsed['port']}",
                        'success': False,
                        'error': 'Xray failed to start',
                        'status_code': None,
                        'response_time_ms': None,
                        'matches_expected': False
                    }

                # Test proxy
                try:
                    proxies = {
                        'http': f'socks5://127.0.0.1:{socks_port}',
                        'https': f'socks5://127.0.0.1:{socks_port}'
                    }

                    start_time = time.time()
                    
                    # Create session for better performance
                    session = requests.Session()
                    session.proxies.update(proxies)
                    
                    response = session.get(
                        self.test_url,
                        timeout=self.test_timeout,
                        allow_redirects=False,  # Faster without redirects
                        headers={'User-Agent': 'Mozilla/5.0'}  # Simple UA
                    )
                    
                    end_time = time.time()
                    response_time = round((end_time - start_time) * 1000, 2)

                    result = {
                        'url': vless_url,
                        'name': parsed['name'],
                        'server': f"{parsed['server']}:{parsed['port']}",
                        'success': True,
                        'status_code': response.status_code,
                        'response_time_ms': response_time,
                        'matches_expected': response.status_code == self.expected_status_code
                    }

                    # Save if matches expected status
                    if result['matches_expected']:
                        self._save_working_proxy_threadsafe(vless_url, response.status_code, response_time)

                    return result

                except requests.exceptions.RequestException as e:
                    return {
                        'url': vless_url,
                        'name': parsed['name'],
                        'server': f"{parsed['server']}:{parsed['port']}",
                        'success': False,
                        'error': str(e)[:100],  # Truncate long errors
                        'status_code': None,
                        'response_time_ms': None,
                        'matches_expected': False
                    }

            finally:
                # Clean up
                if process and process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        process.kill()
                
                # Remove config file
                try:
                    os.unlink(config_path)
                except OSError:
                    pass

        except Exception as e:
            return {
                'url': vless_url,
                'name': 'Unknown',
                'server': 'Unknown',
                'success': False,
                'error': str(e)[:100],
                'status_code': None,
                'response_time_ms': None,
                'matches_expected': False
            }

    def _save_working_proxy_threadsafe(self, vless_url, status_code, response_time_ms):
        """Thread-safe proxy saving"""
        with self.file_lock:
            try:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                with open(self.output_file, 'a', encoding='utf-8') as f:
                    f.write(f"# Status: {status_code} | Response Time: {response_time_ms}ms | Tested: {timestamp}\n")
                    f.write(f"{vless_url}\n\n")
            except Exception as e:
                print(f"❌ Error saving proxy: {e}")

    def _initialize_output_file(self):
        """Initialize output file with header"""
        if not self.output_initialized:
            with self.file_lock:
                if not self.output_initialized:  # Double-check locking
                    try:
                        with open(self.output_file, 'w', encoding='utf-8') as f:
                            f.write(f"# Working VLESS Proxies - Expected Status Code: {self.expected_status_code}\n")
                            f.write(f"# Test Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                            f.write(f"# Test URL: {self.test_url}\n")
                            f.write(f"# Workers: {self.max_workers}\n\n")
                        self.output_initialized = True
                    except Exception as e:
                        print(f"❌ Error initializing output file: {e}")

    def test_multiple_proxies_concurrent(self, max_proxies=None):
        """Test multiple proxies concurrently for maximum speed"""
        urls_to_test = self.vless_urls[:max_proxies] if max_proxies else self.vless_urls
        
        print(f"\n🚀 Starting high-speed concurrent test of {len(urls_to_test)} proxies...")
        print(f"⚡ Using {self.max_workers} concurrent workers")
        print(f"🎯 Looking for status code: {self.expected_status_code}")
        print(f"💾 Saving working proxies to: {self.output_file}")
        print("="*80)

        # Initialize output file
        self._initialize_output_file()

        results = []
        completed = 0
        saved_count = 0
        
        start_time = time.time()

        # Use ThreadPoolExecutor for concurrent testing
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_url = {
                executor.submit(self._test_single_proxy_worker, url, i % self.max_workers): url 
                for i, url in enumerate(urls_to_test)
            }

            # Process completed tasks
            for future in as_completed(future_to_url):
                completed += 1
                try:
                    result = future.result()
                    results.append(result)
                    
                    if result.get('matches_expected'):
                        saved_count += 1
                    
                    # Progress indicator
                    if completed % 10 == 0 or completed == len(urls_to_test):
                        elapsed = time.time() - start_time
                        rate = completed / elapsed if elapsed > 0 else 0
                        print(f"⏳ Progress: {completed}/{len(urls_to_test)} | "
                              f"Rate: {rate:.1f}/sec | "
                              f"Saved: {saved_count} | "
                              f"Elapsed: {elapsed:.1f}s")
                        
                except Exception as e:
                    print(f"❌ Task error: {e}")

        elapsed_time = time.time() - start_time
        print(f"\n🏁 Completed in {elapsed_time:.1f} seconds ({len(urls_to_test)/elapsed_time:.1f} proxies/sec)")
        
        return results

    def test_single_proxy(self, vless_url):
        """Test a single proxy"""
        return self._test_single_proxy_worker(vless_url, 0)

    def print_summary(self, results):
        """Print optimized summary"""
        print("\n" + "="*80)
        print("📊 TEST SUMMARY")
        print("="*80)

        successful = [r for r in results if r['success']]
        failed = [r for r in results if not r['success']]
        matching_expected = [r for r in results if r.get('matches_expected', False)]

        print(f"📈 Total tested: {len(results)}")
        print(f"✅ Successful: {len(successful)} ({len(successful)/len(results)*100:.1f}%)")
        print(f"🎯 Expected status ({self.expected_status_code}): {len(matching_expected)} ({len(matching_expected)/len(results)*100:.1f}%)")
        print(f"❌ Failed: {len(failed)} ({len(failed)/len(results)*100:.1f}%)")

        if matching_expected:
            print(f"\n💾 {len(matching_expected)} working proxies saved to: {self.output_file}")
            
            # Show fastest proxies
            fastest = sorted([r for r in matching_expected if r.get('response_time_ms')], 
                           key=lambda x: x['response_time_ms'])[:5]
            if fastest:
                print(f"\n⚡ Fastest {len(fastest)} working proxies:")
                for i, proxy in enumerate(fastest, 1):
                    print(f"   {i}. {proxy['server']} - {proxy['response_time_ms']}ms")

        print("="*80)


def main():
    import argparse

    parser = argparse.ArgumentParser(description='Fast Xray VLESS Proxy Tester')
    parser.add_argument('vless_url', nargs='?', help='Single VLESS proxy URL to test')
    parser.add_argument('--batch', action='store_true', help='Test all proxies from files')
    parser.add_argument('--max', type=int, help='Maximum number of proxies to test in batch mode')
    parser.add_argument('--expected-status', type=int, default=404, 
                       help='Expected status code for successful proxies (default: 404)')
    parser.add_argument('--output', type=str, default='working_proxies.txt', 
                       help='Output file for working proxies (default: working_proxies.txt)')
    parser.add_argument('--workers', type=int, default=10, 
                       help='Number of concurrent workers (default: 10)')

    args = parser.parse_args()

    # Determine if we should do batch testing
    batch_mode = args.batch or (args.vless_url is None)

    if batch_mode:
        # Batch testing mode
        print("🔄 High-speed batch testing mode enabled")

        if args.vless_url:
            # Single URL provided but batch mode requested
            tester = FastXrayVlessTester([args.vless_url], 
                                       expected_status_code=args.expected_status, 
                                       output_file=args.output,
                                       max_workers=args.workers)
        else:
            # Read from files
            tester = FastXrayVlessTester(expected_status_code=args.expected_status, 
                                       output_file=args.output,
                                       max_workers=args.workers)

        # Test multiple proxies concurrently
        results = tester.test_multiple_proxies_concurrent(args.max)
        tester.print_summary(results)

    else:
        # Single proxy testing mode
        print("🔗 Single proxy testing mode")
        tester = FastXrayVlessTester([args.vless_url], 
                                   expected_status_code=args.expected_status, 
                                   output_file=args.output,
                                   max_workers=1)
        result = tester.test_single_proxy(args.vless_url)

        if result['success']:
            print("\n✅ SUCCESS!")
            status_code = result.get('status_code', 'N/A')
            print(f"📊 Status: {status_code}")
            print(f"⏱️  Response time: {result['response_time_ms']}ms")
            
            if result.get('matches_expected'):
                print(f"🎯 Status matches expected ({tester.expected_status_code}) - Proxy saved!")
            else:
                print(f"⚠️  Status doesn't match expected ({tester.expected_status_code})")
        else:
            print("\n❌ FAILED!")
            print(f"🔍 Error: {result['error']}")


if __name__ == "__main__":
    main()