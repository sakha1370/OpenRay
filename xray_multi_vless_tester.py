#!/usr/bin/env python3
"""
Xray Multi-VLESS Proxy Tester

This script parses multiple VLESS proxy URLs from a text file and tests them using Xray.
It generates Xray configuration files and tests proxy connectivity for each proxy.

Usage:
    python xray_multi_vless_tester.py [input_file]

If no file is provided, it reads from output_iran/test.txt
"""

import json
import os
import subprocess
import sys
import time
import urllib.parse
import requests
from urllib.parse import urlparse, parse_qs
try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False


class XrayMultiVlessTester:
    def __init__(self, input_file=None, test_url="https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent", expected_status_codes=None):
        """
        Initialize Xray Multi-VLESS tester

        Args:
            input_file (str): Path to file containing VLESS URLs. If None, uses output_iran/test.txt
            test_url (str): URL to test through each proxy
            expected_status_codes (list): List of expected HTTP status codes (e.g., [200, 301]). If None, any 2xx code is considered success
        """
        self.input_file = input_file or "/mnt/d/projects/OpenRay/output_iran/test.txt"
        self.test_url = test_url
        self.expected_status_codes = expected_status_codes or [200, 201, 202, 301, 302, 303, 307, 308]  # Default success codes
        self.config_path = "/tmp/xray_config.json"
        self.xray_process = None

        # Read all VLESS URLs from file
        self.vless_urls = self._read_vless_urls()

    def _read_vless_urls(self):
        """Read all VLESS URLs from the input file"""
        try:
            with open(self.input_file, 'r') as f:
                content = f.read()
                vless_urls = []
                for line in content.split('\n'):
                    line = line.strip()
                    if line.startswith('vless://'):
                        vless_urls.append(line)
                return vless_urls
        except FileNotFoundError:
            print(f"❌ Error: File not found: {self.input_file}")
            return []
        except Exception as e:
            print(f"❌ Error reading file: {e}")
            return []

    def _parse_vless_url(self, vless_url):
        """Parse VLESS URL and extract components"""
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

    def generate_xray_config(self, parsed_vless):
        """Generate Xray configuration file"""
        config = {
            "log": {
                "loglevel": "warning"
            },
            "inbounds": [
                {
                    "port": 1080,
                    "protocol": "socks",
                    "settings": {
                        "auth": "noauth",
                        "udp": True
                    },
                    "sniffing": {
                        "enabled": True,
                        "destOverride": ["http", "tls"]
                    }
                },
                {
                    "port": 8080,
                    "protocol": "http",
                    "settings": {
                        "auth": "noauth"
                    }
                }
            ],
            "outbounds": [
                {
                    "protocol": "vless",
                    "settings": {
                        "vnext": [
                            {
                                "address": parsed_vless['server'],
                                "port": parsed_vless['port'],
                                "users": [
                                    {
                                        "id": parsed_vless['uuid'],
                                        "encryption": parsed_vless['encryption']
                                    }
                                ]
                            }
                        ]
                    },
                    "streamSettings": {
                        "network": parsed_vless['type'],
                        "security": parsed_vless['security']
                    }
                },
                {
                    "protocol": "freedom",
                    "tag": "direct"
                }
            ],
            "routing": {
                "rules": [
                    {
                        "type": "field",
                        "outboundTag": "direct",
                        "domain": ["geosite:cn"]
                    }
                ]
            }
        }

        # Configure WebSocket settings if type is ws
        if parsed_vless['type'] == 'ws':
            config["outbounds"][0]["streamSettings"]["wsSettings"] = {
                "path": parsed_vless['path'],
                "headers": {
                    "Host": parsed_vless['host']
                }
            }

        # Configure TLS if security is tls
        if parsed_vless['security'] == 'tls':
            config["outbounds"][0]["streamSettings"]["tlsSettings"] = {
                "serverName": parsed_vless['host']
            }

        return config

    def start_xray(self, parsed_vless):
        """Start Xray process with specific proxy configuration"""
        config = self.generate_xray_config(parsed_vless)
        with open(self.config_path, 'w') as f:
            json.dump(config, f, indent=2)

        try:
            # Start Xray in background
            self.xray_process = subprocess.Popen(
                ['xray', '-config', self.config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            # Wait a moment for Xray to start
            time.sleep(2)

            # Check if process is still running
            if self.xray_process.poll() is None:
                return True
            else:
                stdout, stderr = self.xray_process.communicate()
                print(f"❌ Xray failed to start:")
                print(f"STDOUT: {stdout.decode()}")
                print(f"STDERR: {stderr.decode()}")
                return False

        except FileNotFoundError:
            print("❌ Xray not found. Please make sure Xray is installed and in PATH")
            return False
        except Exception as e:
            print(f"❌ Error starting Xray: {e}")
            return False

    def stop_xray(self):
        """Stop Xray process"""
        if self.xray_process and self.xray_process.poll() is None:
            self.xray_process.terminate()
            self.xray_process.wait()

    def test_single_proxy(self, vless_url, proxy_index):
        """Test a single proxy"""
        try:
            # Parse the VLESS URL
            parsed_vless = self._parse_vless_url(vless_url)

            print(f"\n{'='*60}")
            print(f"TESTING PROXY #{proxy_index + 1}")
            print('='*60)

            # Display proxy info
            print(f"📋 Name: {parsed_vless['name']}")
            print(f"🔗 Server: {parsed_vless['server']}:{parsed_vless['port']}")
            print(f"👤 UUID: {parsed_vless['uuid']}")
            print(f"🌐 Type: {parsed_vless['type']}")
            print(f"🔒 Security: {parsed_vless['security']}")
            if parsed_vless['type'] == 'ws':
                print(f"🌍 Host: {parsed_vless['host']}")
                print(f"📁 Path: {parsed_vless['path']}")

            print("\n🚀 Starting Xray...")

            if not self.start_xray(parsed_vless):
                return {
                    'proxy_index': proxy_index + 1,
                    'name': parsed_vless['name'],
                    'success': False,
                    'error': 'Failed to start Xray',
                    'response_time_ms': 0
                }

            print("⏳ Testing proxy connection...")
            result = self._test_connection()

            self.stop_xray()

            result.update({
                'proxy_index': proxy_index + 1,
                'name': parsed_vless['name'],
                'server': f"{parsed_vless['server']}:{parsed_vless['port']}"
            })

            return result

        except Exception as e:
            self.stop_xray()
            return {
                'proxy_index': proxy_index + 1,
                'name': 'Unknown',
                'success': False,
                'error': str(e),
                'response_time_ms': 0
            }

    def _test_connection(self):
        """Test the proxy connection"""
        try:
            # Configure requests to use the proxy
            proxies = {
                'http': 'socks5://127.0.0.1:1080',
                'https': 'socks5://127.0.0.1:1080'
            }

            start_time = time.time()
            response = requests.get(
                self.test_url,
                proxies=proxies,
                timeout=30,
                allow_redirects=True
            )
            end_time = time.time()

            response_time = round((end_time - start_time) * 1000, 2)

            # Check if status code matches expected codes
            status_code_match = response.status_code in self.expected_status_codes

            return {
                'success': status_code_match,
                'status_code': response.status_code,
                'status_code_match': status_code_match,
                'expected_codes': self.expected_status_codes,
                'response_time_ms': response_time,
                'content_length': len(response.content),
                'server': response.headers.get('server', 'unknown'),
                'final_url': response.url if response.url != self.test_url else None
            }

        except requests.exceptions.RequestException as e:
            return {
                'success': False,
                'status_code_match': False,
                'expected_codes': self.expected_status_codes,
                'error': str(e),
                'error_type': type(e).__name__,
                'response_time_ms': 0
            }

    def run_all_tests(self):
        """Run tests for all proxies"""
        if not self.vless_urls:
            print("❌ No VLESS URLs found in the input file!")
            return

        print(f"\n🎯 Found {len(self.vless_urls)} VLESS proxy(ies) to test")
        print(f"🎯 Test URL: {self.test_url}")
        print(f"🎯 Expected Status Codes: {self.expected_status_codes}")

        results = []
        successful_proxies = 0
        matching_status_proxies = 0

        # Use tqdm progress bar if more than 3 proxies and tqdm is available
        if len(self.vless_urls) > 3 and TQDM_AVAILABLE:
            print("\n📊 Testing proxies with progress bar...")
            proxy_iterator = tqdm(self.vless_urls, desc="Testing Proxies", unit="proxy")
        else:
            proxy_iterator = self.vless_urls

        for i, vless_url in enumerate(proxy_iterator):
            result = self.test_single_proxy(vless_url, i)
            results.append(result)

            if result['success']:
                successful_proxies += 1
            if result.get('status_code_match', False):
                matching_status_proxies += 1

        # Display summary
        self._display_summary(results, successful_proxies, matching_status_proxies)

    def _display_summary(self, results, successful_count, matching_status_count):
        """Display test summary"""
        print(f"\n{'='*80}")
        print("📊 TEST SUMMARY")
        print('='*80)
        print(f"📋 Total Proxies Tested: {len(results)}")
        print(f"✅ Successful: {successful_count}")
        print(f"❌ Failed: {len(results) - successful_count}")
        print(f"🎯 Status Code Matches: {matching_status_count}")
        print(f"📊 Success Rate: {(successful_count / len(results) * 100):.1f}%")
        print(f"🎯 Status Match Rate: {(matching_status_count / len(results) * 100):.1f}%")
        print(f"\n{'='*80}")
        print("📈 DETAILED RESULTS")
        print('='*80)

        # Sort by response time (successful first, then by speed)
        sorted_results = sorted(results, key=lambda x: (not x['success'], x['response_time_ms']))

        for result in sorted_results:
            status_icon = "✅" if result['success'] else "❌"
            status_text = "SUCCESS" if result['success'] else "FAILED"

            # Status code match indicator
            match_icon = "🎯" if result.get('status_code_match', False) else "❌"
            match_text = "MATCH" if result.get('status_code_match', False) else "NO MATCH"

            print(f"\n{status_icon} Proxy #{result['proxy_index']}: {result['name']}")
            print(f"   Server: {result.get('server', 'N/A')}")

            if result['success']:
                print(f"   Status: {result['status_code']} {match_icon} ({match_text})")
                print(f"   Expected: {result.get('expected_codes', 'N/A')}")
                print(f"   Response Time: {result['response_time_ms']} ms")
                print(f"   Content Length: {result['content_length']} bytes")
                if result.get('server'):
                    print(f"   Server: {result['server']}")
            else:
                print(f"   Status Code Match: {match_icon} {match_text}")
                print(f"   Expected: {result.get('expected_codes', 'N/A')}")
                print(f"   Error: {result.get('error', 'Unknown error')}")

        # Show fastest successful proxy
        successful_results = [r for r in results if r['success']]
        if successful_results:
            fastest = min(successful_results, key=lambda x: x['response_time_ms'])
            print(f"\n🏆 FASTEST PROXY: #{fastest['proxy_index']} - {fastest['name']} ({fastest['response_time_ms']} ms)")

        # Show best status code match
        matching_results = [r for r in results if r.get('status_code_match', False)]
        if matching_results:
            best_match = min(matching_results, key=lambda x: x['response_time_ms'])
            print(f"🎯 BEST STATUS MATCH: #{best_match['proxy_index']} - {best_match['name']} ({best_match['response_time_ms']} ms)")


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Test multiple VLESS proxies using Xray")
    parser.add_argument('input_file', nargs='?', help='Path to file containing VLESS URLs')
    parser.add_argument('--expected-status-codes', nargs='+', type=int,
                       default=[200, 201, 202, 301, 302, 303, 307, 308],
                       help='Expected HTTP status codes (default: 200, 201, 202, 301, 302, 303, 307, 308)')
    parser.add_argument('--install-tqdm', action='store_true',
                       help='Install tqdm if not available')

    args = parser.parse_args()

    # Install tqdm if requested
    tqdm_installed = False
    if args.install_tqdm and not TQDM_AVAILABLE:
        print("📦 Installing tqdm...")
        try:
            import subprocess
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'tqdm'])
            tqdm_installed = True
            print("✅ tqdm installed successfully!")
        except subprocess.CalledProcessError:
            print("❌ Failed to install tqdm. Continuing without progress bar.")

    # Re-import tqdm if we just installed it
    if tqdm_installed:
        try:
            from tqdm import tqdm
            TQDM_AVAILABLE = True
        except ImportError:
            pass

    # Create tester
    tester = XrayMultiVlessTester(
        input_file=args.input_file,
        expected_status_codes=args.expected_status_codes
    )

    # Run all tests
    tester.run_all_tests()


if __name__ == "__main__":
    main()
