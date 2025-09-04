#!/usr/bin/env python3
"""
Xray VLESS Proxy Tester

This script parses VLESS proxy URLs and tests them using Xray.
It generates Xray configuration files and tests proxy connectivity.

Usage:
    python xray_vless_tester.py [vless_url]

If no URL is provided, it reads from output_iran/test.txt
"""

import json
import os
import subprocess
import sys
import time
import urllib.parse
import requests
from urllib.parse import urlparse, parse_qs


class XrayVlessTester:
    def __init__(self, vless_url=None, test_url="https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent"):
        """
        Initialize Xray VLESS tester

        Args:
            vless_url (str): VLESS proxy URL. If None, reads from output_iran/test.txt
            test_url (str): URL to test through the proxy
        """
        self.vless_url = vless_url or self._read_vless_from_file()
        self.test_url = test_url
        self.config_path = "/tmp/xray_config.json"
        self.xray_process = None

        # Parse VLESS URL
        self.parsed_vless = self._parse_vless_url()

    def _read_vless_from_file(self):
        """Read VLESS URL from output_iran/test.txt"""
        file_path = "/mnt/d/projects/OpenRay/output_iran/test.txt"
        try:
            with open(file_path, 'r') as f:
                content = f.read().strip()
                # Find the first line that starts with vless://
                for line in content.split('\n'):
                    line = line.strip()
                    if line.startswith('vless://'):
                        return line
            raise ValueError("No VLESS URL found in file")
        except FileNotFoundError:
            raise FileNotFoundError(f"VLESS file not found: {file_path}")

    def _parse_vless_url(self):
        """Parse VLESS URL and extract components"""
        if not self.vless_url.startswith('vless://'):
            raise ValueError("Invalid VLESS URL format")

        # Remove vless:// prefix
        url_without_scheme = self.vless_url[8:]

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

    def generate_xray_config(self):
        """Generate Xray configuration file"""
        parsed = self.parsed_vless

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
                                "address": parsed['server'],
                                "port": parsed['port'],
                                "users": [
                                    {
                                        "id": parsed['uuid'],
                                        "encryption": parsed['encryption']
                                    }
                                ]
                            }
                        ]
                    },
                    "streamSettings": {
                        "network": parsed['type'],
                        "security": parsed['security']
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
        if parsed['type'] == 'ws':
            config["outbounds"][0]["streamSettings"]["wsSettings"] = {
                "path": parsed['path'],
                "headers": {
                    "Host": parsed['host']
                }
            }

        # Configure TLS if security is tls
        if parsed['security'] == 'tls':
            config["outbounds"][0]["streamSettings"]["tlsSettings"] = {
                "serverName": parsed['host']
            }

        return config

    def save_config(self):
        """Save Xray configuration to file"""
        config = self.generate_xray_config()
        with open(self.config_path, 'w') as f:
            json.dump(config, f, indent=2)
        return self.config_path

    def start_xray(self):
        """Start Xray process"""
        self.save_config()

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
                print("✅ Xray started successfully")
                return True
            else:
                stdout, stderr = self.xray_process.communicate()
                print("❌ Xray failed to start:")
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
            print("🛑 Xray stopped")

    def test_proxy(self):
        """Test the proxy by making a request through it"""
        try:
            # Configure requests to use the proxy
            proxies = {
                'http': 'socks5://127.0.0.1:1080',
                'https': 'socks5://127.0.0.1:1080'
            }

            print(f"🧪 Testing proxy with URL: {self.test_url}")

            start_time = time.time()
            response = requests.get(
                self.test_url,
                proxies=proxies,
                timeout=30,
                allow_redirects=True
            )
            end_time = time.time()

            response_time = round((end_time - start_time) * 1000, 2)

            result = {
                'success': True,
                'status_code': response.status_code,
                'response_time_ms': response_time,
                'content_length': len(response.content),
                'server': response.headers.get('server', 'unknown'),
                'final_url': response.url
            }

            return result

        except requests.exceptions.RequestException as e:
            return {
                'success': False,
                'error': str(e),
                'error_type': type(e).__name__
            }

    def run_test(self):
        """Run the complete proxy test"""
        print("\n" + "="*60)
        print("XRAY VLESS PROXY TEST")
        print("="*60)

        # Display parsed VLESS info
        parsed = self.parsed_vless
        print(f"📋 Proxy Name: {parsed['name']}")
        print(f"🔗 Server: {parsed['server']}:{parsed['port']}")
        print(f"👤 UUID: {parsed['uuid']}")
        print(f"🌐 Type: {parsed['type']}")
        print(f"🔒 Security: {parsed['security']}")
        print(f"🛡️  Encryption: {parsed['encryption']}")
        if parsed['type'] == 'ws':
            print(f"🌍 Host: {parsed['host']}")
            print(f"📁 Path: {parsed['path']}")

        print("\n🚀 Starting Xray...")

        if not self.start_xray():
            return

        try:
            print("\n⏳ Testing proxy connection...")
            result = self.test_proxy()

            print("\n" + "-"*40)
            print("TEST RESULTS")
            print("-"*40)

            if result['success']:
                print("✅ SUCCESS: Proxy is working!")
                print(f"📊 Status Code: {result['status_code']}")
                print(f"⏱️  Response Time: {result['response_time_ms']} ms")
                print(f"📄 Content Length: {result['content_length']} bytes")
                print(f"🖥️  Server: {result['server']}")
                if result.get('final_url') and result['final_url'] != self.test_url:
                    print(f"🔄 Final URL: {result['final_url']}")
            else:
                print("❌ FAILED: Proxy test failed")
                print(f"🔍 Error: {result['error']}")
                print(f"📋 Error Type: {result['error_type']}")

        finally:
            self.stop_xray()

        print("\n" + "="*60)


def main():
    # Check if VLESS URL provided as argument
    vless_url = None
    if len(sys.argv) > 1:
        vless_url = sys.argv[1]

    # Create tester
    tester = XrayVlessTester(vless_url)

    # Run the test
    tester.run_test()


if __name__ == "__main__":
    main()
