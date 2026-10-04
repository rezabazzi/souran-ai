#!/usr/bin/env python3
"""
Souran AI Network Server - Comprehensive Test Suite v3.2.0
Tests all components and features
"""

import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

VERSION = "3.1.0"
TESTS = []
PASSED = 0
FAILED = 0

def test(name, func):
    """Run a test"""
    global PASSED, FAILED
    try:
        result = func()
        if result:
            TESTS.append(("PASS", name))
            PASSED += 1
            print(f"✓ {name}")
        else:
            TESTS.append(("FAIL", name))
            FAILED += 1
            print(f"✗ {name}")
    except Exception as e:
        TESTS.append(("FAIL", name))
        FAILED += 1
        print(f"✗ {name}: {e}")

def check_port(port, proto='tcp'):
    """Check if port is listening"""
    try:
        result = subprocess.run(['ss', '-tulpn'], capture_output=True, text=True)
        return f':{port} ' in result.stdout
    except:
        return False

def check_dns():
    """Test DNS resolution"""
    try:
        result = subprocess.run(['dig', '@127.0.0.1', 'google.com', 'A', '+short'], 
                              capture_output=True, text=True, timeout=5)
        return bool(result.stdout.strip())
    except:
        return False

def check_service(name):
    """Check systemd service"""
    try:
        result = subprocess.run(['systemctl', 'is-active', name], 
                              capture_output=True, text=True)
        return result.stdout.strip() == 'active'
    except:
        return False

def check_http(port):
    """Check HTTP response"""
    try:
        result = subprocess.run(['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}', 
                               f'http://127.0.0.1:{port}/'], 
                              capture_output=True, text=True, timeout=3)
        return result.stdout.strip() == '200'
    except:
        return False

def check_file(path):
    """Check if file exists"""
    return Path(path).exists()

def check_tor():
    """Check Tor SOCKS proxy"""
    try:
        result = subprocess.run(['ss', '-tulpn'], capture_output=True, text=True)
        return ':9050 ' in result.stdout
    except:
        return False

# Run tests
print("=" * 60)
print(f"Souran AI Network Server v{VERSION} - Test Suite")
print("=" * 60)
print()

# DNS Tests
test("DNS Resolver (Port 53)", lambda: check_port(53, 'udp'))
test("DNS Resolution", check_dns)
test("DNS Service Active", lambda: check_service('souran-dns'))

# Dashboard Tests
test("Hermes Dashboard (8082)", lambda: check_http(8082))
test("Neuro Dashboard (8383)", lambda: check_http(8383))

# Tor Tests
test("Tor SOCKS (9050)", check_tor)
test("Tor Service", lambda: check_service('tor'))

# File Tests
test("DNS Resolver Script", lambda: check_file('/opt/souran-ai/dns/resolver.py'))
test("Watchdog Script", lambda: check_file('/opt/souran-ai/watchdog.sh'))
test("Anti-Compress Engine", lambda: check_file('/opt/souran-ai/anti_compress.py'))
test("Install Script", lambda: check_file('/opt/souran-ai/install-souran.sh'))
test("Web3 Resolver", lambda: check_file('/opt/souran-ai/dns/web3_resolver.py'))
test("DoT Server", lambda: check_file('/opt/souran-ai/dns/dot_server.py'))
test("DoH Server", lambda: check_file('/opt/souran-ai/dns/doh_server.py'))

# Version Tests
test("VERSION File", lambda: check_file('/opt/souran-ai/VERSION'))
test("Verification Report", lambda: check_file('/opt/souran-ai/VERIFICATION_REPORT.md'))

# Summary
print()
print("=" * 60)
print(f"Test Results: {PASSED} passed, {FAILED} failed")
print("=" * 60)

if FAILED == 0:
    print()
    print("ALL TESTS PASSED!")
    print("Souran AI Network Server is fully operational.")
    sys.exit(0)
else:
    print()
    print(f"{FAILED} test(s) failed. Review above.")
    sys.exit(1)