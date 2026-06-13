#!/usr/bin/env python3
"""
SAFE TEST SAMPLE - Not real malware!
This is just a Python script that LOOKS suspicious for demo purposes.
It contains suspicious strings but does nothing harmful.
"""

import socket
import subprocess
import base64

# Suspicious strings that will be detected
SUSPICIOUS_COMMANDS = [
    "powershell -enc",
    "cmd.exe /c",
    "reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "schtasks /create",
]

# Looks like C2 communication (but fake)
C2_SERVER = "192.168.1.100"
C2_PORT = 4444

# Looks like credential theft (but fake)
def steal_credentials():
    """Fake credential theft - does nothing"""
    passwords = ["password123", "admin", "root"]
    return passwords

# Looks like persistence (but fake)
def create_persistence():
    """Fake persistence - does nothing"""
    registry_key = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\malware"
    return registry_key

# Looks like keylogger (but fake)
def keylogger():
    """Fake keylogger - does nothing"""
    keystrokes = []
    return keystrokes

# Encoded payload (just base64 of "This is a test")
ENCODED_PAYLOAD = base64.b64encode(b"This is a test payload").decode()

# Main function does nothing
if __name__ == "__main__":
    # This script intentionally does NOTHING
    # It just contains suspicious-looking code for testing
    pass

# More suspicious strings
MALWARE_INDICATORS = [
    "VirtualAlloc",
    "CreateRemoteThread",
    "WriteProcessMemory",
    "WScript.Shell",
    "rundll32",
]
