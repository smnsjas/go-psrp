#!/usr/bin/env python3
"""Capture pypsrp traffic for comparison with go-psrp."""

import logging
from pypsrp.client import Client

# Enable debug logging to see all HTTP traffic
logging.basicConfig(level=logging.DEBUG)

# Also enable urllib3 debug logging
logging.getLogger("urllib3").setLevel(logging.DEBUG)
logging.getLogger("pypsrp").setLevel(logging.DEBUG)

def main():
    with Client(
        "10.211.55.6",
        port=5985,
        username="winrm-test",
        password="sigK@@6=q8B2z8iQDzbiqJr4",
        ssl=False,
        auth="ntlm"
    ) as client:
        output, streams, had_errors = client.execute_ps("hostname")
        print(f"\n=== RESULT ===")
        print(f"Output: {output}")
        print(f"Had errors: {had_errors}")

if __name__ == "__main__":
    main()
