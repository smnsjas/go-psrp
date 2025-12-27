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
        "127.0.0.1",
        port=5985,
        username="testuser",
        password="REDACTED_PASSWORD",
        ssl=False,
        auth="ntlm"
    ) as client:
        output, streams, had_errors = client.execute_ps("hostname")
        print(f"\n=== RESULT ===")
        print(f"Output: {output}")
        print(f"Had errors: {had_errors}")

if __name__ == "__main__":
    main()
