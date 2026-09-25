#!/usr/bin/env python3
"""
Quick smoke test for CloudForge Identity Service.

Requires the service to be running on http://localhost:8000
and a valid .env file.

Usage:
    python scripts/test_token.py
"""

import base64
import json
import sys
import urllib.request
import urllib.error

BASE = "http://localhost:8000"
CLIENT_ID = "ingest-studio"
CLIENT_SECRET = "dev-ingest-secret-change-in-prod-9f3a2b1c"


def request(method: str, path: str, data: dict | None = None, auth: tuple | None = None):
    url = BASE + path
    headers = {"Content-Type": "application/json"}
    body = None
    if data is not None:
        body = json.dumps(data).encode()
    if auth:
        token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
        headers["Authorization"] = f"Basic {token}"

    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            detail = json.loads(body)
        except Exception:
            detail = body
        return e.code, detail


def main():
    print("1. Health check...")
    status, data = request("GET", "/health")
    assert status == 200, data
    print("   OK:", data)

    print("2. JWKS...")
    status, data = request("GET", "/.well-known/jwks.json")
    assert status == 200, data
    assert "keys" in data and len(data["keys"]) == 1
    key = data["keys"][0]
    assert key["kty"] == "RSA" and key["alg"] == "RS256" and key["kid"]
    assert key["n"] and key["e"] and key["n"] != "..."
    print("   OK: kid =", key["kid"])

    print("3. Issue token (Basic Auth)...")
    status, data = request(
        "POST",
        "/token",
        data={"scopes": ["ingest:read", "ingest:write"]},
        auth=(CLIENT_ID, CLIENT_SECRET),
    )
    assert status == 200, data
    assert "access_token" in data
    token = data["access_token"]
    print("   OK: token issued, expires_in =", data.get("expires_in"))
    print("   scope =", data.get("scope"))

    print("4. Reject unknown client...")
    status, data = request(
        "POST",
        "/token",
        data={"scopes": ["ingest:read"]},
        auth=("unknown-client", "whatever"),
    )
    assert status == 401, data
    print("   OK: 401")

    print("5. Reject wrong secret...")
    status, data = request(
        "POST",
        "/token",
        data={"scopes": ["ingest:read"]},
        auth=(CLIENT_ID, "wrong-secret"),
    )
    assert status == 401, data
    print("   OK: 401")

    print("6. Reject disallowed scope...")
    status, data = request(
        "POST",
        "/token",
        data={"scopes": ["ingest:read", "nova:query"]},
        auth=(CLIENT_ID, CLIENT_SECRET),
    )
    assert status == 403, data
    print("   OK: 403")

    print()
    print("✅ All smoke tests passed")
    print()
    print("Sample token (first 80 chars):")
    print(token[:80] + "...")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print("❌ Test failed:", e)
        sys.exit(1)
