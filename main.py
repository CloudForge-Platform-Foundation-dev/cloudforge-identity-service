"""
CloudForge Identity Service v1.1.0
Secure JWT issuer following CloudForge Identity Contract v1.

- Algorithm: RS256 only
- Audience: cloudforge-platform (single value for entire platform)
- Scope format: {studio}:{permission} (e.g. ingest:read)
- Private key loaded from environment (never hardcoded)
- Client Credentials flow with allowlist + secret verification
"""

import os
import hmac
import time
import base64
from typing import Any, Optional

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

ISSUER = os.getenv("IDENTITY_ISSUER", "https://identity.cloudforge.internal")
DEFAULT_AUDIENCE = "cloudforge-platform"
KEY_ID = os.getenv("IDENTITY_KEY_ID", "cloudforge-key-2026-v1")
TOKEN_TTL_SECONDS = int(os.getenv("TOKEN_TTL_SECONDS", "3600"))

# Client allowlist: client_id -> allowed scopes
# Secrets are loaded from environment variables: CLIENT_{CLIENT_ID_UPPER}_SECRET
# Example: CLIENT_INGEST_STUDIO_SECRET=...
CLIENT_ALLOWLIST: dict[str, dict[str, Any]] = {
    "ingest-studio": {
        "allowed_scopes": ["ingest:read", "ingest:write"],
    },
    "knowledge-studio": {
        "allowed_scopes": ["knowledge:read", "knowledge:write"],
    },
    "nova-studio": {
        "allowed_scopes": ["nova:query"],
    },
    # Add more studios here as needed
}

# ---------------------------------------------------------------------------
# Key loading
# ---------------------------------------------------------------------------

def _load_private_key() -> rsa.RSAPrivateKey:
    pem = os.getenv("RSA_PRIVATE_KEY")
    if not pem:
        raise RuntimeError(
            "RSA_PRIVATE_KEY environment variable is required. "
            "Generate a keypair with: python scripts/generate_keys.py"
        )
    # Support both escaped newlines and real multiline
    pem = pem.replace("\\n", "\n")
    try:
        key = serialization.load_pem_private_key(
            pem.encode("utf-8"),
            password=None,
            backend=default_backend(),
        )
        if not isinstance(key, rsa.RSAPrivateKey):
            raise ValueError("Key is not an RSA private key")
        return key
    except Exception as e:
        raise RuntimeError(f"Failed to load RSA_PRIVATE_KEY: {e}") from e


def _get_public_numbers(private_key: rsa.RSAPrivateKey):
    public_key = private_key.public_key()
    return public_key.public_numbers()


# Load once at startup
PRIVATE_KEY = _load_private_key()
PUBLIC_NUMBERS = _get_public_numbers(PRIVATE_KEY)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _int_to_base64url(n: int) -> str:
    """Convert integer to base64url-encoded string (no padding)."""
    length = (n.bit_length() + 7) // 8
    data = n.to_bytes(length, byteorder="big")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _get_client_secret(client_id: str) -> str | None:
    """Load client secret from env: CLIENT_{CLIENT_ID_UPPER_WITH_UNDERSCORES}_SECRET"""
    env_key = f"CLIENT_{client_id.upper().replace('-', '_')}_SECRET"
    return os.getenv(env_key)


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="CloudForge Identity Service",
    version="1.1.0",
    description="JWT issuer for CloudForge Platform (Identity Contract v1)",
)

security = HTTPBasic(auto_error=False)


class TokenRequest(BaseModel):
    # Optional body fields (client_id/secret can also come from Basic Auth)
    client_id: str | None = None
    client_secret: str | None = None
    scopes: list[str] = Field(default_factory=list)
    audience: str | list[str] = DEFAULT_AUDIENCE


@app.get("/health")
def health():
    return {"status": "ok", "service": "cloudforge-identity-service", "version": "1.1.0"}


@app.get("/.well-known/jwks.json")
def get_jwks():
    """Return JWKS computed from the real public key."""
    n = _int_to_base64url(PUBLIC_NUMBERS.n)
    e = _int_to_base64url(PUBLIC_NUMBERS.e)
    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": KEY_ID,
                "n": n,
                "e": e,
            }
        ]
    }


@app.post("/token")
def issue_token(
    req: TokenRequest,
    credentials: Optional[HTTPBasicCredentials] = Depends(security),
):
    """
    Issue an access token using Client Credentials flow.

    Authentication:
      - Preferred: HTTP Basic Auth (client_id:client_secret)
      - Fallback: client_id + client_secret in JSON body

    Only clients in CLIENT_ALLOWLIST can request tokens, and only
    for scopes they are allowed to hold.
    """
    # Resolve client_id / secret (Basic Auth takes precedence)
    client_id = None
    client_secret = None

    if credentials is not None:
        client_id = credentials.username
        client_secret = credentials.password
    else:
        client_id = req.client_id
        client_secret = req.client_secret

    if not client_id or not client_secret:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="client_id and client_secret are required (Basic Auth or body)",
            headers={"WWW-Authenticate": "Basic"},
        )

    # 1. Client must exist in allowlist
    if client_id not in CLIENT_ALLOWLIST:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unknown client_id",
            headers={"WWW-Authenticate": "Basic"},
        )

    # 2. Secret must match
    expected_secret = _get_client_secret(client_id)
    if not expected_secret or not hmac.compare_digest(client_secret, expected_secret):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid client credentials",
            headers={"WWW-Authenticate": "Basic"},
        )

    # 3. Scopes must be subset of allowed scopes
    allowed = set(CLIENT_ALLOWLIST[client_id]["allowed_scopes"])
    requested = set(req.scopes)
    if not requested.issubset(allowed):
        forbidden = requested - allowed
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Client is not allowed to request scopes: {sorted(forbidden)}",
        )

    # Force audience to platform value (ignore client-supplied value for security)
    audience = DEFAULT_AUDIENCE

    now = int(time.time())
    scope_str = " ".join(sorted(requested))  # deterministic order

    payload = {
        "iss": ISSUER,
        "sub": client_id,
        "aud": audience,
        "exp": now + TOKEN_TTL_SECONDS,
        "nbf": now,
        "iat": now,
        "scope": scope_str,
    }

    headers = {"kid": KEY_ID, "alg": "RS256"}

    try:
        token = jwt.encode(
            payload,
            PRIVATE_KEY,
            algorithm="RS256",
            headers=headers,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to sign token: {e}",
        ) from e

    return {
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": TOKEN_TTL_SECONDS,
        "scope": scope_str,
    }
