import time
import jwt
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field

app = FastAPI(title="CloudForge Identity Service", version="1.1.0")

RSA_PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----"
KEY_ID = "cloudforge-key-2026-v1"
ISSUER = "https://identity.cloudforge.internal"
DEFAULT_AUDIENCE = "cloudforge-platform"

class TokenRequest(BaseModel):
    client_id: str
    scopes: list[str] = Field(default_factory=list)
    audience: list[str] | str = Field(default_factory=lambda: DEFAULT_AUDIENCE)

@app.post("/token")
def issue_token(req: TokenRequest):
    now = int(time.time())
    scope_str = " ".join(req.scopes)
    payload = {
        "iss": ISSUER,
        "sub": req.client_id,
        "aud": req.audience,
        "exp": now + 3600,
        "nbf": now,
        "iat": now,
        "scope": scope_str
    }
    headers = {"kid": KEY_ID, "alg": "RS256"}
    try:
        token = jwt.encode(payload, RSA_PRIVATE_KEY, algorithm="RS256", headers=headers)
        return {"access_token": token, "token_type": "Bearer", "expires_in": 3600}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/.well-known/jwks.json")
def get_jwks():
    return {"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": KEY_ID, "n": "...", "e": "AQAB"}]}

