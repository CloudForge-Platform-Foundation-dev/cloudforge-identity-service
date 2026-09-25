# CloudForge Identity Service

JWT issuer for the CloudForge Platform, implementing **Identity Contract v1**.

## Features

- **RS256 only** (no HS256 / shared secrets)
- **Audience** fixed to `cloudforge-platform` (single value for whole platform)
- **Client Credentials flow** with allowlist + secret verification
- **JWKS endpoint** computed from the real public key
- Private key loaded from environment variable (never hardcoded)

## Quick Start (local)

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Generate a keypair (first time only)
python scripts/generate_keys.py

# 3. Create .env from the example and fill secrets
cp .env.example .env
# Edit .env:
#   - paste the full content of private_key.pem into RSA_PRIVATE_KEY
#   - set strong random values for CLIENT_*_SECRET

# 4. Run
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

## Endpoints

| Method | Path                      | Description                          |
|--------|---------------------------|--------------------------------------|
| GET    | `/health`                 | Health check                         |
| GET    | `/.well-known/jwks.json`  | Public JWKS (for cloudforge-auth-core) |
| POST   | `/token`                  | Issue access token (Client Credentials) |

### Request token (HTTP Basic Auth – recommended)

```bash
curl -X POST http://localhost:8000/token \
  -u "ingest-studio:your-secret-here" \
  -H "Content-Type: application/json" \
  -d '{"scopes": ["ingest:read", "ingest:write"]}'
```

### Request token (JSON body)

```bash
curl -X POST http://localhost:8000/token \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "ingest-studio",
    "client_secret": "your-secret-here",
    "scopes": ["ingest:read"]
  }'
```

## Client Allowlist

Defined in `main.py` → `CLIENT_ALLOWLIST`.

Secrets are read from environment variables:

```
CLIENT_INGEST_STUDIO_SECRET=...
CLIENT_KNOWLEDGE_STUDIO_SECRET=...
CLIENT_NOVA_STUDIO_SECRET=...
```

To add a new studio:

1. Add entry to `CLIENT_ALLOWLIST` with its allowed scopes
2. Set the corresponding `CLIENT_..._SECRET` env var

## Security Notes

- Private key **must** come from env / secret manager – never commit it
- Only clients in the allowlist can obtain tokens
- Clients can only request scopes they are explicitly allowed
- Audience is forced to `cloudforge-platform` (client cannot override)
- Token lifetime defaults to 3600 seconds (configurable)

## Contract Compliance

| Claim / Rule              | Value                          |
|---------------------------|--------------------------------|
| `alg`                     | RS256                          |
| `aud`                     | `cloudforge-platform`          |
| `iss`                     | configurable (default internal)|
| `scope`                   | space-separated string         |
| Scope format              | `{studio}:{permission}`        |
| Error 401                 | invalid/missing credentials    |
| Error 403                 | valid client but scope denied  |
