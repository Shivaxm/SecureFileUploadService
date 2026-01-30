# Secure File Upload Service

[![CI](https://github.com/Shivaxm/SecureFileUploadService/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Shivaxm/SecureFileUploadService/actions/workflows/ci.yml)

FastAPI + Postgres + MinIO + Redis + RQ service for secure, presigned uploads with checksum verification, sniffing, audit logs, rate limits, and quotas.

## Key features
- **Presigned uploads** keep the API off the file data path (bandwidth-friendly) while enforcing server-side rules.
- **Scan-gated downloads**: files are inaccessible until policy checks pass (checksum + MIME sniff + rules).
- **Security controls**: RBAC/owner checks, short-lived presigns, audit logs, rate limits, and quotas.
- **Async scanning** with Redis/RQ (at-least-once) + idempotent worker retries.

## Architecture (ASCII)
```
[Client] --(auth/register/login)--> [FastAPI]
[Client] --(init)--> [FastAPI] --(presign PUT)--> [MinIO URL]
[Client] --(PUT object)--> [MinIO]
[Client] --(complete)--> [FastAPI] --(enqueue)--> [Redis/RQ]
[Worker] --(scan_file)--> [MinIO + Postgres]
[Client] --(download-url)--> [FastAPI] --(presign GET)--> [MinIO URL]
```

State machine (FileObject.state):
```
INITIATED -> SCANNING -> ACTIVE
INITIATED -> QUARANTINED/REJECTED (checksum/sniff fail)
SCANNING -> QUARANTINED (policy/size/type fail) -> (optional delete later)
```

## Threat model (mitigations)
- IDOR/object auth: owner-or-admin checks on file operations.
- MIME spoofing: sniff first bytes; mismatch => quarantine.
- Checksum integrity: SHA-256 verified on complete before scanning.
- Presigned URL TTL/replay: short-lived presigns (15m PUT, 5m GET).
- Audit logging: actions recorded with actor, IP, UA.
- Rate limiting + quotas: Redis fixed-window limits + per-user usage caps.

## Key metrics (verifiable) + quick verification

- **API surface:** 9 endpoints (auth, upload lifecycle, health, download gating)  
  Verify: `rg "@router\\.(get|post|put|delete)" app/api/routers -n`

- **Topology:** 5 docker-compose services (postgres, redis, minio, api, worker)  
  Verify: `docker compose config --services`

- **Lifecycle model:** 6-state file lifecycle (explicit state machine; only `ACTIVE` can download)  
  Verify: `rg "FileState" -n app`

- **Presign TTLs:** upload 15m, download 5m  
  Verify: `rg "expires_in=15 \\* 60|expires=300" -n app/api/routers/files.py`

- **Sniffing:** reads first 16KB (`bytes=0-16383`) to detect MIME mismatch without downloading full objects  
  Verify: `rg "bytes=0-16383" -n app`

- **Worker retries:** RQ max=3 with backoff `[10, 30, 60]` seconds (idempotent scan)  
  Verify: `rg "Retry\\(max=3" -n app`

- **Rate limits:** per-endpoint limits (register/login/init/complete/download-url)  
  Verify: `rg "rate_limit_(ip|user)\\(" -n app/api/routers`

- **Quotas:** 200 files / 2GB per user  
  Verify: `rg "MAX_(FILES|BYTES)" -n app`

- **Policy:** allowlist of 4 content types; max scan size 50MB  
  Verify: `rg "ALLOWED_CONTENT_TYPES|MAX_SIZE_BYTES" -n app`

- **Tests:** 9 integration tests covering happy-path + abuse/failure cases  
  Verify: `rg "^async def test_" -n tests/integration/test_upload_flow.py | wc -l`

Run the integration test suite:
```bash
make test


## Run locally
```
cp .env.example .env
make up
make migrate
```
API: http://localhost:8000

## Demo (exact commands)
Prereqs on your host:
- Docker running (docker compose)
- curl
- jq (install via `brew install jq`) — or see Python fallback below
- sha256: use `shasum -a 256` on macOS (or `sha256sum` if available)
- A file to upload (example uses `hello.txt`; create it with `echo "hello world" > hello.txt`)
- Host access to MinIO: presigned URLs are signed against `http://localhost:9000` (set in `.env.example` via `MINIO_PUBLIC_ENDPOINT`). If you change the host/port, update that env var before `make up`.

```bash
# 1) Register
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"me@example.com","password":"pass1234"}'

# 2) Login -> capture TOKEN
TOKEN=$(curl -s -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"me@example.com","password":"pass1234"}' | jq -r .access_token)

# 3) Init upload
CHECKSUM=$(shasum -a 256 hello.txt | awk '{print $1}')
INIT=$(curl -s -X POST http://localhost:8000/files/init \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"original_filename":"hello.txt","content_type":"text/plain","checksum_sha256":"'$CHECKSUM'"}')
UPLOAD_URL=$(echo "$INIT" | jq -r .upload_url)
FILE_ID=$(echo "$INIT" | jq -r .file_id)

# 4) PUT to presigned URL (no extra headers needed now)
curl -X PUT "$UPLOAD_URL" -H "Content-Type: text/plain" --data-binary @hello.txt

# 5) Complete
curl -X POST http://localhost:8000/files/$FILE_ID/complete -H "Authorization: Bearer $TOKEN"

# 6) Run scan (either worker running, or trigger once)
docker compose run --rm worker python -c "from app.services.scanner import scan_file; scan_file('$FILE_ID')"

# 7) Get download URL
curl -X POST http://localhost:8000/files/$FILE_ID/download-url -H "Authorization: Bearer $TOKEN"
```

Python-only fallback (no jq/sha256 tools):
```bash
CHECKSUM=$(python - <<'PY'
import hashlib
data = open("hello.txt","rb").read()
print(hashlib.sha256(data).hexdigest())
PY
)

TOKEN=$(curl -s -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"me@example.com","password":"pass1234"}' | python - <<'PY'
import sys, json
print(json.load(sys.stdin)["access_token"])
PY
)
```

## Testing
```
make test
```

## Make targets
- up / down / logs
- migrate / revision
- lint / format / test
- worker
- reset (down -v)

## Tradeoffs
- Presigned URLs reduce API bandwidth/load; trust but verify with checksum/sniff.
- Async scan via RQ: at-least-once; idempotent scan_file guards.
- Fixed-window rate limits: simple and explicit; can burst within window.
- No real AV engine: only MIME/size rules; extend with AV later.
- Quotas enforced in Postgres counters; no caching to keep correctness.
