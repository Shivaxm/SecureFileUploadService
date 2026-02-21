# Deployment Runbook (Local -> Public Demo)

This runbook keeps the current API + worker flow unchanged:
- Presigned upload/download URLs
- Redis RQ scanning worker
- Postgres metadata/state

## What the repo already uses

- API start command: `uvicorn app.main:app --host 0.0.0.0 --port 8000`
- Worker start command: `python -m app.workers.rq_worker`
- Migrations: Alembic (`alembic upgrade head`)
- Storage client: boto3 S3-compatible client (`app/services/storage.py`)

---

## Phase 1: Local production-like Docker Compose

### Services
- `api`, `worker`, `redis`, `postgres`, `minio`

### 1) Start stack
```bash
cp .env.example .env
docker compose up -d --build
```

### 2) Initialize bucket in MinIO
This uses existing storage code to ensure bucket exists:
```bash
docker compose run --rm -e PYTHONPATH=/app api \
  python -c "from app.services.storage import StorageClient; StorageClient(); print('bucket ready')"
```

### 3) Run DB migrations
```bash
docker compose run --rm -e PYTHONPATH=/app api alembic upgrade head
```

### 4) Validate end-to-end flow
1. Open `http://localhost:8000/` and click **Start Demo** (or use auth flow).
2. Upload a file from `/upload`.
3. Confirm status transitions from pending to clean/quarantined in `/files`.
4. Verify download is enabled only when clean.

CLI smoke path (authenticated users):
```bash
TOKEN=$(curl -s -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"me@example.com","password":"pass1234"}' | jq -r .access_token)
```

---

## Phase 2: Public deployment (no public MinIO)

Recommended simple stack:
- Render Web Service: `api`
- Render Background Worker: `worker`
- Managed Postgres (Render or external)
- Managed Redis (Render or Upstash)
- AWS S3 bucket (or any managed S3-compatible provider)

### Required environment variables

Core:
- `DATABASE_URL=postgresql+psycopg2://...`
- `REDIS_URL=redis://...`
- `JWT_SECRET=<strong-random>`
- `JWT_ALGORITHM=HS256`
- `JWT_EXPIRES_SECONDS=3600`
- `ENV=prod`
- `APP_DEBUG=false`

Storage (managed S3):
- `S3_ENDPOINT=https://s3.us-east-1.amazonaws.com` (AWS)
- `S3_PUBLIC_ENDPOINT=https://s3.us-east-1.amazonaws.com`
- `S3_ACCESS_KEY_ID=AKIA...`
- `S3_SECRET_ACCESS_KEY=...`
- `S3_BUCKET=secure-upload-prod`
- `S3_REGION=us-east-1`
- `STORAGE_AUTO_CREATE_BUCKET=false`

TTL knobs:
- `UPLOAD_PRESIGN_TTL_SECONDS=900`
- `DOWNLOAD_PRESIGN_TTL_SECONDS=300`

### Render deployment steps

1. Push repo to GitHub.
2. Create managed Postgres and Redis in Render.
3. Create S3 bucket and IAM user with least privilege:
   - `s3:PutObject`, `s3:GetObject`, `s3:HeadObject`, `s3:ListBucket` on your bucket.
4. Create Render **Web Service**:
   - Build: `pip install -r requirements.txt`
   - Start: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
   - Set env vars listed above.
5. Create Render **Background Worker**:
   - Build: `pip install -r requirements.txt`
   - Start: `python -m app.workers.rq_worker`
   - Reuse same env vars.
6. Run migrations once (Render shell/job):
   - `alembic upgrade head`
7. Point recruiter URL to the web service (HTTPS).

---

## Public demo hardening checklist

- [ ] Keep demo max upload size enforced (10MB currently in demo path).
- [ ] Keep MIME allowlist strict (`text/plain`, `application/pdf`, `image/png`, `image/jpeg`).
- [ ] Rate limit `/demo/start`, `/files/init`, `/files/complete`, `/files/{id}/download-url`.
- [ ] Do not expose MinIO publicly in production.
- [ ] Use strong `JWT_SECRET` and `ENV=prod`.
- [ ] Set `STORAGE_AUTO_CREATE_BUCKET=false` in production.
- [ ] Add TTL cleanup for demo files (cron/job):
  - Query old demo rows by `created_at`.
  - Delete object from S3.
  - Delete DB rows/audit as needed.
