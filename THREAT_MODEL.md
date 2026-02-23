# ScanGate Threat Model (STRIDE)

This document explains what can go wrong in ScanGate, what ScanGate already does to reduce risk, and what would be the next hardening steps. It is written to be readable without security background, while still pointing to the real code.

## What ScanGate is

ScanGate is a secure file upload service:

1. The API creates a database record and returns a short-lived upload link (a presigned URL).
2. The browser uploads bytes directly to S3 using that link (the API never sees the file bytes).
3. The client calls “complete”, the API verifies integrity (SHA-256) and basic file-type rules, then enqueues a scan job.
4. A worker scans the file and updates the state in Postgres.
5. Downloads are blocked unless the state is `ACTIVE` (clean).

Relevant code:

- Upload lifecycle: `app/api/routers/files.py`
- Storage/presign: `app/services/storage.py`
- Scan worker: `app/services/scanner.py`, `app/workers/rq_worker.py`
- File type rules: `app/services/file_type_policy.py`
- Auth + demo: `app/api/routers/auth.py`, `app/api/routers/demo.py`, `app/api/deps.py`
- Rate limits: `app/core/rate_limit.py`
- Audit logging: `app/services/audit.py`

## Data flow (diagram)

This Mermaid diagram is intentionally simple to render reliably on GitHub:

```mermaid
flowchart LR
  client[Client (browser)]
  api[FastAPI API]
  s3[S3 object storage]
  pg[(Postgres)]
  redis[(Redis)]
  worker[RQ worker]

  client -->|Auth, demo start, init/complete/list/download-url| api
  api -->|Read/write metadata + audit| pg
  api -->|Issue presigned upload/download links| client
  client -->|PUT file bytes (presigned)| s3
  api -->|Enqueue scan job| redis
  redis -->|Job| worker
  worker -->|Read file bytes (HEAD/GET)| s3
  worker -->|Update file state + quota + audit| pg
```

## Where trust changes (trust boundaries)

These are the places where data crosses between systems and we should assume it may be unsafe:

1. Internet clients calling the API (all request bodies/headers are untrusted).
2. Presigned links leaving the API (whoever has the link can use it until it expires).
3. Direct upload to S3 (bytes bypass the API once a presigned link exists).
4. API and worker reading/writing Postgres (state and ownership rules depend on DB integrity).
5. API using Redis for rate limits and worker queue (Redis availability and access controls matter).

## STRIDE threats (plain language)

Each item lists:

- Threat: what could happen
- Where: the part of the system it affects
- Risk: High/Medium/Low (why)
- Already in ScanGate: what we do today
- Recommended: what to add next

## Spoofing (pretending to be someone else)

### S-1 Stolen/forged login token used as another user

- Threat: If an attacker gets the JWT signing secret, they can generate tokens and act as any user.
- Where: JWT creation/validation in `app/core/security.py` and auth dependency in `app/api/deps.py`.
- Risk: High, because JWT is the main identity check for authenticated APIs.
- Already in ScanGate: tokens expire (`jwt_expires_seconds` in `app/core/config.py`) and we verify signature+exp in `decode_token`.
- Recommended: rotate secrets; support key IDs (kid) for rotation; consider token revocation for password reset/logout.

### S-2 Demo cookie is forged to access another demo session

- Threat: An attacker tries to forge or modify the `demo` cookie to read or download another person’s demo uploads.
- Where: demo token signing/verification in `app/api/deps.py`, demo scoping in `app/api/routers/files.py`.
- Risk: Medium, because demo access is limited but still touches shared infrastructure.
- Already in ScanGate: HMAC signature + expiry; cookie is `HttpOnly` and `SameSite=Lax`; file access checks include `demo_id` and return 404 for mismatches.
- Recommended: use a separate secret for demo signing (not `jwt_secret`); optionally store demo sessions server-side for revocation.

### S-3 Fake scan jobs injected into Redis

- Threat: If Redis is reachable, an attacker can enqueue scan jobs and try to force worker activity.
- Where: RQ queue in `app/services/scanner.py` and worker in `app/workers/rq_worker.py`.
- Risk: High, because this attacks the backend processing plane.
- Already in ScanGate: worker refuses to transition files unless the DB state is `SCANNING` (`scan_file` checks state).
- Recommended: keep Redis private; require auth/TLS; restrict network access; add monitoring on queue depth and unknown job sources.

## Tampering (changing data)

### T-1 File bytes changed after init

- Threat: A client uploads different bytes than what was described in `/files/init`.
- Where: `/files/{id}/complete` in `app/api/routers/files.py`.
- Risk: High, because file bytes are untrusted and could be malicious.
- Already in ScanGate: we compute SHA-256 over the uploaded object and reject on mismatch (state becomes `REJECTED`).
- Recommended: consider S3 object versioning (so overwrites are detectable) and store a content-length expectation from init.

### T-2 “Looks like a PDF” but is actually something else

- Threat: A client claims a safe type by filename or content-type but uploads a different format.
- Where: file policy in `app/services/file_type_policy.py`, sniffing in complete/scan flows.
- Risk: Medium, because basic checks can be bypassed by more advanced file tricks.
- Already in ScanGate: allowlist by extension; declared content-type must match policy; sniffed MIME must match; magic-byte checks; Office docs must look like ZIPs and pass deeper worker checks.
- Recommended: add a real malware scanner stage in the worker (ClamAV/YARA) before marking `ACTIVE`.

### T-3 Malicious filename used to mess with download headers

- Threat: Filename contains characters that can break headers or paths.
- Where: `StorageClient.generate_presigned_get_download` in `app/services/storage.py`.
- Risk: Medium.
- Already in ScanGate: strips CR/LF, removes path separators, replaces unsafe characters, and uses safe encoding for `Content-Disposition`.
- Recommended: optionally ignore client filename entirely for demo mode and generate a safe server filename.

## Repudiation (denying actions later)

### R-1 “I didn’t upload/download that”

- Threat: A user disputes actions if there is no strong record.
- Where: audit events in `app/services/audit.py` and call sites in `app/api/routers/files.py` and `app/services/scanner.py`.
- Risk: Medium.
- Already in ScanGate: audit rows include action, actor id, file id, IP, user-agent, and timestamps.
- Recommended: include a request ID and the queue job ID for end-to-end tracing; ship audit logs to an external log store.

### R-2 Demo users are hard to attribute

- Threat: Demo mode is anonymous by design, so abuse investigations are harder.
- Where: `/demo/start` in `app/api/routers/demo.py` and demo-scoped branches in `app/api/routers/files.py`.
- Risk: Medium.
- Already in ScanGate: per-IP rate limits on `/demo/start` and per-user rate limits on file routes; audit includes IP/UA.
- Recommended: add per-demo quotas (file count/day) and TTL cleanup; optionally add a lightweight “abuse guard” (captcha after repeated starts).

## Information disclosure (data leaking)

### I-1 Presigned URLs leak like temporary keys

- Threat: If a presigned URL is copied from logs/screenshots/history, anyone can use it until it expires.
- Where: `/files/init` and `/files/{id}/download-url` responses; presign TTLs in `app/core/config.py`.
- Risk: High.
- Already in ScanGate: short TTLs (15 minutes upload, 5 minutes download by default) and download is only issued after state/ownership checks.
- Recommended: avoid logging URLs in frontend; for demo, consider shorter TTLs; consider one-time download URLs if you can enforce it.

### I-2 File metadata reveals internal storage info

- Threat: Responses include bucket/object keys/checksums which can leak internal details if exposed.
- Where: `FileDetail` response model in `app/api/routers/files.py`.
- Risk: Medium.
- Already in ScanGate: ownership checks prevent cross-user reads.
- Recommended: hide `bucket` and `object_key` from non-admin responses (UI does not need them).

## Denial of service (making it slow or unavailable)

### D-1 “Complete” endpoint forces expensive reads

- Threat: `/files/{id}/complete` reads the object to compute SHA-256, which is expensive if abused.
- Where: `complete_upload` in `app/api/routers/files.py`.
- Risk: High, because it is synchronous and can consume API resources.
- Already in ScanGate: per-endpoint rate limits in `app/api/routers/files.py` and demo size caps (10 MB).
- Recommended: move full checksum verification into the worker to protect the API; add timeouts and stricter per-user budgets.

### D-2 Demo content grows without cleanup

- Threat: Demo users accumulate objects and DB rows over time.
- Where: demo flow; cleanup TODO in `app/api/routers/demo.py`.
- Risk: Medium/High (cost and reliability).
- Already in ScanGate: demo size cap and rate limits.
- Recommended: scheduled TTL deletion for demo files (DB + S3) and per-demo file count quota.

## Elevation of privilege (getting more power than intended)

### E-1 Admin token stolen allows bypass of clean-state download gate

- Threat: Admin can get download URLs even when a file is not `ACTIVE` (clean), so a stolen admin token is higher impact.
- Where: `/files/{id}/download-url` in `app/api/routers/files.py` (admin bypass logic).
- Risk: Medium/High.
- Already in ScanGate: explicit admin role checks.
- Recommended: log admin override reason; alert on overrides; consider removing bypass for public demo deployments.

## Attack surface (what’s reachable from the internet)

| Endpoint | What it accepts | Who can call it |
|---|---|---|
| `POST /auth/register` | email + password | Anyone (rate-limited) |
| `POST /auth/login` | email + password | Anyone (rate-limited) |
| `POST /demo/start` | no body; sets cookie | Anyone (rate-limited) |
| `POST /files/init` | filename, content-type, SHA-256, size | Logged-in users or demo sessions |
| `POST /files/{id}/complete` | file id | Logged-in users or demo sessions |
| `GET /files?format=json` | none | Logged-in users or demo sessions |
| `POST /files/{id}/download-url` | file id | Logged-in users or demo sessions |
| `GET /health*` | none | Anyone |

Presigned S3 URLs:

- Upload `PUT` URL: anyone who has the URL can upload bytes until it expires.
- Download `GET` URL: anyone who has the URL can download bytes until it expires.

## What ScanGate already does (quick list)

- Only allows specific file types (extension + content-type + sniff + magic bytes): `app/services/file_type_policy.py`.
- Verifies SHA-256 on complete (rejects mismatches): `app/api/routers/files.py`.
- Blocks downloads unless state is `ACTIVE` (clean) for normal users: `app/api/routers/files.py`.
- Runs async scanning and office ZIP structure checks before `ACTIVE`: `app/services/scanner.py`.
- Enforces ownership and demo isolation (prevents IDOR): `app/api/routers/files.py`.
- Rate limits by IP/user in Redis: `app/core/rate_limit.py`.
- Writes audit events with IP/UA metadata: `app/services/audit.py`.

## Remaining risks (honest)

1. No “real” malware scanner yet; MIME/magic checks are not enough against advanced threats.
2. Presigned URLs can leak; they act like temporary keys.
3. If Redis is exposed, attackers can spam jobs and counters.
4. Demo cleanup is not implemented yet (storage growth over time).
5. Audit logs live in the same database and are not tamper-proof.

## Next hardening steps (most impact, least change)

1. Add malware scanning in the worker before marking `ACTIVE`.
2. Add scheduled demo cleanup (delete old demo rows + objects).
3. Hide storage internals from normal API responses (do not return bucket/object key to UI clients).
4. Lock down Redis and Postgres to private networking only and add readiness checks.
5. Rotate secrets and split demo signing secret from JWT signing secret.
