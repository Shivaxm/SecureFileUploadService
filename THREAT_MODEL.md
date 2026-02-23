# ScanGate Threat Model (STRIDE)

## Scope

- Repo analyzed: `Shivaxm/ScanGate` (FastAPI app, Redis/RQ worker, PostgreSQL, S3-compatible object storage).
- Primary code paths reviewed:
  - `app/api/routers/auth.py`
  - `app/api/routers/demo.py`
  - `app/api/routers/files.py`
  - `app/api/deps.py`
  - `app/core/security.py`
  - `app/core/rate_limit.py`
  - `app/services/storage.py`
  - `app/services/scanner.py`
  - `app/services/file_type_policy.py`
  - `app/services/quota.py`
  - `app/services/audit.py`
  - `app/db/models.py`
  - `app/core/config.py`
  - `app/workers/rq_worker.py`

## System Overview

ScanGate is a secure file-ingest service where clients request presigned upload URLs from FastAPI, upload bytes directly to S3-compatible storage, and then finalize uploads so asynchronous scanning can determine whether downloads are allowed. Metadata, ownership, and state transitions are stored in PostgreSQL; scan jobs are queued in Redis/RQ and executed by a worker. The API enforces per-endpoint rate limits, ownership checks, and state-gated downloads, while demo mode uses an HMAC-signed cookie and isolated `demo_id` scoping.

### Data Flow Diagram (Mermaid)

```mermaid
flowchart LR
    C[Client Browser / API Consumer]
    API[FastAPI API]
    S3[S3-Compatible Object Storage]
    PG[(PostgreSQL)]
    R[(Redis)]
    W[RQ Worker]

    C -->|POST /auth/*, /demo/start, /files/*| API
    API -->|Insert/Query metadata, audit, quotas| PG
    API -->|Issue presigned PUT/GET| C
    C -->|PUT object bytes via presigned URL| S3
    API -->|enqueue_scan(file_id)| R
    W -->|poll jobs| R
    W -->|HEAD/GET object, range reads| S3
    W -->|Update state/quota/audit| PG
    API -->|GET/POST download URL (ACTIVE only)| S3
```

### Key Assets

- Authentication material:
  - JWT bearer tokens from `/auth/login`.
  - Demo cookie token (`demo`) from `/demo/start`.
  - `jwt_secret` in runtime config.
- File data and metadata:
  - Object bytes in S3.
  - Metadata (`file_objects`) and audit entries (`audit_events`) in PostgreSQL.
- Authorization state:
  - `owner_id`, `demo_id`, `role`, and `FileObjectState`.
- Infrastructure credentials:
  - S3 access key/secret, Redis URL, DB URL.

### Trust Boundaries

1. Client -> API boundary (untrusted internet input into FastAPI routes).
2. API -> S3 presign boundary (API signs capability URLs later used outside API path).
3. Client -> S3 direct upload boundary (bytes bypass API controls once URL is issued).
4. API -> PostgreSQL boundary (authorization and state decisions depend on DB integrity).
5. API -> Redis boundary (rate limiting and queueing trust Redis availability/integrity).
6. Worker -> S3 boundary (scanner trusts object storage reads for validation decisions).
7. Worker -> PostgreSQL boundary (worker can transition file states and quota counters).
8. Runtime secrets boundary (ENV configuration for JWT/S3/Redis/DB controls system trust).

## STRIDE Analysis

## Spoofing

### S-01 Forged JWT enables account impersonation

- Threat: An attacker who obtains `jwt_secret` can forge bearer tokens with arbitrary `sub` and potentially admin role context.
- Component: `app/core/security.py:create_access_token`, `decode_token`; auth-protected routes using `deps.get_current_user`.
- Risk: High - JWT is the primary identity primitive for authenticated APIs.
- Mitigation (implemented): JWT signature + expiry verification via `python-jose` (`decode_token`), and user existence check in DB (`deps.get_current_user`).
- Mitigation (recommended): Rotate signing keys; add key IDs and dual-key validation window; separate signing keys per environment and per token class; introduce token revocation list for high-risk events.

### S-02 Replay of stolen bearer token

- Threat: A valid bearer token can be replayed from another client until expiry because no device binding or session revocation exists.
- Component: `Authorization: Bearer` handling in `deps.get_current_user`; `/files/*` and other protected endpoints.
- Risk: Medium - impact is bounded by token TTL but still grants full user actions during that period.
- Mitigation (implemented): Token expiration (`jwt_expires_seconds` in `app/core/config.py`) and role/ownership checks in route handlers.
- Mitigation (recommended): Add jti + server-side denylist on logout/password reset; shorten access token TTL; optionally add refresh-token rotation and anomaly detection on IP/UA drift.

### S-03 Demo token spoofing / session takeover attempt

- Threat: An attacker attempts to forge or tamper with the `demo` cookie to access another demo namespace.
- Component: `app/api/deps.py:create_demo_token`, `verify_demo_token`; `/demo/start`; demo-scoped branches in `/files/*`.
- Risk: Medium - demo mode has reduced privileges but still writes to shared infrastructure.
- Mitigation (implemented): HMAC-SHA256 signature with constant-time compare (`hmac.compare_digest`), expiry bound, `HttpOnly` cookie, `SameSite=Lax`, and `secure` in prod.
- Mitigation (recommended): Use a dedicated secret for demo cookies (not `jwt_secret`), include explicit audience/version fields, and add server-side nonce store for optional revocation.

### S-04 Unauthorized enqueue actor spoofing worker producer

- Threat: If Redis is reachable from untrusted networks, an attacker can inject jobs into the scan queue and impersonate trusted producer behavior.
- Component: `app/services/scanner.py:get_queue/enqueue_scan`, `app/workers/rq_worker.py`.
- Risk: High - queue manipulation can alter processing cadence and potentially force state transitions through scanner paths.
- Mitigation (implemented): None in application layer beyond assuming trusted Redis URL.
- Mitigation (recommended): Place Redis on private network only, require AUTH/TLS, enforce network ACLs, and add signed job payload validation before processing.

## Tampering

### T-01 File bytes modified after init and before complete

- Threat: Uploaded object content differs from metadata declared during `/files/init`.
- Component: `/files/init`, `/files/{id}/complete`; `file_obj.checksum_sha256`.
- Risk: High - tampered bytes could bypass naive extension checks.
- Mitigation (implemented): SHA-256 recomputation over object bytes in `complete_upload`; mismatch sets `REJECTED` and audit event `UPLOAD_REJECTED`.
- Mitigation (recommended): Add optional object-lock/versioning to detect overwrites and preserve forensic lineage.

### T-02 MIME/extension mismatch tampering

- Threat: Client submits safe-looking extension/content-type while uploading different content.
- Component: `validate_upload_metadata` in `app/services/file_type_policy.py`; sniffing in complete/scan flows.
- Risk: Medium - mitigated by fail-closed validation but dependent on sniff capability and policy quality.
- Mitigation (implemented): Extension allowlist, declared MIME checks, sniffed MIME checks, magic-byte checks, office ZIP structure checks; failures lead to `QUARANTINED`.
- Mitigation (recommended): Add AV/malware engine stage (ClamAV/YARA) and maintain policy map with explicit review cadence.

### T-03 Response header tampering via malicious filename

- Threat: Filename with CR/LF or path control characters causes header injection in presigned download responses.
- Component: `StorageClient.generate_presigned_get_download`.
- Risk: Medium - could enable response splitting or unsafe filenames in client context.
- Mitigation (implemented): Sanitization strips CR/LF, path separators, non-printables, and uses RFC5987 `filename*` encoding.
- Mitigation (recommended): Add stricter filename normalization policy and enforce a canonical server-generated download name option.

### T-04 Audit trail tampering by privileged DB actor

- Threat: Insider or compromised DB credentials modify or delete audit rows.
- Component: `audit_events` table and `log_event`.
- Risk: Medium - affects forensics and non-repudiation guarantees.
- Mitigation (implemented): Events are generated in multiple code paths (init/complete/scan/download), increasing coverage.
- Mitigation (recommended): Forward append-only audit stream to immutable store (e.g., object storage with retention or SIEM), and add hash-chain/signature for integrity.

## Repudiation

### R-01 Demo actor attribution is weak

- Threat: Demo actions are difficult to tie to a real human identity; `actor_user_id` can be null for unauthenticated demo paths.
- Component: `log_event` callsites in `/files/*` and scanner.
- Risk: Medium - acceptable for demo UX but weak for abuse investigations.
- Mitigation (implemented): Logs include IP and user-agent when request context exists.
- Mitigation (recommended): Log `demo_id`, request ID, and optional browser fingerprint hash for stronger demo-session traceability.

### R-02 No cryptographic integrity on audit records

- Threat: A party can deny actions by claiming logs were altered post-facto.
- Component: `app/services/audit.py`, `audit_events` persistence model.
- Risk: Medium - standard DB logs are mutable by admins.
- Mitigation (implemented): Structured event schema with timestamps and action labels.
- Mitigation (recommended): Emit signed audit envelopes and archive off-host; enable WORM retention policy for security logs.

### R-03 Limited request correlation across API and worker

- Threat: A user disputes a state transition and there is no guaranteed end-to-end correlation ID from API request to worker job.
- Component: API request handlers vs `scan_file` worker path.
- Risk: Low/Medium - impairs incident triage rather than directly enabling compromise.
- Mitigation (implemented): Events include `file_id`, action names (`UPLOAD_ENQUEUED`, `SCAN_PASS`, etc.), and timestamps.
- Mitigation (recommended): Add trace ID propagation from enqueue to worker and include queue job ID in audit metadata.

### R-04 Authentication events are not fully auditable

- Threat: Register/login attempts are not recorded in `audit_events`, enabling plausible denial of auth abuse attempts.
- Component: `app/api/routers/auth.py` lacks `log_event` usage.
- Risk: Medium - reduces ability to investigate credential stuffing or account misuse.
- Mitigation (implemented): Rate limits on auth endpoints reduce brute-force throughput.
- Mitigation (recommended): Add auth audit events (success/failure, email hash, ip, ua) with privacy-preserving redaction.

## Information Disclosure

### I-01 Metadata oversharing in file listing/detail responses

- Threat: Authenticated users receive bucket name, object key, and checksum fields in API responses; leaked client logs/screenshots expose internals.
- Component: `FileDetail` response model in `app/api/routers/files.py`.
- Risk: Medium - does not expose bytes directly but leaks storage topology and object identifiers.
- Mitigation (implemented): Ownership/admin checks block cross-user access.
- Mitigation (recommended): Return minimal metadata to UI clients; gate operational fields behind admin/debug scopes.

### I-02 Presigned URL leakage reveals temporary object access

- Threat: If a presigned URL is leaked through browser history, logs, referrers, or screenshots, any holder can access object within TTL.
- Component: `/files/init` and `/files/{id}/download-url` responses.
- Risk: High - URL itself is a capability token.
- Mitigation (implemented): Short TTLs (`upload_presign_ttl_seconds=900`, `download_presign_ttl_seconds=300`) and state/ownership checks before issuing download URL.
- Mitigation (recommended): Use stricter TTL for demo mode, add one-time-use semantics where feasible, and avoid logging full URLs in frontend/monitoring.

### I-03 Object key includes original filename

- Threat: `object_key` is `uuid + "_" + original_filename`; sensitive names can leak through telemetry or S3 access logs.
- Component: `init_upload` object key generation.
- Risk: Medium - metadata privacy risk even when bytes are protected.
- Mitigation (implemented): UUID prefix reduces guessability of keys.
- Mitigation (recommended): Use opaque random keys only; store original filename only in DB and response metadata.

### I-04 Health/readiness endpoints provide reconnaissance signal

- Threat: Unauthenticated `/health`, `/health/live`, `/health/ready` allow service fingerprinting and uptime probing.
- Component: `app/api/routers/health.py`.
- Risk: Low - current payload is minimal, but endpoint existence aids recon.
- Mitigation (implemented): `/ready` currently returns coarse `degraded` message without deep internals.
- Mitigation (recommended): Restrict readiness endpoint to internal network and add auth for detailed diagnostics.

## Denial of Service

### D-01 CPU/IO amplification in `/files/{id}/complete`

- Threat: Complete step computes full SHA-256 over object and performs sniff reads; repeated uploads can force expensive storage reads.
- Component: `complete_upload` hash loop + range read.
- Risk: High - synchronous expensive work happens on API request path.
- Mitigation (implemented): Per-endpoint rate limits (`files_complete` 20/60) and demo size cap 10 MB.
- Mitigation (recommended): Offload checksum verification to async worker, add request-level timeout/queue, and apply cost-aware per-user budgets.

### D-02 Queue backlog can delay security gating

- Threat: Worker saturation delays scan completion, causing long pending states and operational degradation.
- Component: Redis queue `scan`; single worker process in `app/workers/rq_worker.py`.
- Risk: Medium - availability/SLA impact; could be abused by flood traffic.
- Mitigation (implemented): Retry policy with backoff (`Retry(max=3, interval=[10,30,60])`).
- Mitigation (recommended): Add queue depth alarms, autoscale workers, and enforce global ingest backpressure when queue lag grows.

### D-03 Redis availability is a hard dependency for rate limits and queueing

- Threat: Redis outage can break auth/file flows (rate limiter exceptions, enqueue failures), reducing service availability.
- Component: `app/core/rate_limit.py`, `app/services/scanner.py`.
- Risk: High - multiple critical paths require Redis.
- Mitigation (implemented): None in app logic beyond middleware wrapper; no local fallback.
- Mitigation (recommended): Add graceful-degradation policy (fail-safe mode per endpoint), Redis health checks in readiness, and circuit-breaker behavior.

### D-04 Demo data accumulation (no TTL cleanup job)

- Threat: Public demo users can fill storage/metadata over time; TODO exists but cleanup is not implemented.
- Component: Demo flow in `/demo/start` and `/files/*`; TODO in `app/api/routers/demo.py`.
- Risk: Medium/High - persistent growth can raise costs and impact performance.
- Mitigation (implemented): Demo upload size cap and route-level rate limits.
- Mitigation (recommended): Implement scheduled TTL deletion for demo rows + objects and enforce per-demo file count quota.

## Elevation of Privilege

### E-01 Compromised JWT secret enables privilege escalation to admin

- Threat: An attacker with signing key can mint token for any `sub`; if coupled with DB role modification or chosen admin ID, can access admin-only paths.
- Component: `decode_token` trust model + role checks in routes.
- Risk: High - trust root compromise.
- Mitigation (implemented): Role checks exist (`user.role == admin`) on protected operations.
- Mitigation (recommended): Isolate secrets in managed secret store, rotate regularly, and add issuer/audience claims with stricter validation.

### E-02 Admin bypass of clean-state download gate can be abused if admin token stolen

- Threat: Current logic allows admin to bypass `ACTIVE` requirement and get download URL for non-clean files.
- Component: `/files/{id}/download-url` condition in `download_url`.
- Risk: Medium/High - intended for ops, but stolen admin token grants sensitive bypass.
- Mitigation (implemented): Requires valid authenticated admin context.
- Mitigation (recommended): Add explicit justification/audit reason for override, optional dual-control for non-ACTIVE downloads, and alerting on override events.

### E-03 Redis write access can influence processing privileges

- Threat: Attacker with Redis write can enqueue arbitrary `file_id` jobs to trigger worker actions under trusted service identity.
- Component: RQ queue producer/consumer trust.
- Risk: High - indirect privilege escalation into backend processing plane.
- Mitigation (implemented): Worker checks file existence and current state (`SCANNING`) before transition.
- Mitigation (recommended): Authenticate queue producers, restrict Redis network, and sign/verify job payload metadata.

### E-04 Anonymous user gains scoped write capability via demo start

- Threat: Unauthenticated internet clients can call `/demo/start` and obtain upload/list/download capabilities in demo namespace.
- Component: `demo.py` + optional-auth branches in `/files/*`.
- Risk: Medium - intentional for UX, but still an elevation from unauthenticated to stateful capability holder.
- Mitigation (implemented): Demo isolation via `demo_id`, stricter demo size limit, and rate limits.
- Mitigation (recommended): Add stronger abuse controls (IP reputation, tighter per-demo quotas, captcha on repeated demo starts).

## Attack Surface Summary

| Surface | Input / Accepted Data | Auth Model | Exposure |
|---|---|---|---|
| `POST /auth/register` | JSON `{email,password}` | None | Public internet, rate-limited |
| `POST /auth/login` | JSON `{email,password}` | None | Public internet, rate-limited |
| `POST /demo/start` | No body; sets `demo` cookie | None | Public internet, rate-limited |
| `POST /files/init` | JSON metadata + optional bearer/demo cookie | Bearer OR demo cookie | Public internet, presign issuance |
| `POST /files/{id}/complete` | Path id, auth context | Bearer OR demo cookie | Public internet, expensive validation |
| `GET /files?format=json` | Query params | Bearer OR demo cookie | Public internet, metadata listing |
| `GET /files/{id}` | Path id | Bearer only | Public internet |
| `POST /files/{id}/download-url` | Path id | Bearer OR demo cookie | Public internet, capability issuance |
| `GET /health` | None | None | Public internet |
| `GET /health/live` | None | None | Public internet |
| `GET /health/ready` | None | None | Public internet |
| `GET /`, `/upload`, `/architecture` | Browser navigation | None | Public internet (UI) |
| Presigned `PUT` URL (S3) | Raw file bytes + signed query params | Capability URL | Public internet, bypasses API |
| Presigned `GET` URL (S3) | Signed query params | Capability URL | Public internet, short TTL |
| Redis (`redis_url`) | Rate-limit counters, RQ jobs | Infrastructure credential | Should be private network only |
| PostgreSQL (`database_url`) | User/file/audit/quota rows | Infrastructure credential | Should be private network only |

## Current Security Controls (Observed)

- Auth:
  - JWT-based bearer auth with signature+exp verification (`app/core/security.py`).
  - Optional auth path for demo mode (`get_current_user_optional` + `get_demo_id`).
- Authorization:
  - Owner/admin checks on file operations in `app/api/routers/files.py`.
  - Demo scoping via `demo_id` with 404 on cross-demo access.
- File safety:
  - SHA-256 checksum verification on complete.
  - MIME sniff + extension policy + magic prefix validation.
  - Office OpenXML internal ZIP entry checks in scanner.
  - Download gated on `FileObjectState.ACTIVE` for non-admins.
- Abuse controls:
  - Redis-backed per-route rate limits.
  - Quotas (max files and bytes) enforced in `QuotaService`.
  - Demo upload size cap (10 MB) at init/complete.
- Observability:
  - Structured audit events with action, actor, IP, UA, metadata.

## Residual Risks

1. No malware engine beyond MIME/magic/policy checks:
   - Advanced payloads can evade file-type validation while still being malicious.
2. Sensitive capability URLs can still leak at client edge:
   - Presigned URLs are bearer-by-possession during TTL.
3. Redis and worker trust model is implicit:
   - Queue integrity depends on network isolation rather than signed job provenance.
4. Demo-mode cleanup is not implemented:
   - Long-lived demo artifacts can create storage/cost and abuse pressure.
5. Audit logs are not immutable:
   - Forensics quality depends on DB trust and operational controls outside app code.

## Prioritized Recommendations

1. Add malware scanning stage (ClamAV/YARA) in worker pipeline before `ACTIVE`.
2. Implement demo TTL cleanup and per-demo object count caps.
3. Isolate and harden Redis (private network, auth, TLS), plus queue-depth alerts.
4. Introduce immutable/forwarded audit logging with correlation IDs.
5. Rotate and split secrets (JWT vs demo cookie signing key; key IDs and rotation plan).

## Assumptions and Non-Goals

- Assumes S3 bucket policies and IAM are correctly configured out-of-band.
- Assumes PostgreSQL and Redis are not publicly exposed.
- This model focuses on application and service integration threats, not host/kernel hardening.
- Frontend/browser hardening (CSP, clickjacking, etc.) is out of scope except where it impacts token/URL leakage.
