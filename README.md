# Secure File Upload Service (Skeleton)

Scaffold for a FastAPI-based secure upload service with MinIO, Postgres, Redis, RQ, and basic CI.

- Start stack: `docker compose up --build`
- Run linters/tests locally: `make lint && make test`
- Alembic migrations: `make revision`, `make migrate`

Implementation is intentionally stubbed with TODOs.

## Quick demo (Phase 2/3 flow)
1) Register + login to get token (replace email/password):
   ```
   curl -X POST http://localhost:8000/auth/register -H "Content-Type: application/json" -d '{"email":"me@example.com","password":"pass1234"}'
   curl -X POST http://localhost:8000/auth/login -H "Content-Type: application/json" -d '{"email":"me@example.com","password":"pass1234"}'
   ```
   Save `access_token` as `$TOKEN`.

2) Init upload (returns presigned PUT):
   ```
   CHECKSUM=$(printf 'hello world' | sha256sum | awk '{print $1}')
   curl -X POST http://localhost:8000/files/init \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"original_filename":"hello.txt","content_type":"text/plain","checksum_sha256":"'$CHECKSUM'"}'
   ```
   Save `upload_url`, `headers_to_include`, and `file_id`.

3) Upload to MinIO using presigned URL (include returned headers):
   ```
   curl -X PUT "$upload_url" -H "Content-Type: text/plain" \
     -H "x-amz-meta-checksum-sha256: $CHECKSUM" \
     -H "x-amz-meta-owner-id: <user-id>" \
     --data-binary @"./hello.txt"
   ```

4) Complete upload (checksum + sniff):
   ```
   curl -X POST http://localhost:8000/files/$file_id/complete \
     -H "Authorization: Bearer $TOKEN"
   ```
