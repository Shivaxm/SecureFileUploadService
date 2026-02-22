# Load Test Results — ScanGate

**Environment:** Render (single web instance + worker), production URL `https://securefileuploadservice.onrender.com`  
**Date:** 2026-02-22 10:46:28 EST  
**Tool:** k6 v1.6.1  
**Warm-up:** 5x `GET /health` with 3s gaps before scenarios

## Scenario 1: Baseline (Health + Page Load)
- **Virtual Users:** 10 concurrent
- **Duration:** 20s
- **Total Requests:** 368
- **Throughput:** 18.40 req/s
- **Latency (p50):** 46.82ms
- **Latency (p95):** 73.41ms
- **Error Rate:** 0.00%

## Scenario 2: Upload Pipeline (init → upload → complete → scan → download)
- **Virtual Users:** 5 concurrent
- **Duration:** 30s
- **Total Upload Cycles Completed:** 20
- **Upload Init (p50 / p95):** 634.52ms / 2671.76ms
- **S3 Upload (p50 / p95):** 51.76ms / 76.18ms
- **Complete + Scan (p50 / p95):** 2.79s / 4.29s (`complete_to_terminal_latency_ms`)
- **Avg Scan Pipeline Latency (init → clean):** 3.98s (`scan_pipeline_latency_ms` avg)
- **Download URL Generation (p50 / p95):** 156.10ms / 305.13ms
- **Error Rate:** 0.00%

## Scenario 3: Concurrent File Listing
- **Virtual Users:** 8 concurrent
- **Duration:** 20s
- **Total Requests:** 155
- **Throughput:** 7.75 req/s
- **Latency (p50):** 55.34ms
- **Latency (p95):** 154.92ms
- **Error Rate:** 0.65% (1 failed request out of 155)

## Key Findings
- End-to-end upload pipeline is stable under concurrent usage: 20/20 upload cycles reached terminal states and were download-eligible when clean.
- Presigned upload path keeps object transfer fast (`PUT` p95 76.18ms), while API remains responsive on page and list endpoints.
- Async scan path is the dominant latency component (`complete_to_terminal` p95 4.29s), which is expected by design.
- Rate limiting is active and observable; after adding retry/backoff and wider scenario spacing, scenario-level error rates remained near zero.

## Architecture Impact on Performance
- Presigned uploads bypass the API server, so file bytes avoid FastAPI and keep request latency low for web/API traffic.
- Redis/RQ async scanning decouples upload completion from scan execution, preventing scan work from blocking upload initiation.
- Redis-backed rate limits constrain burst abuse while still allowing realistic concurrent demo traffic.

## Artifacts
- Script: `k6/load-test.js`
- Raw output: `k6/results/run.txt`
- JSON summary: `k6/results/summary.json`
