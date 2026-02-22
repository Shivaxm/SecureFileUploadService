import http from "k6/http";
import crypto from "k6/crypto";
import { check, sleep } from "k6";
import { Counter, Trend } from "k6/metrics";

const BASE_URL = __ENV.BASE_URL || "https://securefileuploadservice.onrender.com";

const pipelineLatencyMs = new Trend("scan_pipeline_latency_ms", true);
const completeToTerminalLatencyMs = new Trend("complete_to_terminal_latency_ms", true);
const uploadCyclesCompleted = new Counter("upload_cycles_completed");
const uploadCyclesActive = new Counter("upload_cycles_active");

export const options = {
  scenarios: {
    baseline: {
      exec: "baselineScenario",
      executor: "constant-vus",
      vus: 10,
      duration: "20s",
      startTime: "0s",
      gracefulStop: "0s",
    },
    upload_pipeline: {
      exec: "uploadPipelineScenario",
      executor: "constant-vus",
      vus: 5,
      duration: "30s",
      startTime: "25s",
      gracefulStop: "5s",
    },
    files_listing: {
      exec: "filesListingScenario",
      executor: "constant-vus",
      vus: 8,
      duration: "20s",
      startTime: "105s",
      gracefulStop: "0s",
    },
  },
  thresholds: {
    "http_req_duration{scenario:baseline}": ["p(95)<300"],
    "http_req_failed{scenario:baseline}": ["rate<0.01"],
    "http_req_duration{name:POST_files_init}": ["p(95)<500"],
    "http_req_duration{name:POST_complete}": ["p(95)<500"],
    "http_req_duration{name:GET_files_poll}": ["p(95)<300"],
    "http_req_duration{name:PUT_upload}": ["p(95)<5000"],
    "http_req_duration{name:POST_download_url}": ["p(95)<2000"],
    "http_req_failed{scenario:upload_pipeline}": ["rate<0.05"],
    "http_req_duration{name:GET_files_list}": ["p(95)<400"],
    "http_req_failed{scenario:files_listing}": ["rate<0.01"],
  },
};

export function setup() {
  for (let i = 0; i < 5; i += 1) {
    const res = http.get(`${BASE_URL}/health`, { tags: { name: "GET_health_warmup" } });
    check(res, { "warmup /health returns 200": (r) => r.status === 200 });
    sleep(3);
  }
}

function hasDemoCookie() {
  const jar = http.cookieJar();
  const cookies = jar.cookiesForURL(BASE_URL);
  return !!(cookies.demo && cookies.demo.length > 0);
}

function ensureDemoSession() {
  if (hasDemoCookie()) {
    return true;
  }
  const maxAttempts = 5;
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    const res = http.post(`${BASE_URL}/demo/start`, null, {
      tags: { name: "POST_demo_start" },
    });
    const ok = check(res, {
      "demo/start returns 200": (r) => r.status === 200,
    });
    if (ok && hasDemoCookie()) {
      return true;
    }
    if (res.status === 429) {
      sleep(Math.min(2 * attempt, 8));
      continue;
    }
    sleep(1);
  }
  return hasDemoCookie();
}

function randomSleep(minSeconds, maxSeconds) {
  sleep(minSeconds + Math.random() * (maxSeconds - minSeconds));
}

function buildTestContent() {
  const seed = `${__VU}-${__ITER}-${Date.now()}-${Math.random()}`;
  const repeated = seed.repeat(80);
  return repeated.slice(0, 4096);
}

export function baselineScenario() {
  const healthRes = http.get(`${BASE_URL}/health`, { tags: { name: "GET_health" } });
  check(healthRes, { "GET /health is 200": (r) => r.status === 200 });
  sleep(0.5);

  const homeRes = http.get(`${BASE_URL}/`, { tags: { name: "GET_home" } });
  check(homeRes, { "GET / is 200": (r) => r.status === 200 });
  sleep(0.5);

  const architectureRes = http.get(`${BASE_URL}/architecture`, {
    tags: { name: "GET_architecture" },
  });
  check(architectureRes, { "GET /architecture is 200": (r) => r.status === 200 });
  sleep(0.5);
}

export function uploadPipelineScenario() {
  if (!ensureDemoSession()) {
    randomSleep(3, 5);
    return;
  }

  const testContent = buildTestContent();
  const checksum = crypto.sha256(testContent, "hex");
  const filename = `k6-vu${__VU}-iter${__ITER}.txt`;
  const pipelineStart = Date.now();

  const initRes = http.post(
    `${BASE_URL}/files/init`,
    JSON.stringify({
      original_filename: filename,
      content_type: "text/plain",
      checksum_sha256: checksum,
      size_bytes: testContent.length,
    }),
    {
      headers: { "Content-Type": "application/json" },
      tags: { name: "POST_files_init" },
    },
  );
  const initOk = check(initRes, {
    "POST /files/init is 200": (r) => r.status === 200,
  });
  if (!initOk) {
    randomSleep(3, 5);
    return;
  }

  const initBody = initRes.json();
  const uploadUrl = initBody.upload_url;
  const fileId = initBody.file_id;
  const putHeaders = Object.assign({}, initBody.headers_to_include || {});
  if (!putHeaders["Content-Type"] && !putHeaders["content-type"]) {
    putHeaders["Content-Type"] = "text/plain";
  }

  const putRes = http.put(uploadUrl, testContent, {
    headers: putHeaders,
    tags: { name: "PUT_upload" },
  });
  const putOk = check(putRes, {
    "PUT upload is 200/204": (r) => r.status === 200 || r.status === 204,
  });
  if (!putOk) {
    randomSleep(3, 5);
    return;
  }

  const completeStart = Date.now();
  const completeRes = http.post(`${BASE_URL}/files/${fileId}/complete`, null, {
    tags: { name: "POST_complete" },
  });
  const completeOk = check(completeRes, {
    "POST /complete is 200": (r) => r.status === 200,
  });
  if (!completeOk) {
    randomSleep(3, 5);
    return;
  }

  let terminalState = null;
  const maxPolls = 15;
  for (let i = 0; i < maxPolls; i += 1) {
    const pollRes = http.get(`${BASE_URL}/files?format=json`, {
      tags: { name: "GET_files_poll" },
    });
    if (pollRes.status !== 200) {
      sleep(2);
      continue;
    }

    const files = pollRes.json();
    const currentFile = Array.isArray(files) ? files.find((f) => f.id === fileId) : null;
    if (!currentFile) {
      sleep(2);
      continue;
    }

    const state = currentFile.state;
    if (state === "ACTIVE" || state === "QUARANTINED" || state === "REJECTED") {
      terminalState = state;
      pipelineLatencyMs.add(Date.now() - pipelineStart);
      completeToTerminalLatencyMs.add(Date.now() - completeStart);
      break;
    }

    sleep(2);
  }

  if (terminalState) {
    uploadCyclesCompleted.add(1);
  }

  if (terminalState === "ACTIVE") {
    uploadCyclesActive.add(1);
    const downloadRes = http.post(`${BASE_URL}/files/${fileId}/download-url`, null, {
      tags: { name: "POST_download_url" },
    });
    check(downloadRes, {
      "POST /download-url is 200 for ACTIVE": (r) => r.status === 200,
    });
  }

  randomSleep(3, 5);
}

export function filesListingScenario() {
  if (!ensureDemoSession()) {
    randomSleep(1, 2);
    return;
  }

  const listResOne = http.get(`${BASE_URL}/files?format=json`, {
    tags: { name: "GET_files_list" },
  });
  check(listResOne, { "GET /files?format=json #1 is 200": (r) => r.status === 200 });
  randomSleep(1, 2);

  const listResTwo = http.get(`${BASE_URL}/files?format=json`, {
    tags: { name: "GET_files_list" },
  });
  check(listResTwo, { "GET /files?format=json #2 is 200": (r) => r.status === 200 });
  randomSleep(1, 2);
}
