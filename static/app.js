function statusInfo(state) {
  if (state === "ACTIVE") return { label: "CLEAN", cls: "badge-clean", canDownload: true };
  if (state === "QUARANTINED" || state === "REJECTED") return { label: "QUARANTINED", cls: "badge-quarantined", canDownload: false };
  return { label: "PENDING", cls: "badge-pending", canDownload: false };
}

async function api(url, options = {}) {
  const res = await fetch(url, { credentials: "include", ...options });
  if (!res.ok) {
    let detail = "Request failed";
    try {
      const payload = await res.json();
      detail = payload.detail || detail;
    } catch (_err) {}
    throw new Error(detail);
  }
  return res;
}

async function startDemo() {
  // Backend endpoint used: POST /demo/start
  await api("/demo/start", { method: "POST" });
}

function initStartDemoButtons() {
  const buttons = document.querySelectorAll('[data-action="start-demo"]');
  if (!buttons.length) return;

  buttons.forEach((btn) => {
    btn.addEventListener("click", async () => {
      const redirect = btn.dataset.redirect || "/upload";
      const messageId = btn.dataset.messageId;
      const message = messageId ? document.getElementById(messageId) : null;
      const originalText = btn.textContent;
      btn.disabled = true;
      if (message) message.textContent = "Starting demo...";
      btn.textContent = "Starting...";

      try {
        await startDemo();
        window.location.href = redirect;
      } catch (err) {
        const msg = err && err.message ? err.message : "Could not start demo";
        if (message) message.textContent = msg;
        btn.textContent = originalText;
        btn.disabled = false;
      }
    });
  });
}

async function sha256Hex(file) {
  const buf = await file.arrayBuffer();
  const digest = await crypto.subtle.digest("SHA-256", buf);
  return [...new Uint8Array(digest)].map((x) => x.toString(16).padStart(2, "0")).join("");
}

async function uploadBinary(url, headers, file, onProgress) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("PUT", url, true);
    Object.entries(headers || {}).forEach(([k, v]) => xhr.setRequestHeader(k, v));
    xhr.upload.onprogress = (event) => {
      if (event.lengthComputable && onProgress) onProgress(Math.round((event.loaded / event.total) * 100));
    };
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) return resolve();
      reject(new Error("Upload to storage failed"));
    };
    xhr.onerror = () => reject(new Error("Upload network error"));
    xhr.send(file);
  });
}

async function pollFileState(fileId, timeoutMs = 90000) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    // Backend endpoint used: GET /files?format=json
    const res = await api("/files?format=json");
    const files = await res.json();
    const file = files.find((f) => f.id === fileId);
    if (file && !["INITIATED", "SCANNING", "UPLOADED"].includes(file.state)) return file.state;
    await new Promise((r) => setTimeout(r, 2000));
  }
  return "SCANNING";
}

function initHomePage() {
  const btn = document.getElementById("startDemoBtn");
  if (!btn) return;
  const message = document.getElementById("homeMessage");
  btn.addEventListener("click", async () => {
    btn.disabled = true;
    message.textContent = "Starting demo...";
    try {
      await startDemo();
      window.location.href = "/upload";
    } catch (err) { message.textContent = err.message; btn.disabled = false; }
  });
}

function setBadge(node, state) {
  const info = statusInfo(state);
  node.textContent = info.label;
  node.className = `badge ${info.cls}`;
}

function initUploadPage() {
  const input = document.getElementById("fileInput");
  const button = document.getElementById("uploadBtn");
  if (!input || !button) return;
  const progress = document.getElementById("uploadProgress");
  const message = document.getElementById("uploadMessage");
  const result = document.getElementById("uploadResult");
  const resultName = document.getElementById("resultFileName");
  const resultStatus = document.getElementById("resultStatus");

  // Default UI state: don't show PENDING until an upload is started.
  if (result) result.classList.add("hidden");
  if (resultName) resultName.textContent = "-";
  if (resultStatus) {
    resultStatus.textContent = "Ready";
    resultStatus.className = "badge";
  }

  button.addEventListener("click", async () => {
    const file = input.files && input.files[0];
    if (!file) {
      message.textContent = "Choose a file first.";
      return;
    }
    button.disabled = true;
    progress.value = 0;
      message.textContent = "Preparing upload...";

      try {
        const checksum = await sha256Hex(file);
      // Backend endpoint used: POST /files/init
      const initRes = await api("/files/init", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          original_filename: file.name,
          content_type: file.type || "application/octet-stream",
          checksum_sha256: checksum,
          size_bytes: file.size,
        }),
      });
      const initBody = await initRes.json();

      // Show result area as soon as the upload is initiated.
      result.classList.remove("hidden");
      resultName.textContent = file.name;
      setBadge(resultStatus, "SCANNING");

      message.textContent = "Uploading file to storage...";
      await uploadBinary(
        initBody.upload_url,
        initBody.headers_to_include,
        file,
        (p) => (progress.value = p)
      );

      message.textContent = "Finalizing upload...";
      // Backend endpoint used: POST /files/{id}/complete
      await api(`/files/${initBody.file_id}/complete`, { method: "POST" });

      message.textContent = "Waiting for scan...";
      const finalState = await pollFileState(initBody.file_id);

      result.classList.remove("hidden");
      resultName.textContent = file.name;
      setBadge(resultStatus, finalState);
      message.textContent = "Upload complete.";
    } catch (err) { message.textContent = err.message; }
    finally { button.disabled = false; }
  });
}

async function requestDownload(fileId, messageNode) {
  try {
    // Backend endpoint used: POST /files/{id}/download-url
    const res = await api(`/files/${fileId}/download-url`, { method: "POST" });
    const body = await res.json();
    window.location.href = body.download_url;
  } catch (err) {
    if (messageNode) messageNode.textContent = err.message;
  }
}

function renderFilesTable(files, tbody, message) {
  tbody.innerHTML = "";
  if (!files.length) {
    tbody.innerHTML =
      '<tr><td colspan="4">No files yet — <a href="/upload">upload one</a>.</td></tr>';
    return;
  }

  files.forEach((f) => {
    const tr = document.createElement("tr");
    const status = statusInfo(f.state);
    const created = new Date(f.created_at).toLocaleString();

    const nameTd = document.createElement("td");
    nameTd.textContent = f.original_filename;
    tr.appendChild(nameTd);

    const dateTd = document.createElement("td");
    dateTd.textContent = created;
    tr.appendChild(dateTd);

    const statusTd = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = `badge ${status.cls}`;
    badge.textContent = status.label;
    statusTd.appendChild(badge);
    tr.appendChild(statusTd);

    const actionTd = document.createElement("td");
    if (status.canDownload) {
      const btn = document.createElement("button");
      btn.className = "btn";
      btn.textContent = "Download";
      btn.addEventListener("click", () => requestDownload(f.id, message));
      actionTd.appendChild(btn);
    } else if (f.state === "QUARANTINED" || f.state === "REJECTED") {
      actionTd.textContent = "Quarantined";
    } else {
      actionTd.textContent = "Download disabled until scan completes";
    }
    tr.appendChild(actionTd);

    tbody.appendChild(tr);
  });
}

function initFilesPage() {
  const tbody = document.getElementById("filesTableBody");
  if (!tbody) return;
  const message = document.getElementById("filesMessage");
  const retryBtn = document.getElementById("filesRetryBtn");

  const load = async () => {
    try {
      // Backend endpoint used: GET /files?format=json
      const res = await api("/files?format=json");
      const files = await res.json();
      renderFilesTable(files, tbody, message);
      message.textContent = "";
      if (retryBtn) retryBtn.classList.add("hidden");
      return true;
    } catch (err) {
      const msg = err && err.message ? err.message : "Could not load files.";
      const demoNotStarted = msg.includes("Start demo at POST /demo/start");
      tbody.innerHTML = demoNotStarted
        ? '<tr><td colspan="4">Demo not started — click “Start Demo” above.</td></tr>'
        : '<tr><td colspan="4">Could not load files.</td></tr>';
      message.textContent = demoNotStarted ? "Demo not started." : msg;
    }
    if (retryBtn) retryBtn.classList.remove("hidden");
    return false;
  };

  const start = async () => {
    const ok = await load();
    if (ok) {
      setInterval(load, 5000);
      return;
    }

    // If demo isn't started, avoid leaving users stuck. The templates already
    // show a Start Demo CTA; here we just stop the auto-poll.
    if (retryBtn) {
      retryBtn.onclick = () => load();
    }
  };

  start();
}

(function init() {
  initStartDemoButtons();
  const page = document.body.dataset.page;
  if (page === "home") initHomePage();
  if (page === "upload") initUploadPage();
  if (page === "files") initFilesPage();
})();
