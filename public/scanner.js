const gateInput = document.getElementById("gateInput");
const waitingEl = document.getElementById("scanWaiting");
const resultCard = document.getElementById("scanResultCard");
const resultIcon = document.getElementById("scanResultIcon");
const resultStatus = document.getElementById("scanResultStatus");
const resultDetails = document.getElementById("scanResultDetails");
const resultActionBadge = document.getElementById("scanResultActionBadge");

const html5QrCode = new Html5Qrcode("reader");

function extractToken(decodedText) {
  try {
    const url = new URL(decodedText);
    const parts = url.pathname.split("/").filter(Boolean);
    if (parts.length >= 2 && parts[0] === "verify") return parts[1];
  } catch (_error) {
    return decodedText;
  }
  return decodedText;
}

function renderResult(data) {
  waitingEl.style.display = "none";
  resultCard.className = "scan-result-card visible";

  const isOk = data.ok === true;
  const isDuplicate = data.duplicate_scan === true;
  const result = (data.result || "INVALID").toLowerCase();

  // Set card color class
  resultCard.classList.add(`result-${result}`);

  // Icon
  if (isDuplicate) {
    resultIcon.textContent = "⏳";
  } else if (isOk) {
    resultIcon.textContent = "✅";
  } else if (result === "expired") {
    resultIcon.textContent = "⌛";
  } else if (result === "revoked") {
    resultIcon.textContent = "🚫";
  } else {
    resultIcon.textContent = "❌";
  }

  // Status text
  if (isDuplicate) {
    resultStatus.textContent = "Duplicate Scan — Cooldown Active";
    resultStatus.className = "scan-result-status fail";
  } else {
    resultStatus.textContent = (data.result || "INVALID").toUpperCase();
    resultStatus.className = `scan-result-status ${isOk ? "ok" : "fail"}`;
  }

  // Details
  const details = [];
  if (data.sticker) {
    details.push(`<p class="scan-result-detail"><strong>Student:</strong> ${data.sticker.full_name || "-"} (${data.sticker.student_number || "-"})</p>`);
    details.push(`<p class="scan-result-detail"><strong>Plate:</strong> ${data.sticker.plate_number || "-"}</p>`);
    details.push(`<p class="scan-result-detail"><strong>Vehicle:</strong> ${data.sticker.model || "-"}</p>`);
    details.push(`<p class="scan-result-detail"><strong>Sticker:</strong> ${data.sticker.sticker_code || "-"}</p>`);
  }
  if (data.message) {
    details.push(`<p class="scan-result-detail"><strong>Note:</strong> ${data.message}</p>`);
  }
  const timestamp = data.scanned_at ? new Date(data.scanned_at).toLocaleString() : null;
  if (timestamp) {
    details.push(`<p class="scan-result-detail"><strong>Time:</strong> ${timestamp}</p>`);
  }
  resultDetails.innerHTML = details.join("");

  // Action badge
  if (isOk && data.action && !isDuplicate) {
    const isEntry = data.action === "ENTRY";
    resultActionBadge.innerHTML = `
      <span class="scan-result-action" style="background: ${isEntry ? "var(--green-text)" : "var(--red-text)"}">
        ${isEntry ? "🟢" : "🔴"} ${data.action} Recorded
      </span>`;
  } else {
    resultActionBadge.innerHTML = "";
  }
}

function showError(message) {
  waitingEl.style.display = "none";
  resultCard.className = "scan-result-card visible result-invalid";
  resultIcon.textContent = "⚠️";
  resultStatus.textContent = "Scan Error";
  resultStatus.className = "scan-result-status fail";
  resultDetails.innerHTML = `<p class="scan-result-detail">${message}</p>`;
  resultActionBadge.innerHTML = "";
}

async function handleScan(decodedText) {
  const token = extractToken(decodedText);
  const gate = gateInput ? gateInput.value || "Main Gate" : "Main Gate";

  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token, gate })
    });

    if (!response.ok) {
      showError(`Server returned status ${response.status}. Please try again.`);
      return;
    }

    const data = await response.json();
    renderResult(data);
  } catch (err) {
    showError(`Network error: Unable to reach the server. Check your connection.`);
  }
}

function onScanSuccess(decodedText) {
  html5QrCode
    .pause()
    .then(() => handleScan(decodedText))
    .catch(() => {})
    .finally(() => setTimeout(() => html5QrCode.resume(), 2000));
}

function onScanFailure(_errorMessage) {}

async function startScanner() {
  const config = {
    fps: 12,
    qrbox: { width: 250, height: 250 }
  };

  try {
    await html5QrCode.start(
      { facingMode: { exact: "environment" } },
      config,
      onScanSuccess,
      onScanFailure
    );
    return;
  } catch (_error) {
    // Fallback: select a back camera by label
  }

  try {
    const devices = await Html5Qrcode.getCameras();
    if (!devices || devices.length === 0) {
      showError("No camera found on this device.");
      return;
    }
    const rearCam =
      devices.find((d) => /back|rear|environment/i.test(d.label)) || devices[0];
    await html5QrCode.start(rearCam.id, config, onScanSuccess, onScanFailure);
  } catch (error) {
    showError(`Unable to open camera: ${error}`);
  }
}

startScanner();
