const output = document.getElementById("scanOutput");
const gateInput = document.getElementById("gateInput");
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

async function handleScan(decodedText) {
  const token = extractToken(decodedText);
  const gate = gateInput.value || "Main Gate";

  const response = await fetch("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token, gate })
  });
  const data = await response.json();
  const timestampText = data.scanned_at
    ? new Date(data.scanned_at).toLocaleString()
    : "N/A";
  const header = data.duplicate_scan
    ? "Duplicate scan ignored (cooldown active)"
    : "Scan processed";
  output.textContent =
    `${header}\nScan Timestamp: ${timestampText}\n` + JSON.stringify(data, null, 2);
}

function onScanSuccess(decodedText) {
  html5QrCode
    .pause()
    .then(() => handleScan(decodedText))
    .catch((_error) => {})
    .finally(() => setTimeout(() => html5QrCode.resume(), 1800));
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
    // Fallback: select a back camera by label if exact facing mode is unsupported.
  }

  try {
    const devices = await Html5Qrcode.getCameras();
    if (!devices || devices.length === 0) {
      output.textContent = "No camera found.";
      return;
    }

    const rearCam =
      devices.find((d) => /back|rear|environment/i.test(d.label)) || devices[0];

    await html5QrCode.start(rearCam.id, config, onScanSuccess, onScanFailure);
  } catch (error) {
    output.textContent = `Unable to open camera: ${error}`;
  }
}

startScanner();
