(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  if (root) root.ScannerDeviceCheck = api;
}(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  function classifyDevice(width, userAgent) {
    const viewport = Number(width) || 0;
    const ua = String(userAgent || "");
    if (/tablet|ipad/i.test(ua) || (viewport >= 700 && viewport <= 1100 && /android/i.test(ua))) return "tablet";
    if (/mobile|android|iphone/i.test(ua) || viewport < 700) return "mobile";
    return "desktop";
  }

  function evaluateCapabilities(capabilities) {
    const data = capabilities || {};
    const checks = [
      { key: "secure", label: "Secure camera connection", passed: data.secureContext === true, required: true },
      { key: "camera", label: "Camera API", passed: data.camera === true, required: true },
      { key: "storage", label: "Offline queue storage", passed: data.indexedDb === true, required: true },
      { key: "serviceWorker", label: "Offline app support", passed: data.serviceWorker === true, required: false },
      { key: "detector", label: "Fast native QR detection", passed: data.barcodeDetector === true, required: false },
      { key: "torch", label: "Flashlight control", passed: data.torch === true, required: false }
    ];
    const requiredPassed = checks.filter((check) => check.required).every((check) => check.passed);
    const optionalPassed = checks.filter((check) => !check.required && check.passed).length;
    return {
      checks,
      ready: requiredPassed,
      grade: !requiredPassed ? "needs-attention" : optionalPassed >= 2 ? "excellent" : "ready"
    };
  }

  function inspect(cameraContainer) {
    const container = typeof cameraContainer === "string" ? document.getElementById(cameraContainer) : cameraContainer;
    const video = container?.querySelector?.("video");
    const track = video?.srcObject?.getVideoTracks?.()[0] || null;
    let torch = false;
    try {
      torch = track?.getCapabilities?.()?.torch === true;
    } catch (_error) {
      torch = false;
    }
    const result = evaluateCapabilities({
      secureContext: window.isSecureContext === true || window.location.hostname === "localhost",
      camera: Boolean(navigator.mediaDevices?.getUserMedia),
      indexedDb: typeof indexedDB !== "undefined",
      serviceWorker: "serviceWorker" in navigator,
      barcodeDetector: typeof BarcodeDetector !== "undefined",
      torch
    });
    return {
      ...result,
      deviceClass: classifyDevice(window.innerWidth, navigator.userAgent)
    };
  }

  return { classifyDevice, evaluateCapabilities, inspect };
}));
