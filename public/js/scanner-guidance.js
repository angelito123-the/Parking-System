(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
    return;
  }
  root.ScannerGuidance = factory();
}(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  const MESSAGES = Object.freeze({
    idle: { key: "idle", message: "Start the camera to scan a QR code.", tone: "neutral" },
    center: { key: "center", message: "Center the QR code in the camera view.", tone: "neutral" },
    lighting: { key: "lighting", message: "Increase lighting or use the flashlight.", tone: "warning" },
    closer: { key: "closer", message: "Move closer to the QR code.", tone: "warning" },
    steady: { key: "steady", message: "Hold steady while the QR code focuses.", tone: "warning" },
    reading: { key: "reading", message: "Hold steady. Reading QR code...", tone: "ready" },
    detected: { key: "detected", message: "QR detected. Processing...", tone: "ready" },
    torchError: { key: "torch-error", message: "Flashlight could not be changed.", tone: "error" }
  });

  function finiteNumber(value) {
    const number = Number(value);
    return Number.isFinite(number) ? number : null;
  }

  function chooseGuidance(metrics) {
    const data = metrics || {};
    const brightness = finiteNumber(data.brightness);
    const areaRatio = finiteNumber(data.areaRatio);
    const confidence = finiteNumber(data.confidence);
    const threshold = finiteNumber(data.threshold) ?? 0.35;
    const detectedRegion = data.detectedRegion === true;

    if (brightness !== null && brightness < 62) return MESSAGES.lighting;
    if (detectedRegion && areaRatio !== null && areaRatio < 0.07) return MESSAGES.closer;
    if (detectedRegion && confidence !== null && confidence < threshold) return MESSAGES.steady;
    if (detectedRegion) return MESSAGES.reading;
    return MESSAGES.center;
  }

  class ScannerGuidance {
    constructor(options) {
      const config = options || {};
      this.cameraContainer = typeof config.cameraContainer === "string"
        ? document.getElementById(config.cameraContainer)
        : config.cameraContainer;
      this.guidanceElement = typeof config.guidanceElement === "string"
        ? document.getElementById(config.guidanceElement)
        : config.guidanceElement;
      this.torchButton = typeof config.torchButton === "string"
        ? document.getElementById(config.torchButton)
        : config.torchButton;
      this.active = false;
      this.activeSince = 0;
      this.lastKey = "";
      this.pendingKey = "";
      this.pendingHits = 0;
      this.missedFrames = 0;
      this.torchEnabled = false;
      this.supportRefreshTimer = null;

      if (this.torchButton) {
        this.torchButton.addEventListener("click", () => this.toggleTorch());
      }
      this.setGuidance(MESSAGES.idle, true);
    }

    setGuidance(guidance, force) {
      if (!this.guidanceElement || !guidance) return;
      if (!force && guidance.key === this.lastKey) return;

      const textElement = this.guidanceElement.querySelector(".scanner-guidance-text");
      if (textElement) textElement.textContent = guidance.message;
      else this.guidanceElement.textContent = guidance.message;

      this.guidanceElement.classList.remove("is-warning", "is-ready", "is-error");
      if (guidance.tone && guidance.tone !== "neutral") {
        this.guidanceElement.classList.add(`is-${guidance.tone}`);
      }
      this.lastKey = guidance.key;
    }

    getVideoTrack() {
      const video = this.cameraContainer?.querySelector("video");
      const tracks = video?.srcObject?.getVideoTracks?.();
      return tracks && tracks.length ? tracks[0] : null;
    }

    async refreshTorchSupport() {
      if (!this.torchButton) return false;
      const track = this.getVideoTrack();
      let supported = false;

      try {
        const capabilities = track?.getCapabilities?.();
        supported = capabilities?.torch === true;
      } catch (_error) {
        supported = false;
      }

      this.torchButton.hidden = !supported;
      this.torchButton.disabled = !supported;
      if (!supported) this.updateTorchButton(false);
      return supported;
    }

    updateTorchButton(enabled) {
      this.torchEnabled = Boolean(enabled);
      if (!this.torchButton) return;
      this.torchButton.classList.toggle("is-active", this.torchEnabled);
      this.torchButton.setAttribute("aria-pressed", String(this.torchEnabled));
      this.torchButton.setAttribute("aria-label", this.torchEnabled ? "Turn flashlight off" : "Turn flashlight on");
      const label = this.torchButton.querySelector(".scanner-torch-label");
      if (label) label.textContent = this.torchEnabled ? "Flashlight on" : "Flashlight";
    }

    async toggleTorch() {
      const track = this.getVideoTrack();
      if (!track) {
        await this.refreshTorchSupport();
        return;
      }

      const nextState = !this.torchEnabled;
      try {
        await track.applyConstraints({ advanced: [{ torch: nextState }] });
        this.updateTorchButton(nextState);
        if (nextState) this.setGuidance(MESSAGES.center, true);
      } catch (_error) {
        this.setGuidance(MESSAGES.torchError, true);
        await this.refreshTorchSupport();
      }
    }

    start() {
      this.active = true;
      this.activeSince = Date.now();
      this.missedFrames = 0;
      this.pendingKey = "";
      this.pendingHits = 0;
      this.setGuidance(MESSAGES.center, true);
      clearTimeout(this.supportRefreshTimer);
      this.supportRefreshTimer = setTimeout(() => this.refreshTorchSupport(), 250);
    }

    async stop() {
      this.active = false;
      clearTimeout(this.supportRefreshTimer);
      const track = this.getVideoTrack();
      if (track && this.torchEnabled) {
        try {
          await track.applyConstraints({ advanced: [{ torch: false }] });
        } catch (_error) {
          // The camera may already be closing.
        }
      }
      this.updateTorchButton(false);
      if (this.torchButton) this.torchButton.hidden = true;
      this.setGuidance(MESSAGES.idle, true);
    }

    update(metrics) {
      if (!this.active) return;
      this.missedFrames = 0;
      const next = chooseGuidance(metrics);
      if (next.key === this.lastKey) {
        this.pendingKey = "";
        this.pendingHits = 0;
        return;
      }

      if (next.key === this.pendingKey) this.pendingHits += 1;
      else {
        this.pendingKey = next.key;
        this.pendingHits = 1;
      }

      if (this.pendingHits >= 3) {
        this.setGuidance(next, false);
        this.pendingKey = "";
        this.pendingHits = 0;
      }
    }

    unreadableFrame() {
      if (!this.active) return;
      this.missedFrames += 1;
      if (this.missedFrames % 20 !== 0) return;
      const elapsed = Date.now() - this.activeSince;
      const phase = Math.floor(elapsed / 4000) % 3;
      const guidance = phase === 1
        ? MESSAGES.closer
        : phase === 2
          ? MESSAGES.steady
          : MESSAGES.center;
      this.setGuidance(guidance, false);
    }

    detected() {
      if (!this.active) return;
      this.pendingKey = "";
      this.pendingHits = 0;
      this.setGuidance(MESSAGES.detected, true);
    }
  }

  ScannerGuidance.chooseGuidance = chooseGuidance;
  ScannerGuidance.MESSAGES = MESSAGES;
  return ScannerGuidance;
}));
