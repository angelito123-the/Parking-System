(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
    return;
  }
  root.MLQrCodeScanner = factory();
}(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  const STATE = Object.freeze({
    UNKNOWN: 0,
    NOT_STARTED: 1,
    SCANNING: 2,
    PAUSED: 3
  });

  function clamp(value, min, max) {
    return Math.max(min, Math.min(max, value));
  }

  function toUint8(value) {
    return value < 0 ? 0 : value > 255 ? 255 : value | 0;
  }

  function ensureJsQrAvailable() {
    if (typeof jsQR !== "function") {
      throw new Error("jsQR decoder is required. Load jsQR before MLQrCodeScanner.");
    }
  }

  function averageLumaStd(luma, width, height, rect) {
    const x0 = Math.max(0, Math.floor(rect.x));
    const y0 = Math.max(0, Math.floor(rect.y));
    const x1 = Math.min(width, Math.ceil(rect.x + rect.width));
    const y1 = Math.min(height, Math.ceil(rect.y + rect.height));
    if (x1 <= x0 || y1 <= y0) return 0;

    let sum = 0;
    let sumSq = 0;
    let count = 0;
    for (let y = y0; y < y1; y += 1) {
      const row = y * width;
      for (let x = x0; x < x1; x += 1) {
        const v = luma[row + x];
        sum += v;
        sumSq += v * v;
        count += 1;
      }
    }

    if (!count) return 0;
    const mean = sum / count;
    const variance = Math.max(0, (sumSq / count) - (mean * mean));
    return Math.sqrt(variance);
  }

  function rgbToLuma(imageData) {
    const { data, width, height } = imageData;
    const out = new Uint8ClampedArray(width * height);
    for (let i = 0, j = 0; i < data.length; i += 4, j += 1) {
      out[j] = toUint8((data[i] * 0.299) + (data[i + 1] * 0.587) + (data[i + 2] * 0.114));
    }
    return out;
  }

  function estimateMeanLuma(luma) {
    if (!luma || !luma.length) return null;
    const step = Math.max(1, Math.floor(luma.length / 4096));
    let sum = 0;
    let count = 0;
    for (let i = 0; i < luma.length; i += step) {
      sum += luma[i];
      count += 1;
    }
    return count ? Math.round(sum / count) : null;
  }

  function normalizeContrast(luma) {
    let min = 255;
    let max = 0;
    for (let i = 0; i < luma.length; i += 1) {
      const value = luma[i];
      if (value < min) min = value;
      if (value > max) max = value;
    }

    if (max - min < 8) {
      return luma.slice();
    }

    const scale = 255 / (max - min);
    const out = new Uint8ClampedArray(luma.length);
    for (let i = 0; i < luma.length; i += 1) {
      out[i] = toUint8((luma[i] - min) * scale);
    }
    return out;
  }

  function buildIntegralImage(luma, width, height) {
    const integral = new Float64Array((width + 1) * (height + 1));
    for (let y = 1; y <= height; y += 1) {
      let rowSum = 0;
      for (let x = 1; x <= width; x += 1) {
        rowSum += luma[(y - 1) * width + (x - 1)];
        integral[y * (width + 1) + x] = integral[(y - 1) * (width + 1) + x] + rowSum;
      }
    }
    return integral;
  }

  function adaptiveThreshold(luma, width, height, windowSize, bias) {
    const half = Math.max(1, Math.floor(windowSize / 2));
    const integral = buildIntegralImage(luma, width, height);
    const out = new Uint8ClampedArray(luma.length);

    for (let y = 0; y < height; y += 1) {
      const y0 = Math.max(0, y - half);
      const y1 = Math.min(height - 1, y + half);
      for (let x = 0; x < width; x += 1) {
        const x0 = Math.max(0, x - half);
        const x1 = Math.min(width - 1, x + half);

        const ax = x0;
        const ay = y0;
        const bx = x1 + 1;
        const by = y1 + 1;

        const sum = integral[(by * (width + 1)) + bx]
          - integral[(ay * (width + 1)) + bx]
          - integral[(by * (width + 1)) + ax]
          + integral[(ay * (width + 1)) + ax];

        const area = (x1 - x0 + 1) * (y1 - y0 + 1);
        const mean = sum / area;
        const index = y * width + x;
        out[index] = luma[index] >= (mean - bias) ? 255 : 0;
      }
    }

    return out;
  }

  function grayscaleToRgba(gray, width, height) {
    const out = new Uint8ClampedArray(width * height * 4);
    for (let i = 0, j = 0; i < gray.length; i += 1, j += 4) {
      const g = gray[i];
      out[j] = g;
      out[j + 1] = g;
      out[j + 2] = g;
      out[j + 3] = 255;
    }
    return out;
  }

  function parseCorners(candidate) {
    if (!candidate || !candidate.cornerPoints || candidate.cornerPoints.length < 4) return null;
    const points = candidate.cornerPoints.map((point) => ({
      x: Number(point.x),
      y: Number(point.y)
    }));
    if (points.some((point) => !Number.isFinite(point.x) || !Number.isFinite(point.y))) return null;

    let tl = points[0];
    let tr = points[1];
    let br = points[2];
    let bl = points[3];

    points.sort((a, b) => (a.y - b.y) || (a.x - b.x));
    const top = points.slice(0, 2).sort((a, b) => a.x - b.x);
    const bottom = points.slice(2).sort((a, b) => a.x - b.x);
    tl = top[0];
    tr = top[1];
    bl = bottom[0];
    br = bottom[1];

    return { tl, tr, br, bl };
  }

  function rectifyQuadBilinear(gray, width, height, corners, size) {
    const output = new Uint8ClampedArray(size * size);
    const tl = corners.tl;
    const tr = corners.tr;
    const br = corners.br;
    const bl = corners.bl;

    for (let y = 0; y < size; y += 1) {
      const v = size <= 1 ? 0 : y / (size - 1);
      for (let x = 0; x < size; x += 1) {
        const u = size <= 1 ? 0 : x / (size - 1);

        const sx = ((1 - u) * (1 - v) * tl.x)
          + (u * (1 - v) * tr.x)
          + (u * v * br.x)
          + ((1 - u) * v * bl.x);
        const sy = ((1 - u) * (1 - v) * tl.y)
          + (u * (1 - v) * tr.y)
          + (u * v * br.y)
          + ((1 - u) * v * bl.y);

        const ix = clamp(Math.round(sx), 0, width - 1);
        const iy = clamp(Math.round(sy), 0, height - 1);
        output[(y * size) + x] = gray[(iy * width) + ix];
      }
    }

    return output;
  }

  function cropRect(gray, width, height, rect) {
    const x0 = clamp(Math.floor(rect.x), 0, width - 1);
    const y0 = clamp(Math.floor(rect.y), 0, height - 1);
    const x1 = clamp(Math.ceil(rect.x + rect.width), x0 + 1, width);
    const y1 = clamp(Math.ceil(rect.y + rect.height), y0 + 1, height);

    const outWidth = Math.max(1, x1 - x0);
    const outHeight = Math.max(1, y1 - y0);
    const output = new Uint8ClampedArray(outWidth * outHeight);

    for (let y = 0; y < outHeight; y += 1) {
      const srcOffset = (y0 + y) * width + x0;
      const dstOffset = y * outWidth;
      output.set(gray.subarray(srcOffset, srcOffset + outWidth), dstOffset);
    }

    return { gray: output, width: outWidth, height: outHeight };
  }

  function normalizeRect(rect, width, height) {
    if (!rect) {
      return {
        x: 0,
        y: 0,
        width,
        height
      };
    }
    const x = clamp(Number(rect.x || 0), 0, Math.max(0, width - 1));
    const y = clamp(Number(rect.y || 0), 0, Math.max(0, height - 1));
    const maxWidth = Math.max(1, width - x);
    const maxHeight = Math.max(1, height - y);
    const normalizedWidth = clamp(Number(rect.width || width), 1, maxWidth);
    const normalizedHeight = clamp(Number(rect.height || height), 1, maxHeight);
    return {
      x,
      y,
      width: normalizedWidth,
      height: normalizedHeight
    };
  }

  function expandRect(rect, frameWidth, frameHeight, paddingRatio = 0.14) {
    const normalized = normalizeRect(rect, frameWidth, frameHeight);
    const padX = normalized.width * Math.max(0, paddingRatio);
    const padY = normalized.height * Math.max(0, paddingRatio);
    return normalizeRect({
      x: normalized.x - padX,
      y: normalized.y - padY,
      width: normalized.width + (padX * 2),
      height: normalized.height + (padY * 2)
    }, frameWidth, frameHeight);
  }

  function decodeQrFromGray(gray, width, height) {
    if (!gray || !width || !height) return null;
    const candidateBinary = adaptiveThreshold(gray, width, height, 17, 6);
    const binaryRgba = grayscaleToRgba(candidateBinary, width, height);
    let decodeResult = jsQR(binaryRgba, width, height, { inversionAttempts: "dontInvert" });
    if (decodeResult && decodeResult.data) return decodeResult;

    const normalizedRgba = grayscaleToRgba(gray, width, height);
    decodeResult = jsQR(normalizedRgba, width, height, { inversionAttempts: "attemptBoth" });
    return decodeResult && decodeResult.data ? decodeResult : null;
  }

  function estimateEdgeDensity(binary, width, height, rect) {
    const x0 = Math.max(0, Math.floor(rect.x));
    const y0 = Math.max(0, Math.floor(rect.y));
    const x1 = Math.min(width - 1, Math.ceil(rect.x + rect.width) - 1);
    const y1 = Math.min(height - 1, Math.ceil(rect.y + rect.height) - 1);
    if (x1 <= x0 || y1 <= y0) return 0;

    let transitions = 0;
    let comparisons = 0;

    for (let y = y0; y < y1; y += 2) {
      const row = y * width;
      for (let x = x0; x < x1; x += 2) {
        const a = binary[row + x];
        const b = binary[row + x + 1];
        const c = binary[row + width + x];
        if (a !== b) transitions += 1;
        if (a !== c) transitions += 1;
        comparisons += 2;
      }
    }

    return comparisons ? transitions / comparisons : 0;
  }

  function pickBestDetection(detections, frameWidth, frameHeight) {
    if (!Array.isArray(detections) || detections.length === 0) return null;
    let best = null;
    let bestScore = -1;

    for (const detection of detections) {
      const box = detection.boundingBox || detection.bounding_box || detection.box || null;
      if (!box) continue;
      const width = Math.max(1, Number(box.width || box.w || 0));
      const height = Math.max(1, Number(box.height || box.h || 0));
      const x = Number(box.x || box.left || 0);
      const y = Number(box.y || box.top || 0);
      if (!Number.isFinite(width) || !Number.isFinite(height) || width < 6 || height < 6) continue;

      const areaScore = clamp((width * height) / (frameWidth * frameHeight), 0, 1);
      const aspect = width / height;
      const aspectScore = 1 - clamp(Math.abs(Math.log(aspect)) / 1.2, 0, 1);
      const score = (areaScore * 0.62) + (aspectScore * 0.38);

      if (score > bestScore) {
        bestScore = score;
        best = {
          detection,
          rect: { x, y, width, height },
          corners: parseCorners(detection),
          detectorScore: score
        };
      }
    }

    return best;
  }

  class MLQrCodeScanner {
    constructor(containerId, options = {}) {
      ensureJsQrAvailable();

      this.container = typeof containerId === "string"
        ? document.getElementById(containerId)
        : containerId;
      if (!this.container) {
        throw new Error("MLQrCodeScanner container not found.");
      }

      this.options = {
        targetFps: Math.max(8, Math.min(30, Number(options.targetFps) || 30)),
        confidenceThreshold: clamp(Number(options.confidenceThreshold) || 0.45, 0.1, 0.99),
        lowConfidenceDecodeRatio: clamp(Number(options.lowConfidenceDecodeRatio) || 0.6, 0.2, 1),
        maxProcessWidth: Math.max(320, Math.min(960, Number(options.maxProcessWidth) || 640)),
        perspectiveSize: Math.max(160, Math.min(420, Number(options.perspectiveSize) || 280)),
        duplicateSuppressMs: Math.max(120, Math.min(1500, Number(options.duplicateSuppressMs) || 260)),
        onMlMetrics: typeof options.onMlMetrics === "function" ? options.onMlMetrics : null
      };

      this.state = STATE.NOT_STARTED;
      this.video = null;
      this.stream = null;
      this.rawCanvas = document.createElement("canvas");
      this.rawCtx = this.rawCanvas.getContext("2d", { willReadFrequently: true });
      this.rafId = null;
      this.lastFrameAt = 0;
      this.lastDecodedAt = 0;
      this.lastDecodedText = "";
      this.processing = false;
      this.onSuccess = null;
      this.onFailure = null;
      this.detector = null;
      this.lastProcessDurationMs = 0;
      this.lastMlMetrics = null;
      this.frameCounter = 0;
      this.lastDetectedRegion = null;
      this.readinessModel = typeof ScanReadinessModel === "function"
        ? new ScanReadinessModel({
            storageKey: String(options.readinessStorageKey || "naap-scan-readiness-v1")
          })
        : null;

      if (typeof BarcodeDetector !== "undefined") {
        this.detector = new BarcodeDetector({ formats: ["qr_code"] });
      }
    }

    static async getCameras() {
      if (!navigator.mediaDevices || !navigator.mediaDevices.enumerateDevices) return [];
      const devices = await navigator.mediaDevices.enumerateDevices();
      return devices
        .filter((device) => device.kind === "videoinput")
        .map((device, index) => ({
          id: device.deviceId,
          label: device.label || `Camera ${index + 1}`
        }));
    }

    getState() {
      return this.state;
    }

    async start(cameraConfig, _scanConfig, onSuccess, onFailure) {
      this.onSuccess = typeof onSuccess === "function" ? onSuccess : null;
      this.onFailure = typeof onFailure === "function" ? onFailure : null;

      await this.stop().catch(() => null);
      this.container.innerHTML = "";

      this.video = document.createElement("video");
      this.video.setAttribute("playsinline", "true");
      this.video.muted = true;
      this.video.autoplay = true;
      this.video.style.width = "100%";
      this.video.style.height = "auto";
      this.video.style.display = "block";
      this.container.appendChild(this.video);

      const baseVideo = {
        width: { ideal: 1920 },
        height: { ideal: 1080 },
        frameRate: { ideal: 30, min: 15 }
      };

      let mediaConstraints = { video: baseVideo, audio: false };
      if (typeof cameraConfig === "string") {
        mediaConstraints.video = { ...baseVideo, deviceId: { exact: cameraConfig } };
      } else if (cameraConfig && typeof cameraConfig === "object" && cameraConfig.facingMode) {
        mediaConstraints.video = { ...baseVideo, facingMode: cameraConfig.facingMode };
      } else {
        mediaConstraints.video = { ...baseVideo, facingMode: { ideal: "environment" } };
      }

      this.stream = await navigator.mediaDevices.getUserMedia(mediaConstraints);
      this.video.srcObject = this.stream;
      await this.video.play();

      // Continuous autofocus materially improves reads from vehicle stickers at
      // changing distances. Unsupported constraints are ignored safely.
      const videoTrack = this.stream.getVideoTracks()[0] || null;
      if (videoTrack && typeof videoTrack.getCapabilities === "function" && typeof videoTrack.applyConstraints === "function") {
        try {
          const capabilities = videoTrack.getCapabilities() || {};
          const advanced = {};
          if (Array.isArray(capabilities.focusMode) && capabilities.focusMode.includes("continuous")) {
            advanced.focusMode = "continuous";
          }
          if (Array.isArray(capabilities.exposureMode) && capabilities.exposureMode.includes("continuous")) {
            advanced.exposureMode = "continuous";
          }
          if (Array.isArray(capabilities.whiteBalanceMode) && capabilities.whiteBalanceMode.includes("continuous")) {
            advanced.whiteBalanceMode = "continuous";
          }
          if (Object.keys(advanced).length) {
            await videoTrack.applyConstraints({ advanced: [advanced] });
          }
        } catch (_constraintError) {
          // Camera still works when a browser rejects optional advanced modes.
        }
      }

      this.state = STATE.SCANNING;
      this.lastFrameAt = 0;
      this.lastDecodedAt = 0;
      this.lastDecodedText = "";
      this.frameCounter = 0;
      this.lastDetectedRegion = null;
      this.startLoop();
      return null;
    }

    startLoop() {
      const frameIntervalMs = 1000 / this.options.targetFps;

      const tick = async (now) => {
        if (this.state === STATE.NOT_STARTED || this.state === STATE.UNKNOWN) return;
        if (this.state === STATE.PAUSED) {
          this.rafId = requestAnimationFrame(tick);
          return;
        }
        if (this.processing) {
          this.rafId = requestAnimationFrame(tick);
          return;
        }
        if (now - this.lastFrameAt < frameIntervalMs) {
          this.rafId = requestAnimationFrame(tick);
          return;
        }

        this.lastFrameAt = now;
        this.processing = true;
        try {
          await this.processFrame(now);
        } catch (error) {
          if (this.onFailure) this.onFailure(error);
        } finally {
          this.processing = false;
          this.rafId = requestAnimationFrame(tick);
        }
      };

      this.rafId = requestAnimationFrame(tick);
    }

    measureRegion(detection, width, height) {
      if (!detection?.detection || !detection.rect) {
        this.lastDetectedRegion = null;
        return { areaRatio: null, detectedRegion: false, stabilityScore: 0.18 };
      }

      const rect = normalizeRect(detection.rect, width, height);
      const areaRatio = clamp((rect.width * rect.height) / (width * height), 0, 1);
      const current = {
        x: (rect.x + (rect.width / 2)) / width,
        y: (rect.y + (rect.height / 2)) / height,
        area: areaRatio
      };
      let stabilityScore = 0.58;

      if (this.lastDetectedRegion) {
        const positionDelta = Math.hypot(
          current.x - this.lastDetectedRegion.x,
          current.y - this.lastDetectedRegion.y
        );
        const areaDelta = Math.abs(current.area - this.lastDetectedRegion.area)
          / Math.max(0.02, current.area, this.lastDetectedRegion.area);
        stabilityScore = clamp(1 - ((positionDelta * 4.2) + (areaDelta * 0.75)), 0, 1);
      }

      this.lastDetectedRegion = current;
      return { areaRatio, detectedRegion: true, stabilityScore };
    }

    recordMetrics(confidence, started, details = {}) {
      this.lastProcessDurationMs = performance.now() - started;
      this.frameCounter += 1;
      const metrics = {
        confidence,
        threshold: this.options.confidenceThreshold,
        processMs: Math.round(this.lastProcessDurationMs),
        fps: this.lastProcessDurationMs > 0 ? Math.round(1000 / this.lastProcessDurationMs) : 0,
        usedDetector: !!this.detector,
        ...details
      };

      if (this.readinessModel) {
        let assessment = this.readinessModel.assess(metrics);
        const succeeded = details.scanSucceeded === true;
        const candidatePresent = details.detectedRegion === true
          || confidence >= (this.options.confidenceThreshold * 0.78);
        if (succeeded) {
          assessment = this.readinessModel.observe(metrics, true, 1);
        } else if (candidatePresent && this.frameCounter % 6 === 0) {
          // Failed frames are sampled lightly so an empty camera view cannot
          // overwhelm the much more valuable successful-read examples.
          assessment = this.readinessModel.observe(metrics, false, details.detectedRegion ? 0.35 : 0.12);
        }
        metrics.readinessScore = assessment.score;
        metrics.readinessGuidance = assessment.guidance;
        metrics.learningSamples = assessment.samples;
        metrics.learningTrained = assessment.trained;
        metrics.learningAccuracy = assessment.accuracy;
      }

      delete metrics.scanSucceeded;
      this.lastMlMetrics = metrics;
      if (this.options.onMlMetrics) {
        this.options.onMlMetrics(metrics);
      }
      return metrics;
    }

    emitDecoded(decodedText, now, confidence, model, preprocess) {
      const text = String(decodedText || "").trim();
      if (!text) return false;
      if (text === this.lastDecodedText && (now - this.lastDecodedAt) < this.options.duplicateSuppressMs) {
        return false;
      }

      this.lastDecodedText = text;
      this.lastDecodedAt = now;

      if (this.onSuccess) {
        this.onSuccess(text, {
          ml_confidence: Math.round(confidence * 1000) / 1000,
          preprocess,
          model,
          process_ms: Math.round(this.lastProcessDurationMs),
          readiness_score: this.lastMlMetrics?.readinessScore ?? null,
          readiness_guidance: this.lastMlMetrics?.readinessGuidance ?? null,
          learning_samples: this.lastMlMetrics?.learningSamples ?? 0,
          learning_trained: this.lastMlMetrics?.learningTrained === true
        });
      }
      return true;
    }

    async processFrame(now) {
      if (!this.video || this.video.readyState < 2 || !this.rawCtx) return;

      const videoWidth = this.video.videoWidth || 0;
      const videoHeight = this.video.videoHeight || 0;
      if (!videoWidth || !videoHeight) return;

      const scale = Math.min(1, this.options.maxProcessWidth / videoWidth);
      const width = Math.max(160, Math.round(videoWidth * scale));
      const height = Math.max(120, Math.round(videoHeight * scale));

      if (this.rawCanvas.width !== width || this.rawCanvas.height !== height) {
        this.rawCanvas.width = width;
        this.rawCanvas.height = height;
      }

      this.rawCtx.drawImage(this.video, 0, 0, width, height);

      const started = performance.now();
      let bestDetection = null;
      if (this.detector) {
        try {
          const detections = await this.detector.detect(this.rawCanvas);
          bestDetection = pickBestDetection(detections, width, height);
        } catch (_detectorError) {
          // Disable detector if the browser reports runtime support issues.
          this.detector = null;
        }
      }

      const regionQuality = this.measureRegion(bestDetection, width, height);

      const nativeDecodedText = String(bestDetection?.detection?.rawValue || bestDetection?.detection?.raw_value || "").trim();
      if (nativeDecodedText) {
        const confidence = 0.98;
        this.recordMetrics(confidence, started, { ...regionQuality, scanSucceeded: true });
        this.emitDecoded(nativeDecodedText, now, confidence, "BarcodeDetector-native", {
          contrast_normalization: false,
          adaptive_thresholding: false,
          perspective_correction: false,
          quiet_zone_padding: false
        });
        return;
      }

      const frame = this.rawCtx.getImageData(0, 0, width, height);

      // Most well-lit QR codes decode directly. Return immediately so the more
      // expensive contrast, threshold, crop, and perspective passes are only
      // used for difficult frames.
      let fastDecodeResult = null;
      try {
        fastDecodeResult = jsQR(frame.data, width, height, { inversionAttempts: "dontInvert" });
      } catch (_fastDecodeError) {
        fastDecodeResult = null;
      }
      if (fastDecodeResult?.data) {
        const confidence = 0.9;
        this.recordMetrics(confidence, started, { ...regionQuality, scanSucceeded: true });
        this.emitDecoded(fastDecodeResult.data, now, confidence, "jsQR-fast", {
          contrast_normalization: false,
          adaptive_thresholding: false,
          perspective_correction: false,
          quiet_zone_padding: false
        });
        return;
      }

      const luma = rgbToLuma(frame);
      const brightness = estimateMeanLuma(luma);
      const normalized = normalizeContrast(luma);
      const binary = adaptiveThreshold(normalized, width, height, 19, 7);

      if (!bestDetection) {
        bestDetection = {
          detection: null,
          rect: {
            x: 0,
            y: 0,
            width,
            height
          },
          corners: null,
          detectorScore: 0.28
        };
      }

      bestDetection.rect = normalizeRect(bestDetection.rect, width, height);

      const areaRatio = clamp((bestDetection.rect.width * bestDetection.rect.height) / (width * height), 0, 1);
      const shapeRatio = bestDetection.rect.width / bestDetection.rect.height;
      const shapeScore = 1 - clamp(Math.abs(Math.log(shapeRatio)) / 1.1, 0, 1);
      const contrastStd = averageLumaStd(normalized, width, height, bestDetection.rect);
      const contrastScore = clamp(contrastStd / 78, 0, 1);
      const edgeDensity = estimateEdgeDensity(binary, width, height, bestDetection.rect);
      const edgeScore = clamp(edgeDensity / 0.42, 0, 1);

      let confidence = clamp(
        (bestDetection.detectorScore * 0.38)
          + (areaRatio * 0.18)
          + (shapeScore * 0.14)
          + (contrastScore * 0.15)
          + (edgeScore * 0.15),
        0,
        1
      );
      const qualityDetails = {
        brightness,
        areaRatio: bestDetection.detection ? areaRatio : null,
        detectedRegion: !!bestDetection.detection,
        stabilityScore: regionQuality.stabilityScore,
        contrastScore,
        edgeScore,
        shapeScore
      };

      const learnedReadiness = this.readinessModel
        ? this.readinessModel.assess({ confidence, ...qualityDetails }).score
        : null;
      const adaptiveThreshold = learnedReadiness !== null && learnedReadiness >= 0.68
        ? this.options.confidenceThreshold * 0.84
        : this.options.confidenceThreshold;

      const lowConfidenceThreshold = adaptiveThreshold * this.options.lowConfidenceDecodeRatio;
      const retryInterval = learnedReadiness !== null && learnedReadiness >= 0.6 ? 5 : 10;
      const allowLowConfidenceAttempt = ((this.frameCounter + 1) % retryInterval === 0)
        && confidence >= lowConfidenceThreshold;
      if (confidence < adaptiveThreshold && !allowLowConfidenceAttempt) {
        this.recordMetrics(confidence, started, { ...qualityDetails, scanSucceeded: false });
        return;
      }

      let decodeResult = null;

      if (bestDetection.corners) {
        const warped = rectifyQuadBilinear(
          normalized,
          width,
          height,
          bestDetection.corners,
          this.options.perspectiveSize
        );
        decodeResult = decodeQrFromGray(warped, this.options.perspectiveSize, this.options.perspectiveSize);
      }

      if (!decodeResult) {
        // Preserve a quiet zone around the QR. Cropping directly on the native
        // bounding box can remove the white border required by decoders.
        const paddedRect = expandRect(bestDetection.rect, width, height, 0.16);
        const crop = cropRect(normalized, width, height, paddedRect);
        decodeResult = decodeQrFromGray(crop.gray, crop.width, crop.height);
      }

      // Fallback to full-frame decoding so off-center codes can still be detected.
      if (!decodeResult && (bestDetection.rect.width < width || bestDetection.rect.height < height)) {
        decodeResult = decodeQrFromGray(normalized, width, height);
      }

      if (!decodeResult || !decodeResult.data) {
        this.recordMetrics(confidence, started, { ...qualityDetails, scanSucceeded: false });
        return;
      }

      this.recordMetrics(confidence, started, { ...qualityDetails, scanSucceeded: true });

      this.emitDecoded(
        decodeResult.data,
        now,
        confidence,
        this.detector ? "BarcodeDetector+jsQR" : "jsQR-fallback",
        {
          contrast_normalization: true,
          adaptive_thresholding: true,
          perspective_correction: !!bestDetection.corners,
          quiet_zone_padding: true
        }
      );
    }

    async pause() {
      if (this.state !== STATE.SCANNING) return;
      this.state = STATE.PAUSED;
    }

    async resume() {
      if (this.state !== STATE.PAUSED) return;
      this.state = STATE.SCANNING;
    }

    async stop() {
      if (this.rafId) {
        cancelAnimationFrame(this.rafId);
        this.rafId = null;
      }

      if (this.stream) {
        for (const track of this.stream.getTracks()) {
          track.stop();
        }
      }

      this.stream = null;
      this.video = null;
      this.state = STATE.NOT_STARTED;
    }

    async clear() {
      this.container.innerHTML = "";
    }
  }

  MLQrCodeScanner.STATE = STATE;
  return MLQrCodeScanner;
}));
