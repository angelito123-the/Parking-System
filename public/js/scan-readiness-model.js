(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) {
    module.exports = api;
  }
  if (root) {
    root.ScanReadinessModel = api.ScanReadinessModel;
  }
}(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  const MODEL_VERSION = 1;
  const FEATURE_NAMES = Object.freeze([
    "brightness",
    "contrast",
    "sharpness",
    "size",
    "stability",
    "confidence"
  ]);
  const DEFAULT_WEIGHTS = Object.freeze({
    bias: -2.1,
    brightness: 0.8,
    contrast: 1.1,
    sharpness: 0.8,
    size: 1.1,
    stability: 0.9,
    confidence: 1.4
  });

  function clamp(value, min, max) {
    return Math.max(min, Math.min(max, value));
  }

  function finiteNumber(value) {
    const number = Number(value);
    return Number.isFinite(number) ? number : null;
  }

  function sigmoid(value) {
    if (value >= 0) {
      const exp = Math.exp(-value);
      return 1 / (1 + exp);
    }
    const exp = Math.exp(value);
    return exp / (1 + exp);
  }

  function brightnessQuality(value) {
    const brightness = finiteNumber(value);
    if (brightness === null) return 0.55;
    if (brightness <= 135) return clamp(brightness / 135, 0, 1);
    return clamp(1 - ((brightness - 135) / 120), 0, 1);
  }

  function normalizeFeatures(metrics) {
    const data = metrics || {};
    const confidence = clamp(finiteNumber(data.confidence) ?? 0, 0, 1);
    const detected = data.detectedRegion === true;
    const areaRatio = finiteNumber(data.areaRatio);
    const contrastScore = finiteNumber(data.contrastScore);
    const edgeScore = finiteNumber(data.edgeScore);
    const stabilityScore = finiteNumber(data.stabilityScore);

    return {
      brightness: brightnessQuality(data.brightness),
      contrast: clamp(contrastScore ?? (0.25 + (confidence * 0.55)), 0, 1),
      sharpness: clamp(edgeScore ?? (0.25 + (confidence * 0.5)), 0, 1),
      size: areaRatio === null
        ? (detected ? 0.35 : 0.12)
        : clamp(areaRatio / 0.18, 0, 1),
      stability: clamp(stabilityScore ?? (detected ? 0.55 : 0.18), 0, 1),
      confidence
    };
  }

  function recommendationFor(features, weights, detected) {
    if (features.brightness < 0.43 || features.contrast < 0.28) return "lighting";
    if (detected && features.size < 0.4) return "closer";

    const guidanceByFeature = {
      brightness: "lighting",
      contrast: "lighting",
      sharpness: "steady",
      size: detected ? "closer" : "center",
      stability: "steady",
      confidence: detected ? "steady" : "center"
    };
    let strongestDeficit = -1;
    let recommendation = detected ? "steady" : "center";

    for (const name of FEATURE_NAMES) {
      const learnedImportance = clamp(Math.abs(finiteNumber(weights[name]) ?? 0.5), 0.2, 3);
      const deficit = (1 - features[name]) * learnedImportance;
      if (deficit > strongestDeficit) {
        strongestDeficit = deficit;
        recommendation = guidanceByFeature[name];
      }
    }
    return recommendation;
  }

  class ScanReadinessModel {
    constructor(options) {
      const config = options || {};
      this.storageKey = String(config.storageKey || "naap-scan-readiness-v1");
      this.storage = config.storage || (typeof localStorage !== "undefined" ? localStorage : null);
      this.baseLearningRate = clamp(finiteNumber(config.learningRate) ?? 0.12, 0.01, 0.5);
      this.weights = { ...DEFAULT_WEIGHTS };
      this.samples = 0;
      this.successes = 0;
      this.failures = 0;
      this.correct = 0;
      this.lastSavedSample = 0;
      this.load();
    }

    load() {
      if (!this.storage || typeof this.storage.getItem !== "function") return;
      try {
        const saved = JSON.parse(this.storage.getItem(this.storageKey) || "null");
        if (!saved || saved.version !== MODEL_VERSION || !saved.weights) return;
        const loadedWeights = { ...DEFAULT_WEIGHTS };
        for (const name of ["bias", ...FEATURE_NAMES]) {
          const value = finiteNumber(saved.weights[name]);
          if (value !== null) loadedWeights[name] = clamp(value, -3, 3);
        }
        this.weights = loadedWeights;
        this.samples = Math.max(0, Math.floor(finiteNumber(saved.samples) ?? 0));
        this.successes = Math.max(0, Math.floor(finiteNumber(saved.successes) ?? 0));
        this.failures = Math.max(0, Math.floor(finiteNumber(saved.failures) ?? 0));
        this.correct = Math.max(0, Math.floor(finiteNumber(saved.correct) ?? 0));
        this.lastSavedSample = this.samples;
      } catch (_error) {
        // A corrupt or blocked localStorage entry should never stop scanning.
      }
    }

    save(force) {
      if (!this.storage || typeof this.storage.setItem !== "function") return;
      if (!force && this.samples - this.lastSavedSample < 6) return;
      try {
        this.storage.setItem(this.storageKey, JSON.stringify({
          version: MODEL_VERSION,
          weights: this.weights,
          samples: this.samples,
          successes: this.successes,
          failures: this.failures,
          correct: this.correct
        }));
        this.lastSavedSample = this.samples;
      } catch (_error) {
        // Private browsing and full storage are safe, non-fatal fallbacks.
      }
    }

    assess(metrics) {
      const features = normalizeFeatures(metrics);
      let logit = this.weights.bias;
      for (const name of FEATURE_NAMES) {
        logit += this.weights[name] * features[name];
      }
      const score = clamp(sigmoid(logit), 0.01, 0.99);
      return {
        score,
        guidance: recommendationFor(features, this.weights, metrics?.detectedRegion === true),
        features,
        samples: this.samples,
        trained: this.samples >= 12,
        accuracy: this.samples ? this.correct / this.samples : null
      };
    }

    observe(metrics, succeeded, sampleWeight) {
      const label = succeeded ? 1 : 0;
      const weight = clamp(finiteNumber(sampleWeight) ?? 1, 0.05, 1);
      const before = this.assess(metrics);
      const error = label - before.score;
      const learningRate = this.baseLearningRate / Math.sqrt(1 + (this.samples / 80));

      this.weights.bias = clamp(this.weights.bias + (learningRate * weight * error), -3, 3);
      for (const name of FEATURE_NAMES) {
        const regularization = 0.0004 * this.weights[name];
        const update = (error * before.features[name]) - regularization;
        this.weights[name] = clamp(this.weights[name] + (learningRate * weight * update), -3, 3);
      }

      this.samples += 1;
      if (label) this.successes += 1;
      else this.failures += 1;
      if ((before.score >= 0.5) === Boolean(label)) this.correct += 1;
      this.save(Boolean(label));
      return this.assess(metrics);
    }

    getStatus() {
      return {
        version: MODEL_VERSION,
        samples: this.samples,
        successes: this.successes,
        failures: this.failures,
        trained: this.samples >= 12,
        accuracy: this.samples ? this.correct / this.samples : null
      };
    }
  }

  return {
    ScanReadinessModel,
    normalizeFeatures,
    brightnessQuality,
    MODEL_VERSION
  };
}));
