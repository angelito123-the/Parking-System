(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
    return;
  }
  root.QRBehaviorClassifier = factory();
}(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  const SHORTENER_DOMAINS = new Set([
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "cutt.ly",
    "rebrand.ly",
    "tiny.cc",
    "buff.ly",
    "shorturl.at"
  ]);

  const KNOWN_SAFE_HOSTS = [
    "localhost",
    "127.0.0.1",
    "railway.app",
    "up.railway.app",
    "naap",
    "school.edu.ph"
  ];

  const MALICIOUS_SIGNATURES = [
    "javascript:",
    "data:text/html",
    "<script",
    "onerror=",
    "document.cookie",
    "window.location",
    "eval(",
    "atob(",
    "fromcharcode",
    "cmd=",
    "union select",
    "drop table"
  ];

  function clamp(value, min, max) {
    return Math.max(min, Math.min(max, value));
  }

  function sigmoid(z) {
    return 1 / (1 + Math.exp(-z));
  }

  function normalizeHost(hostname) {
    return String(hostname || "").trim().toLowerCase();
  }

  function looksLikeVerifyTokenPayload(text) {
    const raw = String(text || "").trim();
    if (!raw) return false;

    if (/^[a-f0-9]{24,}$/i.test(raw)) return true;

    try {
      const parsed = new URL(raw);
      return /^\/verify\/[a-z0-9_-]{12,}$/i.test(parsed.pathname || "");
    } catch (_error) {
      return false;
    }
  }

  function estimateEntropy(text) {
    const source = String(text || "");
    if (!source) return 0;

    const counts = new Map();
    for (const char of source) {
      counts.set(char, (counts.get(char) || 0) + 1);
    }

    let entropy = 0;
    const len = source.length;
    for (const count of counts.values()) {
      const p = count / len;
      entropy += -p * Math.log2(p);
    }
    return entropy;
  }

  function countRedirectLikeParams(url) {
    if (!url || !url.searchParams) return 0;
    const redirKeys = ["url", "target", "dest", "redirect", "next", "continue", "goto", "redir"];
    let count = 0;
    for (const key of redirKeys) {
      if (url.searchParams.has(key)) count += 1;
    }
    return count;
  }

  function hasLikelyBase64Payload(text) {
    const raw = String(text || "");
    if (!raw) return false;

    const chunks = raw.match(/[A-Za-z0-9+/=]{24,}/g) || [];
    if (!chunks.length) return false;

    for (const chunk of chunks) {
      if (chunk.length % 4 !== 0) continue;
      if (!/^[A-Za-z0-9+/=]+$/.test(chunk)) continue;
      try {
        const decoded = typeof atob === "function"
          ? atob(chunk)
          : Buffer.from(chunk, "base64").toString("utf8");

        if (/(https?:\/\/|<script|eval\(|function\s*\(|window\.|document\.)/i.test(decoded)) {
          return true;
        }
      } catch (_error) {
        // ignore invalid base64 chunks
      }
    }

    return false;
  }

  function extractUrls(text) {
    const raw = String(text || "");
    if (!raw) return [];

    const urlMatches = raw.match(/https?:\/\/[^\s"'<>]+/gi) || [];
    const urls = [];
    for (const maybeUrl of urlMatches) {
      try {
        urls.push(new URL(maybeUrl));
      } catch (_error) {
        // ignore malformed URL
      }
    }
    return urls;
  }

  function computeFeatures(inputText) {
    const text = String(inputText || "").trim();
    const lower = text.toLowerCase();
    const urls = extractUrls(text);

    let shortenerHits = 0;
    let ipUrlHits = 0;
    let httpOnlyHits = 0;
    let unknownDomainHits = 0;
    let suspiciousTldHits = 0;
    let redirectSignal = 0;

    for (const url of urls) {
      const host = normalizeHost(url.hostname);

      if (SHORTENER_DOMAINS.has(host)) shortenerHits += 1;
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) ipUrlHits += 1;
      if (url.protocol === "http:") httpOnlyHits += 1;
      if (countRedirectLikeParams(url) > 0) redirectSignal += 1;

      const safe = KNOWN_SAFE_HOSTS.some((safeHost) => host === safeHost || host.endsWith(`.${safeHost}`));
      if (!safe) unknownDomainHits += 1;

      if (/(\.zip|\.top|\.click|\.work|\.monster|\.xyz|\.icu)$/i.test(host)) {
        suspiciousTldHits += 1;
      }
    }

    const hasKnownBadSignature = MALICIOUS_SIGNATURES.some((sig) => lower.includes(sig));
    const multipleUrls = urls.length > 1;
    const entropy = estimateEntropy(text);
    const base64Payload = hasLikelyBase64Payload(text);
    const rawLength = text.length;

    const featureSet = {
      has_url: urls.length > 0 ? 1 : 0,
      uses_shortener: shortenerHits > 0 ? 1 : 0,
      ip_based_url: ipUrlHits > 0 ? 1 : 0,
      unknown_domain: unknownDomainHits > 0 ? 1 : 0,
      suspicious_tld: suspiciousTldHits > 0 ? 1 : 0,
      redirect_signal: redirectSignal > 0 ? 1 : 0,
      http_only: httpOnlyHits > 0 ? 1 : 0,
      multiple_urls: multipleUrls ? 1 : 0,
      known_bad_signature: hasKnownBadSignature ? 1 : 0,
      base64_payload: base64Payload ? 1 : 0,
      entropy_high: entropy >= 4.45 ? 1 : 0,
      long_payload: rawLength >= 140 ? 1 : 0,
      looks_verify_payload: looksLikeVerifyTokenPayload(text) ? 1 : 0,
      simple_token: /^[a-z0-9_-]{16,80}$/i.test(text) ? 1 : 0
    };

    return {
      text,
      urls,
      entropy,
      rawLength,
      features: featureSet
    };
  }

  const MODEL = Object.freeze({
    bias: -2.05,
    weights: Object.freeze({
      uses_shortener: 1.05,
      ip_based_url: 1.35,
      unknown_domain: 0.9,
      suspicious_tld: 0.85,
      redirect_signal: 1.1,
      http_only: 0.45,
      multiple_urls: 0.55,
      known_bad_signature: 2.3,
      base64_payload: 1.2,
      entropy_high: 0.6,
      long_payload: 0.35,
      looks_verify_payload: -1.45,
      simple_token: -0.75
    })
  });

  function scoreFeatures(featureSummary) {
    const features = featureSummary && featureSummary.features ? featureSummary.features : {};
    let z = MODEL.bias;

    for (const [name, weight] of Object.entries(MODEL.weights)) {
      z += (Number(features[name]) || 0) * weight;
    }

    return clamp(sigmoid(z), 0, 1);
  }

  function riskLevelFromScore(score) {
    if (score >= 0.72) return "high";
    if (score >= 0.42) return "medium";
    return "low";
  }

  function buildReasons(summary) {
    const f = summary.features || {};
    const reasons = [];

    if (f.known_bad_signature) reasons.push("Contains known malicious script/signature markers.");
    if (f.ip_based_url) reasons.push("Uses an IP-based URL instead of a domain.");
    if (f.uses_shortener && f.unknown_domain) reasons.push("Uses URL shortener with unknown final domain context.");
    if (f.redirect_signal) reasons.push("Contains redirect-like parameters.");
    if (f.base64_payload) reasons.push("Contains base64-like encoded payload.");
    if (f.suspicious_tld) reasons.push("Uses a high-risk top-level domain.");
    if (f.http_only) reasons.push("Uses non-HTTPS URL.");
    if (f.multiple_urls) reasons.push("Contains multiple URLs in one QR payload.");
    if (f.entropy_high && !f.looks_verify_payload) reasons.push("Payload appears highly obfuscated.");

    if (!reasons.length && f.looks_verify_payload) {
      reasons.push("Matches expected verify-token format.");
    }

    if (!reasons.length) {
      reasons.push("No strong anomaly patterns detected.");
    }

    return reasons;
  }

  function classify(inputText) {
    const summary = computeFeatures(inputText);
    const rawScore = scoreFeatures(summary);
    const riskScore = Math.round(rawScore * 100) / 100;
    const riskLevel = riskLevelFromScore(riskScore);
    const reasons = buildReasons(summary);

    return {
      riskScore,
      riskLevel,
      reasons,
      entropy: Math.round(summary.entropy * 100) / 100,
      length: summary.rawLength,
      features: summary.features
    };
  }

  return {
    classify,
    computeFeatures,
    scoreFeatures,
    riskLevelFromScore
  };
}));
