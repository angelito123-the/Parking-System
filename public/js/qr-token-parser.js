(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
    return;
  }
  root.QRTokenParser = factory();
}(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  function extract(input, baseUrl) {
    const raw = String(input == null ? "" : input).trim();
    if (!raw) return "";

    try {
      const fallbackBase = String(baseUrl || "http://localhost");
      const parsed = new URL(raw, fallbackBase);
      const parts = parsed.pathname.split("/").filter(Boolean);

      if (parts.length >= 3 && parts[0].toLowerCase() === "verify" && parts[1].toLowerCase() === "visitor") {
        return decodeURIComponent(parts[2]);
      }
      if (parts.length >= 2 && parts[0].toLowerCase() === "verify") {
        return decodeURIComponent(parts[1]);
      }
    } catch (_error) {
      // A raw sticker token is a supported QR payload.
    }

    return raw;
  }

  return { extract };
}));
