(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
    return;
  }
  root.NaapUiState = factory();
}(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  const TYPES = new Set(["loading", "empty", "error", "success", "offline"]);
  const DEFAULTS = {
    loading: ["Loading", "Please wait while the latest information is retrieved."],
    empty: ["Nothing to show", "There are no records available right now."],
    error: ["Unable to load", "Please try again."],
    success: ["Completed", "The operation was completed successfully."],
    offline: ["You are offline", "Reconnect to load the latest information."]
  };

  function escapeHtml(value) {
    return String(value == null ? "" : value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function render(type, options = {}) {
    const safeType = TYPES.has(type) ? type : "empty";
    const defaults = DEFAULTS[safeType];
    const title = options.title === false ? "" : escapeHtml(options.title || defaults[0]);
    const message = options.message === false ? "" : escapeHtml(options.message || defaults[1]);
    const compactClass = options.compact ? " is-compact" : "";
    const role = safeType === "error" ? "alert" : "status";
    const visual = safeType === "loading"
      ? '<span class="ui-state-spinner"></span>'
      : '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="8"></circle><path d="M12 8v4"></path><path d="M12 16h.01"></path></svg>';

    return `<div class="ui-state ui-state-${safeType}${compactClass}" role="${role}" aria-live="polite">
      <span class="ui-state-visual" aria-hidden="true">${visual}</span>
      <div class="ui-state-copy">
        ${title ? `<strong>${title}</strong>` : ""}
        ${message ? `<p>${message}</p>` : ""}
      </div>
    </div>`;
  }

  return { escapeHtml, render };
}));
