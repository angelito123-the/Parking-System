const test = require("node:test");
const assert = require("node:assert/strict");
const { render } = require("../public/js/ui-states");

test("renders consistent accessible UI states", () => {
  assert.match(render("loading"), /ui-state-loading/);
  assert.match(render("error"), /role="alert"/);
  assert.match(render("offline", { compact: true }), /is-compact/);
});

test("escapes dynamic UI state content", () => {
  const html = render("error", { title: "Failed", message: "<script>alert(1)</script>" });
  assert.doesNotMatch(html, /<script>/);
  assert.match(html, /&lt;script&gt;/);
});
