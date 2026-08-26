const test = require("node:test");
const assert = require("node:assert/strict");
const { serializeForScript } = require("../lib/serialize-for-script");

test("serializes inline data without allowing a script element breakout", () => {
  const serialized = serializeForScript({ value: "</script><script>alert(1)</script>&" });
  assert.doesNotMatch(serialized, /<|>|&/);
  assert.deepEqual(JSON.parse(serialized), { value: "</script><script>alert(1)</script>&" });
});

test("normalizes undefined inline values to null", () => {
  assert.equal(serializeForScript(undefined), "null");
});
