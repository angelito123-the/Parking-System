"use strict";

function serializeForScript(value) {
  const json = JSON.stringify(value);
  if (json === undefined) return "null";
  return json
    .replace(/&/g, "\\u0026")
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
}

module.exports = { serializeForScript };
