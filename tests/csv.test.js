const test = require("node:test");
const assert = require("node:assert/strict");
const { parseCsv, stringifyCsv } = require("../lib/csv");

test("CSV backup round-trips quoted values and protects spreadsheets", () => {
  const columns = [{ key: "name", label: "name" }, { key: "note", label: "note" }];
  const csv = stringifyCsv(columns, [{ name: "Doe, Jane", note: "=HYPERLINK(\"bad\")" }]);
  assert.match(csv, /^\uFEFFname,note/);
  assert.match(csv, /'=HYPERLINK/);
  const [row] = parseCsv(csv);
  assert.equal(row.name, "Doe, Jane");
  assert.equal(row.note, "=HYPERLINK(\"bad\")");
});

test("CSV parser normalizes headers and rejects malformed files", () => {
  const [row] = parseCsv("Student ID,Full Name\r\n123,Angelito");
  assert.equal(row.student_id, "123");
  assert.equal(row.full_name, "Angelito");
  assert.throws(() => parseCsv('name\n"unclosed'));
  assert.throws(() => parseCsv("name,name\na,b"));
});

test("CSV parser enforces its data-row limit", () => {
  assert.throws(() => parseCsv("id\n1\n2", { maxRows: 1 }), /limited to 1/);
});
