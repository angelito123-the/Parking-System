const test = require("node:test");
const assert = require("node:assert/strict");
const { parseCsv, parseCsvDocument, stringifyCsv } = require("../lib/csv");

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

test("CSV document parser returns normalized headers for server-side validation", () => {
  const document = parseCsvDocument("Student Number,Full Name\n2026-01,Student One");
  assert.deepEqual(document.headers, ["student_number", "full_name"]);
  assert.equal(document.records[0].__rowNumber, 2);
  assert.equal(document.records[0].__columnCount, 2);
});
