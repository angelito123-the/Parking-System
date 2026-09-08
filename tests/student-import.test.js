const test = require("node:test");
const assert = require("node:assert/strict");
const { parseCsvDocument } = require("../lib/csv");
const { validateStudentImportDocument } = require("../lib/student-import");

const officialProgram = "Bachelor of Science in Information Systems with Specialization in Aviation Information Systems";

test("student CSV validation canonicalizes course codes and marks creates and updates", () => {
  const document = parseCsvDocument([
    "student_number,full_name,program,year_level,email",
    "2026-001,Student One,BSIS-AIS,1st Year,one@example.com",
    `2026-002,Student Two,${officialProgram},2,two@example.com`
  ].join("\n"));
  const result = validateStudentImportDocument(document, new Set(["2026-002"]));

  assert.equal(result.canImport, true);
  assert.equal(result.createCount, 1);
  assert.equal(result.updateCount, 1);
  assert.equal(result.rows[0].program, officialProgram);
  assert.equal(result.rows[0].yearLevel, "1");
});

test("student CSV validation blocks missing headers, invalid fields, and duplicates", () => {
  const missingHeader = validateStudentImportDocument(
    parseCsvDocument("student_number,full_name\n2026-001,Student One")
  );
  assert.equal(missingHeader.canImport, false);
  assert.match(missingHeader.headerErrors.join(" "), /program/);

  const invalidRows = validateStudentImportDocument(parseCsvDocument([
    "student_number,full_name,program,year_level,email",
    "2026-001,Student One,Not a course,8,not-an-email",
    "2026-001,Student Two,BSIS-AIS,2,two@example.com"
  ].join("\n")));
  assert.equal(invalidRows.canImport, false);
  assert.equal(invalidRows.invalidCount, 2);
  assert.match(invalidRows.rows[1].issues.join(" "), /duplicated/);
});

test("student CSV validation reports extra unheaded values", () => {
  const document = parseCsvDocument([
    "student_number,full_name,program,year_level",
    "2026-003,Student Three,BSIS-AIS,3,unexpected"
  ].join("\n"));
  const result = validateStudentImportDocument(document);
  assert.equal(result.canImport, false);
  assert.match(result.rows[0].issues.join(" "), /header has 4 columns/);
});
