const {
  findAcademicProgram,
  isValidYearLevel
} = require("./academic-programs");

const STUDENT_IMPORT_COLUMNS = Object.freeze([
  "student_number",
  "full_name",
  "program",
  "year_level",
  "email"
]);
const STUDENT_IMPORT_REQUIRED_COLUMNS = Object.freeze([
  "student_number",
  "full_name",
  "program",
  "year_level"
]);

function normalizeYearLevel(value) {
  const raw = String(value || "").trim();
  if (isValidYearLevel(raw)) return raw;
  const match = raw.match(/^([1-5])(?:st|nd|rd|th)?(?:\s+year)?$/i);
  return match && isValidYearLevel(match[1]) ? match[1] : "";
}

function isValidEmail(value) {
  const email = String(value || "").trim();
  if (!email) return true;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function validateStudentImportDocument(document, existingStudentNumbers = new Set()) {
  const headers = Array.isArray(document?.headers) ? document.headers : [];
  const records = Array.isArray(document?.records) ? document.records : [];
  const headerErrors = STUDENT_IMPORT_REQUIRED_COLUMNS
    .filter((column) => !headers.includes(column))
    .map((column) => `Missing required column: ${column}`);
  const headerWarnings = headers
    .filter((column) => !STUDENT_IMPORT_COLUMNS.includes(column))
    .map((column) => `Ignored column: ${column}`);
  const knownStudentNumbers = new Set(
    Array.from(existingStudentNumbers || []).map((value) => String(value || "").trim().toUpperCase())
  );
  const seenStudentNumbers = new Set();

  const rows = records.map((record) => {
    const issues = [];
    const studentNumber = String(record.student_number || "").trim();
    const fullName = String(record.full_name || "").trim().replace(/\s+/g, " ");
    const rawProgram = String(record.program || "").trim();
    const academicProgram = findAcademicProgram(rawProgram);
    const yearLevel = normalizeYearLevel(record.year_level);
    const email = String(record.email || "").trim();
    const studentKey = studentNumber.toUpperCase();

    if (Number(record.__columnCount) > headers.length) {
      issues.push(`Row has ${record.__columnCount} values but the header has ${headers.length} columns.`);
    }

    if (!studentNumber) issues.push("Student number is required.");
    else if (studentNumber.length > 50) issues.push("Student number exceeds 50 characters.");
    if (!fullName) issues.push("Full name is required.");
    else if (fullName.length > 150) issues.push("Full name exceeds 150 characters.");
    if (!rawProgram) issues.push("Course is required.");
    else if (!academicProgram) issues.push("Course is not in the official course list.");
    if (!String(record.year_level || "").trim()) issues.push("Year level is required.");
    else if (!yearLevel) issues.push("Year level must be 1 to 5.");
    if (email.length > 120) issues.push("Email exceeds 120 characters.");
    else if (!isValidEmail(email)) issues.push("Email format is invalid.");
    if (studentKey && seenStudentNumbers.has(studentKey)) {
      issues.push("Student number is duplicated in this file.");
    }
    if (studentKey) seenStudentNumbers.add(studentKey);

    const action = issues.length
      ? "invalid"
      : knownStudentNumbers.has(studentKey)
        ? "update"
        : "create";

    return {
      rowNumber: Number(record.__rowNumber) || 0,
      studentNumber,
      fullName,
      program: academicProgram?.name || rawProgram,
      programCode: academicProgram?.code || "",
      yearLevel,
      email,
      action,
      issues
    };
  });

  const invalidCount = rows.filter((row) => row.action === "invalid").length;
  const createCount = rows.filter((row) => row.action === "create").length;
  const updateCount = rows.filter((row) => row.action === "update").length;
  return {
    rows,
    headerErrors,
    headerWarnings,
    total: rows.length,
    invalidCount,
    validCount: rows.length - invalidCount,
    createCount,
    updateCount,
    canImport: rows.length > 0 && invalidCount === 0 && headerErrors.length === 0
  };
}

module.exports = {
  STUDENT_IMPORT_COLUMNS,
  STUDENT_IMPORT_REQUIRED_COLUMNS,
  normalizeYearLevel,
  validateStudentImportDocument
};
