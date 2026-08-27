const test = require("node:test");
const assert = require("node:assert/strict");

const {
  ACADEMIC_PROGRAM_GROUPS,
  ACADEMIC_PROGRAMS,
  YEAR_LEVELS,
  findAcademicProgram,
  isValidAcademicProgram,
  isValidYearLevel,
  splitLegacyAcademicValue
} = require("../lib/academic-programs");

test("defines all official academic programs under their three institutes", () => {
  assert.equal(ACADEMIC_PROGRAM_GROUPS.length, 3);
  assert.equal(ACADEMIC_PROGRAMS.length, 12);
  assert.equal(new Set(ACADEMIC_PROGRAMS.map((program) => program.name)).size, 12);
});

test("validates official courses and supported year levels", () => {
  const informationSystems = ACADEMIC_PROGRAMS.find((program) => program.code === "BSIS-AIS");
  assert.ok(informationSystems);
  assert.equal(isValidAcademicProgram(informationSystems.name), true);
  assert.equal(isValidAcademicProgram("Unknown course"), false);
  assert.equal(YEAR_LEVELS.length, 5);
  assert.equal(isValidYearLevel("4"), true);
  assert.equal(isValidYearLevel("6"), false);
});

test("splits the legacy combined course and year format", () => {
  const result = splitLegacyAcademicValue("BSAIS 4-2", null);
  assert.equal(result.yearLevel, "4");
  assert.equal(
    result.program,
    "Bachelor of Science in Information Systems with Specialization in Aviation Information Systems"
  );
  assert.equal(findAcademicProgram(result.program)?.code, "BSIS-AIS");
});

test("preserves an existing separated year level", () => {
  const result = splitLegacyAcademicValue("BSAeE", "3");
  assert.equal(result.yearLevel, "3");
  assert.equal(result.program, "Bachelor of Science in Aeronautical Engineering");
});
