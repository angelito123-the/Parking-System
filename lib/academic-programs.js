const ACADEMIC_PROGRAM_GROUPS = Object.freeze([
  Object.freeze({
    institute: "Institute of Engineering and Technology (InET)",
    programs: Object.freeze([
      Object.freeze({
        name: "Bachelor of Science in Aeronautical Engineering",
        code: "BSAeE"
      }),
      Object.freeze({
        name: "Bachelor of Science in Air Transportation Major in Advance Flying",
        code: "BSAT"
      }),
      Object.freeze({
        name: "Bachelor of Science in Aircraft Maintenance Technology",
        code: "BSAMT"
      }),
      Object.freeze({
        name: "Bachelor of Science in Aviation Electronics Technology",
        code: "BSAET"
      }),
      Object.freeze({
        name: "Associate in Aircraft Maintenance Technology",
        code: "AAMT"
      }),
      Object.freeze({
        name: "Associate in Aviation Electronics Technology",
        code: "AAET"
      })
    ])
  }),
  Object.freeze({
    institute: "Institute of Liberal Arts and Sciences (ILAS)",
    programs: Object.freeze([
      Object.freeze({
        name: "Bachelor of Science in Aviation Communication Major in Flight Operations",
        code: "BSAvCom"
      }),
      Object.freeze({
        name: "Bachelor of Science in Aviation Tourism Major in Travel Management",
        code: "BSAvTour"
      }),
      Object.freeze({
        name: "Bachelor of Science in Supply Management with Specialization in Aviation Logistics",
        code: ""
      }),
      Object.freeze({
        name: "Bachelor of Science in Aviation Safety and Security Management",
        code: "BSAvSSM"
      })
    ])
  }),
  Object.freeze({
    institute: "Institute of Computer Studies (ICS)",
    programs: Object.freeze([
      Object.freeze({
        name: "Bachelor of Science in Information Technology with Specialization in Aviation Information Technology",
        code: "BSIT-AIT"
      }),
      Object.freeze({
        name: "Bachelor of Science in Information Systems with Specialization in Aviation Information Systems",
        code: "BSIS-AIS"
      })
    ])
  })
]);

const ACADEMIC_PROGRAMS = Object.freeze(
  ACADEMIC_PROGRAM_GROUPS.flatMap((group) => group.programs)
);

const YEAR_LEVELS = Object.freeze([
  Object.freeze({ value: "1", label: "1st Year" }),
  Object.freeze({ value: "2", label: "2nd Year" }),
  Object.freeze({ value: "3", label: "3rd Year" }),
  Object.freeze({ value: "4", label: "4th Year" }),
  Object.freeze({ value: "5", label: "5th Year" })
]);

const ACADEMIC_PROGRAM_NAMES = new Set(ACADEMIC_PROGRAMS.map((program) => program.name));
const YEAR_LEVEL_VALUES = new Set(YEAR_LEVELS.map((year) => year.value));

const LEGACY_COURSE_ALIASES = new Map();
ACADEMIC_PROGRAMS.forEach((program) => {
  if (program.code) LEGACY_COURSE_ALIASES.set(normalizeCourseKey(program.code), program.name);
  LEGACY_COURSE_ALIASES.set(normalizeCourseKey(program.name), program.name);
});

// Previously used by the project for Aviation Information Systems records.
LEGACY_COURSE_ALIASES.set(
  "BSAIS",
  "Bachelor of Science in Information Systems with Specialization in Aviation Information Systems"
);

function normalizeCourseKey(value) {
  return String(value || "")
    .trim()
    .toUpperCase()
    .replace(/[^A-Z0-9]/g, "");
}

function isValidAcademicProgram(value) {
  return ACADEMIC_PROGRAM_NAMES.has(String(value || "").trim());
}

function isValidYearLevel(value) {
  return YEAR_LEVEL_VALUES.has(String(value || "").trim());
}

function findAcademicProgram(value) {
  const rawValue = String(value || "").trim();
  if (!rawValue) return null;

  const officialName = LEGACY_COURSE_ALIASES.get(normalizeCourseKey(rawValue)) || rawValue;
  return ACADEMIC_PROGRAMS.find((program) => program.name === officialName) || null;
}

function getYearLevelLabel(value) {
  const rawValue = String(value || "").trim();
  return YEAR_LEVELS.find((year) => year.value === rawValue)?.label || "";
}

function splitLegacyAcademicValue(program, yearLevel) {
  const rawProgram = String(program || "").trim();
  const rawYearLevel = String(yearLevel || "").trim();
  if (!rawProgram) {
    return { program: "", yearLevel: isValidYearLevel(rawYearLevel) ? rawYearLevel : "" };
  }

  let coursePart = rawProgram;
  let parsedYearLevel = isValidYearLevel(rawYearLevel) ? rawYearLevel : "";

  if (!parsedYearLevel) {
    const combinedMatch = rawProgram.match(/^(.+?)\s+([1-5])(?:\s*[-–]\s*[A-Za-z0-9]+)?$/i);
    if (combinedMatch) {
      coursePart = combinedMatch[1].trim();
      parsedYearLevel = combinedMatch[2];
    }
  }

  const officialProgram = LEGACY_COURSE_ALIASES.get(normalizeCourseKey(coursePart)) || coursePart;
  return { program: officialProgram, yearLevel: parsedYearLevel };
}

module.exports = {
  ACADEMIC_PROGRAM_GROUPS,
  ACADEMIC_PROGRAMS,
  YEAR_LEVELS,
  findAcademicProgram,
  getYearLevelLabel,
  isValidAcademicProgram,
  isValidYearLevel,
  splitLegacyAcademicValue
};
