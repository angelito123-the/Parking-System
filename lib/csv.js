function sanitizeSpreadsheetCell(value) {
  const text = value == null ? "" : String(value);
  return /^[=+\-@]/.test(text) ? `'${text}` : text;
}

function escapeCsvCell(value) {
  const text = sanitizeSpreadsheetCell(value);
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

function stringifyCsv(columns, rows) {
  const safeColumns = Array.isArray(columns) ? columns : [];
  const safeRows = Array.isArray(rows) ? rows : [];
  const lines = [safeColumns.map((column) => escapeCsvCell(column.label || column.key)).join(",")];
  for (const row of safeRows) {
    lines.push(safeColumns.map((column) => escapeCsvCell(row?.[column.key])).join(","));
  }
  return `\uFEFF${lines.join("\r\n")}`;
}

function parseCsv(text, options = {}) {
  const maxRows = Math.max(1, Math.min(10000, Number(options.maxRows) || 2000));
  const input = String(text || "").replace(/^\uFEFF/, "");
  const rows = [];
  let row = [];
  let cell = "";
  let quoted = false;

  for (let index = 0; index < input.length; index += 1) {
    const character = input[index];
    if (quoted) {
      if (character === '"' && input[index + 1] === '"') {
        cell += '"';
        index += 1;
      } else if (character === '"') {
        quoted = false;
      } else {
        cell += character;
      }
      continue;
    }
    if (character === '"') quoted = true;
    else if (character === ",") {
      row.push(cell);
      cell = "";
    } else if (character === "\n") {
      row.push(cell.replace(/\r$/, ""));
      if (row.some((value) => String(value).trim())) rows.push(row);
      if (rows.length > maxRows + 1) throw new Error(`CSV is limited to ${maxRows} data rows.`);
      row = [];
      cell = "";
    } else {
      cell += character;
    }
  }
  if (quoted) throw new Error("CSV contains an unclosed quoted value.");
  row.push(cell.replace(/\r$/, ""));
  if (row.some((value) => String(value).trim())) rows.push(row);
  if (rows.length > maxRows + 1) throw new Error(`CSV is limited to ${maxRows} data rows.`);
  if (!rows.length) return [];

  const headers = rows[0].map((value) => String(value).trim().toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_|_$/g, ""));
  if (!headers.length || headers.some((header) => !header)) throw new Error("CSV header names are invalid.");
  if (new Set(headers).size !== headers.length) throw new Error("CSV contains duplicate headers.");
  return rows.slice(1).map((values, index) => {
    const record = { __rowNumber: index + 2 };
    headers.forEach((header, columnIndex) => {
      let value = String(values[columnIndex] ?? "").trim();
      if (/^'[=+\-@]/.test(value)) value = value.slice(1);
      record[header] = value;
    });
    return record;
  });
}

module.exports = {
  escapeCsvCell,
  parseCsv,
  sanitizeSpreadsheetCell,
  stringifyCsv
};
