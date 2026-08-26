const QRCode = require("qrcode");
const { PNG } = require("pngjs");

const QR_DARK = "#0f2942";
const QR_LIGHT = "#ffffff";
const BRAND_BLUE = [37, 99, 235, 255];
const WHITE = [255, 255, 255, 255];

const LETTERS = Object.freeze({
  A: ["01110", "10001", "10001", "11111", "10001", "10001", "10001"],
  N: ["10001", "11001", "10101", "10011", "10001", "10001", "10001"],
  P: ["11110", "10001", "10001", "11110", "10000", "10000", "10000"]
});

function fillPixel(png, x, y, color) {
  if (x < 0 || y < 0 || x >= png.width || y >= png.height) return;
  const offset = (png.width * y + x) << 2;
  png.data[offset] = color[0];
  png.data[offset + 1] = color[1];
  png.data[offset + 2] = color[2];
  png.data[offset + 3] = color[3];
}

function fillRect(png, x, y, width, height, color) {
  for (let py = y; py < y + height; py += 1) {
    for (let px = x; px < x + width; px += 1) {
      fillPixel(png, px, py, color);
    }
  }
}

function fillRoundedRect(png, x, y, width, height, radius, color) {
  const safeRadius = Math.max(0, Math.min(radius, Math.floor(Math.min(width, height) / 2)));
  for (let py = y; py < y + height; py += 1) {
    for (let px = x; px < x + width; px += 1) {
      const pointX = px + 0.5;
      const pointY = py + 0.5;
      const distanceX = Math.max(x + safeRadius - pointX, 0, pointX - (x + width - safeRadius));
      const distanceY = Math.max(y + safeRadius - pointY, 0, pointY - (y + height - safeRadius));
      if ((distanceX * distanceX) + (distanceY * distanceY) <= safeRadius * safeRadius) {
        fillPixel(png, px, py, color);
      }
    }
  }
}

function drawWord(png, word, centerX, startY, scale, color) {
  const glyphWidth = 5;
  const letterGap = 1;
  const totalUnits = (word.length * glyphWidth) + ((word.length - 1) * letterGap);
  const startX = Math.round(centerX - ((totalUnits * scale) / 2));

  [...word].forEach((letter, letterIndex) => {
    const glyph = LETTERS[letter];
    if (!glyph) return;
    const glyphX = startX + (letterIndex * (glyphWidth + letterGap) * scale);
    glyph.forEach((row, rowIndex) => {
      [...row].forEach((cell, columnIndex) => {
        if (cell !== "1") return;
        fillRect(
          png,
          glyphX + (columnIndex * scale),
          startY + (rowIndex * scale),
          scale,
          scale,
          color
        );
      });
    });
  });
}

function addNaapBadge(png) {
  const plateSize = Math.max(80, Math.round(png.width * 0.18));
  const plateX = Math.round((png.width - plateSize) / 2);
  const plateY = Math.round((png.height - plateSize) / 2);
  const plateRadius = Math.round(plateSize * 0.16);
  const inset = Math.max(7, Math.round(plateSize * 0.09));
  const badgeSize = plateSize - (inset * 2);

  fillRoundedRect(png, plateX, plateY, plateSize, plateSize, plateRadius, WHITE);
  fillRoundedRect(
    png,
    plateX + inset,
    plateY + inset,
    badgeSize,
    badgeSize,
    Math.round(badgeSize * 0.15),
    BRAND_BLUE
  );

  const textScale = Math.max(2, Math.floor(badgeSize / 30));
  const textHeight = 7 * textScale;
  drawWord(
    png,
    "NAAP",
    Math.round(png.width / 2),
    Math.round((png.height - textHeight) / 2),
    textScale,
    WHITE
  );
}

async function generateBrandedQrPng(payload, options = {}) {
  const value = String(payload || "").trim();
  if (!value) throw new Error("QR payload is required.");

  const requestedSize = Number(options.size) || 720;
  const size = Math.max(320, Math.min(1600, Math.round(requestedSize)));
  const baseQr = await QRCode.toBuffer(value, {
    type: "png",
    width: size,
    margin: 4,
    errorCorrectionLevel: "H",
    color: {
      dark: QR_DARK,
      light: QR_LIGHT
    }
  });
  const png = PNG.sync.read(baseQr);
  addNaapBadge(png);
  return PNG.sync.write(png);
}

module.exports = {
  generateBrandedQrPng
};
