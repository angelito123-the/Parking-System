'use strict';

const fs = require('fs');
const path = require('path');
const { PNG } = require('pngjs');

const OUTPUT_DIR = path.join(__dirname, '..', 'public', 'icons');
const SUPERSAMPLE = 4;

function interpolate(start, end, amount) {
  return start.map((value, index) => Math.round(value + ((end[index] - value) * amount)));
}

function setPixel(png, x, y, color) {
  if (x < 0 || y < 0 || x >= png.width || y >= png.height) return;
  const offset = ((y * png.width) + x) * 4;
  png.data[offset] = color[0];
  png.data[offset + 1] = color[1];
  png.data[offset + 2] = color[2];
  png.data[offset + 3] = 255;
}

function roundedRectContains(px, py, x, y, width, height, radius) {
  const right = x + width;
  const bottom = y + height;
  if (px < x || py < y || px >= right || py >= bottom) return false;
  const cx = px < x + radius ? x + radius : px >= right - radius ? right - radius : px;
  const cy = py < y + radius ? y + radius : py >= bottom - radius ? bottom - radius : py;
  const dx = px - cx;
  const dy = py - cy;
  return (dx * dx) + (dy * dy) <= radius * radius;
}

function drawRoundedRect(png, x, y, width, height, radius, colorAt) {
  const x0 = Math.max(0, Math.floor(x));
  const y0 = Math.max(0, Math.floor(y));
  const x1 = Math.min(png.width, Math.ceil(x + width));
  const y1 = Math.min(png.height, Math.ceil(y + height));
  for (let py = y0; py < y1; py += 1) {
    for (let px = x0; px < x1; px += 1) {
      if (roundedRectContains(px + 0.5, py + 0.5, x, y, width, height, radius)) {
        setPixel(png, px, py, typeof colorAt === 'function' ? colorAt(px, py) : colorAt);
      }
    }
  }
}

function drawEllipse(png, centerX, centerY, radiusX, radiusY, colorAt) {
  const x0 = Math.max(0, Math.floor(centerX - radiusX));
  const y0 = Math.max(0, Math.floor(centerY - radiusY));
  const x1 = Math.min(png.width, Math.ceil(centerX + radiusX));
  const y1 = Math.min(png.height, Math.ceil(centerY + radiusY));
  for (let py = y0; py < y1; py += 1) {
    for (let px = x0; px < x1; px += 1) {
      const dx = ((px + 0.5) - centerX) / radiusX;
      const dy = ((py + 0.5) - centerY) / radiusY;
      if ((dx * dx) + (dy * dy) <= 1) {
        setPixel(png, px, py, typeof colorAt === 'function' ? colorAt(px, py) : colorAt);
      }
    }
  }
}

function downsample(source, size, scale) {
  const output = new PNG({ width: size, height: size });
  const samples = scale * scale;
  for (let y = 0; y < size; y += 1) {
    for (let x = 0; x < size; x += 1) {
      const totals = [0, 0, 0, 0];
      for (let sy = 0; sy < scale; sy += 1) {
        for (let sx = 0; sx < scale; sx += 1) {
          const sourceOffset = ((((y * scale) + sy) * source.width) + ((x * scale) + sx)) * 4;
          totals[0] += source.data[sourceOffset];
          totals[1] += source.data[sourceOffset + 1];
          totals[2] += source.data[sourceOffset + 2];
          totals[3] += source.data[sourceOffset + 3];
        }
      }
      const outputOffset = ((y * size) + x) * 4;
      output.data[outputOffset] = Math.round(totals[0] / samples);
      output.data[outputOffset + 1] = Math.round(totals[1] / samples);
      output.data[outputOffset + 2] = Math.round(totals[2] / samples);
      output.data[outputOffset + 3] = Math.round(totals[3] / samples);
    }
  }
  return output;
}

function createIcon(size, { maskable = false } = {}) {
  const highSize = size * SUPERSAMPLE;
  const canvas = new PNG({ width: highSize, height: highSize });
  const navyTop = [17, 38, 63];
  const navyBottom = [9, 26, 45];
  const blueTop = [59, 130, 246];
  const blueBottom = [29, 78, 216];
  const white = [255, 255, 255];

  for (let y = 0; y < highSize; y += 1) {
    const rowColor = interpolate(navyTop, navyBottom, y / Math.max(1, highSize - 1));
    for (let x = 0; x < highSize; x += 1) setPixel(canvas, x, y, rowColor);
  }

  const margin = highSize * (maskable ? 0.22 : 0.12);
  const markSize = highSize - (margin * 2);
  const markColor = (_x, y) => interpolate(blueTop, blueBottom, Math.max(0, Math.min(1, (y - margin) / markSize)));
  drawRoundedRect(canvas, margin, margin, markSize, markSize, markSize * 0.22, markColor);

  const stemX = margin + (markSize * 0.285);
  const stemY = margin + (markSize * 0.235);
  drawRoundedRect(canvas, stemX, stemY, markSize * 0.105, markSize * 0.54, markSize * 0.052, white);

  const bowlX = margin + (markSize * 0.51);
  const bowlY = margin + (markSize * 0.39);
  drawEllipse(canvas, bowlX, bowlY, markSize * 0.225, markSize * 0.165, white);
  drawEllipse(canvas, bowlX, bowlY, markSize * 0.125, markSize * 0.073, markColor);

  return downsample(canvas, size, SUPERSAMPLE);
}

function writeIcon(filename, size, options) {
  const icon = createIcon(size, options);
  fs.writeFileSync(path.join(OUTPUT_DIR, filename), PNG.sync.write(icon));
}

fs.mkdirSync(OUTPUT_DIR, { recursive: true });
writeIcon('favicon-32.png', 32);
writeIcon('apple-touch-icon.png', 180);
writeIcon('icon-192.png', 192);
writeIcon('icon-512.png', 512);
writeIcon('icon-maskable-512.png', 512, { maskable: true });
console.log('Generated NAAP Parking PWA icons.');
