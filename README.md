# NAAP Parking Management System

Web app for National Aviation Academy of the Philippines student parking with QR sticker identity verification.

## Stack

- Node.js + Express
- EJS templates
- MySQL database
- QR image generation (`qrcode`)
- Browser camera scanning (`html5-qrcode`)

## Setup

1. Install dependencies:
   ```bash
   npm install
   ```
2. Create database tables:
   ```bash
   mysql -u root -p < sql/schema.sql
   ```
3. Copy env file and update values:
   ```bash
   copy .env.example .env
   ```
4. Start app:
   ```bash
   npm run dev
   ```
5. Open:
   `http://localhost:3000`

## Main Features

- Register students
- Register student vehicles
- Issue parking stickers with unique QR token
- View printable QR image per sticker
- Camera-based scanner page for gate officers
- Automatic phone camera QR detection mode with guard slot assignment
- Auto log each scan with result and entry/exit action
- Revoke stickers
- Reports module with date/gate filters
- CSV export for scan logs (thesis documentation ready)

## Routes

- `/` Dashboard and recent scans
- `/students` Manage students
- `/vehicles` Manage vehicles
- `/stickers` Issue/revoke stickers and view QR links
- `/scanner` Live camera QR scanner
- `/scanner/auto` Automatic gate phone camera scanner
- `/verify/:token` Manual verification endpoint
- `POST /api/scan` Scan API used by scanner page
- `POST /api/auto-scan/detect` Auto-detect QR and trigger ENTRY/EXIT flow
- `POST /api/auto-scan/confirm-entry` Guard-confirmed ENTRY save with slot assignment
- `/reports` Analytics page with filters and CSV export (`?format=csv`)

## Notes

- For production, add user authentication/roles for admin and guards.
- You can print stickers by opening each `/stickers/:id/qr` image and sending it to a label printer.
