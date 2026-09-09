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

- Role-based access control (Admin and Guard)
- Secure username-and-password login with hashed passwords, temporary-password changes, and account suspension
- Role-specific dashboards and dynamic navigation
- Register students
- Register student vehicles
- Issue parking stickers with unique QR token
- View printable QR image per sticker
- Preview and queue an active sticker QR code for delivery to the student's registered email address, with retry history
- Camera-based scanner page for gate officers
- Automatic phone camera QR detection mode with guard slot assignment
- Auto log each scan with result and entry/exit action
- Replace lost/exposed QR codes while immediately invalidating the previous code, or revoke the whole sticker
- Configure standard, accessibility, reserved, and temporarily disabled parking spaces
- Create and restore passphrase-protected encrypted backups
- Reports module with date/gate filters
- CSV export for scan logs (thesis documentation ready)

## Routes

- `/` Role-based redirect (Admin/Guard)
- `/admin` Admin dashboard
- `/admin/users` User management and role assignment
- `/guard` Guard dashboard
- `/students` Manage students (Admin)
- `/stickers` Issue/revoke stickers and view QR links (Admin)
- `POST /stickers/:id/email` Queue an active sticker QR image for email delivery (Admin)
- `/admin/slots` Configure parking spaces and capacity-warning thresholds (Admin)
- `/admin/data` Create, download, check, and restore encrypted backups (Admin)
- `/scanner` Live camera QR scanner (Guard/Admin)
- `/scanner/auto` Automatic gate phone camera scanner (Guard/Admin)
- `/verify/:token` Manual verification endpoint
- `POST /api/scan` Scan API used by scanner page (Guard/Admin)
- `POST /api/auto-scan/detect` Auto-detect QR and trigger ENTRY/EXIT flow (Guard/Admin)
- `POST /api/auto-scan/confirm-entry` Guard-confirmed ENTRY save with slot assignment (Guard/Admin)
- `/reports` Analytics page with filters and CSV export (`?format=csv`) (Admin)

## Notes

- Default users are seeded from `.env` values on startup.
- You can print stickers by opening each `/stickers/:id/qr` image and sending it to a label printer.
- QR email delivery requires `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, and `SMTP_FROM` in `.env`. Set `SMTP_SECURE=true` for implicit TLS (normally port 465); port 587 normally uses `false` and upgrades with STARTTLS.
- Production requires unique `ADMIN_PASSWORD`, `GUARD_PASSWORD`, and a `SESSION_SECRET` of at least 32 characters. Never commit real values to Git; rotate any value that was previously committed.
- `TRUST_PROXY_HOPS=1` is appropriate for the standard Render proxy setup. Change it only when the number of trusted reverse proxies in front of the app changes.
- Set `BACKUP_ENCRYPTION_KEY` to enable one encrypted backup per day. `BACKUP_EMAIL_TO` can send that encrypted file through the configured SMTP account. Manual encrypted backups remain available without these optional settings.
- Default retention is 30 days for scan snapshots, 365 days for gate records, 90 days for scanner diagnostics, 730 days for security audits, and 14 days for saved encrypted backups. Confirm these periods against the school's approved records policy before production use.
- Guard accounts are automatically suspended after 120 days without a sign-in in production unless `GUARD_INACTIVITY_DAYS` is changed or set to `0`.
- For a no-cost online deployment, follow [DEPLOY_FREE.md](./DEPLOY_FREE.md).
- Before using a phone or tablet at a gate, follow the [scanner device test checklist](./docs/SCANNER_DEVICE_TESTING.md).
