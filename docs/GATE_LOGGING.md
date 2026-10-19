# Gate-aware vehicle movements

This repository uses Express, MySQL/TiDB, EJS templates and browser JavaScript. Authentication uses the existing server session cookie. This change keeps that architecture, the existing Guard/Admin roles, camera detection, parking assignment and entry confirmation. It does not introduce React, JWT or a Student login role.

## Database and deployment

`sql/migrations/20261018-gate-logging.sql` adds `gates` and `vehicle_logs`. The normal database startup runs it before the server accepts requests. It can also be applied with the MySQL client to an existing, initialized database:

```sh
mysql --host="$DB_HOST" --port="$DB_PORT" --user="$DB_USER" --password "$DB_NAME" < sql/migrations/20261018-gate-logging.sql
```

Use your host's required TLS options when connecting to TiDB. Take a database backup before deployment. The application database user needs permission to create these tables, foreign keys and indexes. No existing table or column is dropped or renamed.

- Gate 1, Gate 2 and Gate 3 initially allow both directions. Gate 4 is exit-only. Gate 5 remains available with both directions for existing installations.
- Seed rows use `INSERT IGNORE`, so restarting does not reset configured directions.
- Admin dashboard → **Vehicle gate history → Configure gate directions** changes a gate to entry, exit or both. Guards should reload their scanner after configuration changes; the backend always validates the current setting.
- Existing authorized entry/exit rows are copied into the new history once, using a unique reference to `scan_logs.id`. The old records remain unchanged, including their timestamps and text gate names.
- Old Main/Side/North/South gate names map to Gate 1/2/3/4. Unknown historical identities remain nullable. Snapshot text preserves the plate, actor and gate if a related account or vehicle is deleted.
- The migration adds foreign keys for vehicle, actor, gate and original scan, plus indexes for vehicle/time, gate/time, time and scan type/time.
- Session pairing uses `LEAD` to select the immediately following movement, including ties ordered by log ID. It requires MySQL 8+, MariaDB 10.2+, or TiDB with window functions enabled. See [TiDB's supported window functions](https://docs.pingcap.com/tidb/stable/window-functions/). It avoids subqueries in `JOIN ON`, which TiDB does not support.
- The new history follows the existing `SCAN_LOG_RETENTION_DAYS` policy (365 days by default). It does not silently retain copies after the original scan history expires.
- Back up the full database, including the two new tables. Registration-only CSV recovery is not a movement-history backup.

## Recording a movement

1. A Guard signs in and selects the actual gate on the existing scanner or Manual Gate Tools page.
2. The backend verifies the QR, locks the vehicle state, and determines entry/exit from that vehicle's latest authorized movement. Replacement stickers therefore share one movement state.
3. Entry is allowed only at an entry/both gate, and exit only at an exit/both gate. Gate type validates the movement; it does not fabricate a missing entry.
4. Entry still needs a parking slot and confirmation. A phone's pending request keeps the gate where it was scanned, even if a monitor uses a different gate. Confirmation rechecks the gate setting.
5. The original scan, new movement and parking assignment/release are saved in one transaction. The existing `SCAN_COOLDOWN_SECONDS` setting defaults to 10 seconds.

The manual, camera, verification-form, legacy scan and offline-sync paths all populate registered-vehicle history. Offline movements retain their capture timestamps and are checked against current gate rules when synchronized. A conflicting offline item receives a rejected receipt instead of blocking the entire batch. Visitor passes retain their separate existing history; gate direction checks also apply to those movements. Administrative force exit is retained and is explicitly recorded without inventing a physical gate ID.

## APIs

Use the existing signed-in session cookie and same-origin requests. The actor is taken from the authenticated user, never from submitted `guard_id` values.

| Endpoint | Access | Purpose |
| --- | --- | --- |
| `GET /api/gates` | Admin, Guard | Read configured gate IDs, names and directions |
| `POST /api/gates/:id` | Admin | Change direction with `{ "type": "entry" }`, `exit`, or `both`; recorded in the security audit |
| `POST /api/scans` | Guard | Submit `{ "qr_data": "QR_TOKEN_OR_VERIFY_URL", "gate_id": 1, "slot_id": 12 }` |
| `GET /api/logs` | Admin, Guard | Paginated individual movements |
| `GET /api/vehicle-sessions` | Admin, Guard | Paginated paired entries/exits |
| `GET /api/vehicles/:id/latest-session` | Admin, Guard | Latest session, or `session: null` before any entry |

Read endpoints accept `page` (default 1), `limit` (default 25, maximum 100), `vehicle_id`, `vehicle` (plate prefix), `gate_id`, `date_from`, and `date_to`. Individual logs also accept `scan_type=entry|exit`. Dates use `YYYY-MM-DD` in Philippine time, including the entire end date. Session date filters apply to entry time, while its gate filter matches either end. JSON timestamps are UTC; the dashboard displays Philippine time.

### Example: Gate 1 entry, Gate 4 exit

IDs below are illustrative. Read `/api/gates` and `/api/parking-slots` to get actual IDs, and use a valid test QR for a vehicle currently outside.

```http
POST /api/scans
Content-Type: application/json

{"qr_data":"VALID_TEST_QR","gate_id":1,"slot_id":12}
```

Expected `201` response:

```json
{
  "ok": true,
  "movement_saved": true,
  "requires_confirmation": false,
  "message": "Entry recorded at Gate 1.",
  "scan": {
    "id": 101,
    "vehicle_id": 7,
    "guard_id": 2,
    "gate_id": 1,
    "gate_name": "Gate 1",
    "scan_type": "entry",
    "scanned_at": "2026-10-19T01:00:00.000Z"
  },
  "parking_slot": "A-01",
  "released_slot": null
}
```

Without `slot_id`, an entry returns `200`, `movement_saved: false` and `requires_confirmation: true`, plus the parking overview. No entry is saved until a slot is confirmed.

Wait at least the configured cooldown, then submit:

```http
POST /api/scans
Content-Type: application/json

{"qr_data":"VALID_TEST_QR","gate_id":4}
```

Expected `201` response:

```json
{
  "ok": true,
  "movement_saved": true,
  "requires_confirmation": false,
  "message": "Exit recorded at Gate 4.",
  "scan": {
    "id": 102,
    "vehicle_id": 7,
    "guard_id": 2,
    "gate_id": 4,
    "gate_name": "Gate 4",
    "scan_type": "exit",
    "scanned_at": "2026-10-19T02:00:00.000Z"
  },
  "parking_slot": null,
  "released_slot": "A-01"
}
```

`GET /api/vehicles/7/latest-session` should show `entry_gate: "Gate 1"`, `exit_gate: "Gate 4"`, both times, and both Guard names. The Admin and Guard dashboards display the same paired record.

A repeated scan inside the cooldown returns `409` with `code: "DUPLICATE_SCAN"`. Entry at Gate 4 returns `409` with `code: "GATE_DIRECTION_MISMATCH"`. Invalid QR/gate/filter inputs return `400`; unauthenticated requests return `401`; disallowed roles return `403`.

## Manual-entry troubleshooting and verification

- Open Guard dashboard → **Manual Gate Tools**, search for a valid vehicle, select it, choose an available slot, then select **Record ENTRY**. Success identifies the gate. Search recognizes expired stickers instead of offering them as active.
- If all spaces are disabled, entry is intentionally unavailable. The page explains that an Admin must reopen parking: use **Parking Slots → Enable all parking slots** to reopen every zone, or edit one space to reopen it individually. Existing closures are never automatically undone, and vehicles already inside can still exit through a suitable gate.
- Manual lookup and slot selection keep working if optional camera guidance or parking-layout decoration scripts fail to load. Submission buttons block repeated clicks while saving.
- Phone cameras require HTTPS, except browser localhost development. Verify camera permission on the actual phone as well as automated tests.

Run `npm test`, and `npm run test:camera`. For dashboard/manual browser tests, start a local test server, set `E2E_BASE_URL`, `ADMIN_USERNAME`, `ADMIN_PASSWORD`, `GUARD_USERNAME`, and `GUARD_PASSWORD`, then run `npx playwright test e2e/gate-logging.spec.js`. Browser tests stub movement submissions and do not change parking assignments. The development checkout requires its existing local review settings (`E2E_ALLOW_WRITES=1`, a loopback `DB_HOST`, and a separate `DB_NAME` ending in `_review`) for browser tests. It additionally provides `npm run lint` and `npm run build`; the deployed EJS checkout runs directly with `npm start`.

Before release, verify on a disposable database: migration repeatability, original log preservation, role restrictions, Gate 1→4, rapid and concurrent scans, replacement QR exit, queued confirmation after a gate-setting change, and offline entry/exit. Verify the dashboard filters on desktop and phone. Never use real student QR codes for automated write tests against production.

## Changed files

| Files | Responsibility |
| --- | --- |
| `lib/parking/gate-logging.js`, `lib/parking/gate-routes.js` | Gate rules, transactional movement checks, paired sessions and protected APIs |
| `sql/migrations/20261018-gate-logging.sql`, `db.js` | Additive schema, backfill and startup integration |
| `server.js` | Connect existing scanner paths to gate logging; preserve the original gate through remote confirmation |
| `views/scanner*.ejs`, `views/verify.ejs`, `public/js/gate-selector.js` | Configured gate choices, direction hints and manual-entry feedback |
| `views/partials/gate-history.ejs`, `public/js/gate-history.js` | History table, filters, pagination, loading/errors and Admin gate settings |
| `views/dashboard.ejs`, `views/guard_dashboard.ejs`, `views/admin_records.ejs` | Add history to existing dashboards and movement records |
| `tests/gate-logging.test.js`, `tests/password-login.test.js`, `e2e/gate-logging.spec.js`, `e2e/camera-startup.spec.js` | Rule, access, desktop/phone and camera regression coverage |

The organized development checkout uses `database/database-setup.js`, `database/migrations/`, `views/components/`, and the corresponding `views/admin/`, `views/guard/` and `views/verification/` templates for the same changes.
