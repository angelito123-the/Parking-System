# Free online deployment: Render + TiDB Cloud

This setup uses:

- **Render Free Web Service** for the Node.js application and HTTPS domain.
- **TiDB Cloud Starter** for the MySQL-compatible database.

The application stores sessions and new scan snapshots in TiDB, so they are not
lost when Render's free service sleeps or restarts.

## 1. Put the project on GitHub

Create a GitHub repository and push this project folder. Do not upload `.env`,
`node_modules`, log files, or `storage/snapshots`; `.gitignore` excludes them.

The repository root used by Render must be the folder containing `package.json`,
`server.js`, and `render.yaml`.

## 2. Create the free TiDB database

1. Sign in at <https://tidbcloud.com/>.
2. Create a **TiDB Cloud Starter** instance and keep it within the free quota.
3. Open the instance, select **Connect**, and choose a public connection for a
   general MySQL client.
4. Generate and safely save the database password.
5. In the public endpoint firewall rules, allow Render to connect. Render Free
   does not provide a fixed outbound IP, so the practical free-tier setting is
   `0.0.0.0/0`. Protect the database with the generated strong password and TLS.
6. Copy the host, port, username (including its TiDB prefix), password, and
   database name shown in the connection dialog.

Do not run `sql/schema.sql` manually. The app creates and updates its tables on
startup in the configured database.

## 3. Create the Render web service

1. Sign in at <https://dashboard.render.com/>.
2. Select **New > Blueprint** and connect the GitHub repository.
3. Choose the repository's `render.yaml` file.
4. Keep the service plan set to **Free**.
5. Enter the prompted environment variables:

| Variable | Value |
| --- | --- |
| `DB_HOST` | TiDB public host |
| `DB_PORT` | TiDB port, commonly `4000` |
| `DB_USER` | TiDB username including its instance prefix |
| `DB_PASSWORD` | Generated TiDB password |
| `DB_NAME` | Database from the TiDB connection dialog, commonly `test` |
| `ADMIN_USERNAME` | Your chosen administrator username |
| `ADMIN_PASSWORD` | A new strong administrator password |
| `GUARD_USERNAME` | Your chosen guard username |
| `GUARD_PASSWORD` | A different strong guard password |

`DB_SSL=true`, `NODE_ENV=production`, and a random `SESSION_SECRET` are handled
by `render.yaml`.

Render automatically provides its final public URL to the application. If you
later attach a custom domain, add `APP_BASE_URL=https://your-domain.example` in
the Render Environment page and redeploy so newly printed QR codes use it.

## 4. Verify the deployment

1. Open `/healthz`; it should return `{"ok":true}`.
2. Sign in with the new administrator account.
3. Create a test student, vehicle, and sticker.
4. Open `/scanner/auto` on a phone and allow camera permission.
5. Test a scan, sign out, and sign back in.

## Free-tier limitations

- Render sleeps the service after 15 minutes without traffic. The first request
  after sleep can take about a minute.
- Render's local filesystem is temporary, but this app stores new scan snapshots
  and sessions in TiDB.
- TiDB's free quota is 5 GiB row storage and 50 million request units per month.
- This setup is suitable for demonstrations, school projects, and light usage;
  it is not an always-on production service-level guarantee.
