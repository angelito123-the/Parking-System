# Deploy Guide (Railway + MySQL)

This deployment keeps the app online even when your laptop is off.

## 1) Push project to GitHub

From `C:\Users\Arlene\Parking-System`:

```powershell
git init
git add .
git commit -m "Initial deploy-ready app"
git branch -M main
git remote add origin https://github.com/<your-username>/<your-repo>.git
git push -u origin main
```

If git is not installed, install Git for Windows first.

## 2) Create Railway project

1. Go to `https://railway.app`.
2. Create a new project.
3. Add a **MySQL** service.
4. Add a **GitHub Repo** service and select this repository.

## 3) Set web service environment variables

In Railway, open your web service Variables and set:

- `PORT=3000`
- `DB_HOST=${{MySQL.MYSQLHOST}}`
- `DB_PORT=${{MySQL.MYSQLPORT}}`
- `DB_USER=${{MySQL.MYSQLUSER}}`
- `DB_PASSWORD=${{MySQL.MYSQLPASSWORD}}`
- `DB_NAME=${{MySQL.MYSQLDATABASE}}`

After first deploy, copy your service public URL and set:

- `APP_BASE_URL=https://<your-railway-domain>`

## 4) Create database tables

Use Railway MySQL connect details and run:

```sql
CREATE DATABASE IF NOT EXISTS naap_parking;
USE naap_parking;
```

Then run everything inside `sql/schema.sql` (table creation statements).

## 5) Redeploy and test

1. Trigger a redeploy from Railway.
2. Open your Railway URL in browser.
3. Verify pages load: `/`, `/students`, `/vehicles`, `/stickers`, `/scanner`.

## Notes

- Railway is cloud-hosted, so it keeps running with your laptop off.
- Keep `APP_BASE_URL` set to your Railway domain for correct QR links.
