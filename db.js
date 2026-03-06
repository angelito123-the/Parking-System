const mysql = require("mysql2/promise");
const fs = require("fs");
const path = require("path");
require("dotenv").config();

const host = process.env.DB_HOST || process.env.MYSQLHOST || "localhost";
const port = Number(process.env.DB_PORT || process.env.MYSQLPORT || 3306);
const user = process.env.DB_USER || process.env.MYSQLUSER || "root";
const password = process.env.DB_PASSWORD || process.env.MYSQLPASSWORD || "";
const database = process.env.DB_NAME || process.env.MYSQLDATABASE || "naap_parking";

const pool = mysql.createPool({
  host,
  port,
  user,
  password,
  database,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  multipleStatements: true
});

async function ensureDatabaseSchema() {
  const schemaPath = path.join(__dirname, "sql", "schema.sql");
  const schemaSql = fs.readFileSync(schemaPath, "utf8");

  // Force schema creation in the currently configured DB (Railway uses "railway" by default).
  const sql = schemaSql
    .replace(/CREATE DATABASE IF NOT EXISTS .*?;\s*/i, "")
    .replace(/USE .*?;\s*/i, "");

  await pool.query(sql);
}

module.exports = {
  pool,
  ensureDatabaseSchema
};
