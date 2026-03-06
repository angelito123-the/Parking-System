const mysql = require("mysql2/promise");
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
  queueLimit: 0
});

module.exports = pool;
