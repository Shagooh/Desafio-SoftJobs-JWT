const env = require('dotenv').config()

const { Pool } = require("pg");

const pool = new Pool({
    user: process.env.PGUSER,
    host: process.env.PGHOST,
    database: process.env.PGDATABASE,
    password: process.env.PGPASSWORD,
    port: process.env.PGPORT,
    allowExitOnIdle: true
});

try {
  pool.query("SELECT NOW()");
  console.log("Database connected");
} catch (error) {
  console.log(error);
}


module.exports = { pool }