const mysql = require('mysql2/promise');

const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: 'YOUR_DB_PASSWORD',
  database: 'user_info'
});

module.exports = pool;
