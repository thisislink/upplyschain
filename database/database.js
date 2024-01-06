const sqlite3 = require('sqlite3').verbose();
// Connect to SQLite database
const db = new sqlite3.Database('./upplyschain.db', (err) => {
  if (err) {
    console.error(err.message);
  } else {
    console.log('Connected to the upplyschain SQLite database.');
  }
});


//test123@gmail.com Password123
db.serialize(function() {
  // Create users table
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL
  )`);
});

module.exports = db;
