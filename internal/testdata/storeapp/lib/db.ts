import Database from "better-sqlite3";

let db: Database.Database | null = null;

// Opens the database on first use and seeds it, so every route that calls
// getDb() also "reaches" the seed writes below. Detectors must not treat
// that as the route writing those tables.
export function getDb() {
  if (db) return db;
  db = new Database("data/store.db");
  seed(db);
  return db;
}

function seed(db: Database.Database) {
  db.prepare("INSERT INTO users (email, password, role) VALUES (?, ?, ?)").run("admin@example.com", "x", "admin");
  db.prepare("INSERT INTO notes (owner, body) VALUES (?, ?)").run(1, "welcome");
  db.prepare("INSERT INTO messages (name, body) VALUES (?, ?)").run("seed", "hello");
}
