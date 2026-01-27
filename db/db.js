import Database from "better-sqlite3";


export const db = new Database('database.db')



db.exec(`
    CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name text,
    email text,
    password text
    )
    `)


    db.exec(`
    CREATE TABLE IF NOT EXISTS refresh_tokens(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL,
    device TEXT,
    revoked INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,
    FOREIGN KEY (user_id) REFERENCES users(id)
    )
    `)



