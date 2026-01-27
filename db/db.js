import Database from "better-sqlite3";


export const db = new Database('mydbsqlite')

db.exec('DROP TABLE IF EXISTS users')

db.exec(`
    CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name text,
    email text,
    password text,
    refresh_token text
    )
    `)

