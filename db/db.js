import Database from "better-sqlite3";


export const db = new Database('mydbsqlite')

db.exec(`
    CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email text,
    refresh_token text
    )
    `)

