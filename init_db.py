import sqlite3

DATABASE = 'calls.db'

def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()

    # Update users table to include 'role' instead of 'is_admin'
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('faculty', 'admin'))
    )''')

    # Calls table (faculty call reports)
    c.execute('''CREATE TABLE IF NOT EXISTS calls (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        student TEXT,
        phone_number TEXT,
        status TEXT,
        notes TEXT,
        call_date TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')

    conn.close()
    print("✅ Database initialized!")

# Run this script once
init_db()


