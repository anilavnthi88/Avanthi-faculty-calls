import sqlite3

DATABASE = 'calls.db'  # Change this to your actual DB path if different

def fix_users_table():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()

    # Check if 'users' table exists
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
    if c.fetchone():
        # Check if 'is_admin' column exists
        c.execute("PRAGMA table_info(users)")
        columns = [col[1] for col in c.fetchall()]
        
        if 'is_admin' not in columns:
            print("🛠 Adding 'is_admin' column to users table...")
            c.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0")
            conn.commit()
    else:
        print("🛠 Creating 'users' table with 'is_admin' column...")
        c.execute('''CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0
        )''')
        conn.commit()

    conn.close()


def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()

    # Ensure 'users' table is correct
    fix_users_table()

    # General Calls Table
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

    # EAPCET Calls Table
    c.execute('''CREATE TABLE IF NOT EXISTS eapcet_calls (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        student TEXT,
        phone_number TEXT,
        status TEXT,
        notes TEXT,
        call_date TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')

    # POLYCET Calls Table
    c.execute('''CREATE TABLE IF NOT EXISTS polycet_calls (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        student TEXT,
        phone_number TEXT,
        status TEXT,
        notes TEXT,
        call_date TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')

    conn.commit()
    conn.close()
    print("✅ Database initialized successfully!")



