import sqlite3

DATABASE = 'calls.db'

conn = sqlite3.connect(DATABASE)
c = conn.cursor()

# Add 'role' column to 'users' table
c.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'faculty'")
conn.commit()
conn.close()

print("✅ Role column added successfully!")
