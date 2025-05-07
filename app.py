from flask import Flask, render_template, request, redirect, session, send_file
import sqlite3
import os
import pandas as pd  # For Excel support

app = Flask(__name__)
app.secret_key = 'your_secret_key'

DATABASE = 'calls.db'

# Initialize the database and tables, and add phone_number column if it doesn't exist
def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()

    # Create users table if it doesn't exist
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        is_admin INTEGER DEFAULT 0
    )''')

    # Create calls table if it doesn't exist
    c.execute('''CREATE TABLE IF NOT EXISTS calls (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        student TEXT,
        status TEXT,
        notes TEXT,
        call_date TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')

    # Check if phone_number column exists and add it if not
    try:
        c.execute("SELECT phone_number FROM calls LIMIT 1")
    except sqlite3.OperationalError:
        c.execute("ALTER TABLE calls ADD COLUMN phone_number TEXT")
        conn.commit()

    conn.close()

def get_db():
    return sqlite3.connect(DATABASE)

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username=? AND password=?', (username, password))
    user = c.fetchone()
    conn.close()
    if user:
        session['user_id'] = user[0]
        session['username'] = user[1]
        session['is_admin'] = user[3]
        if user[3] == 1:
            return redirect('/adminpanel')
        else:
            return redirect('/dashboard')
    return 'Invalid credentials'

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        is_admin = 1 if 'is_admin' in request.form else 0
        conn = get_db()
        c = conn.cursor()
        c.execute('INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)', (username, password, is_admin))
        conn.commit()
        conn.close()
        return redirect('/')
    return render_template('register.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session or session.get('is_admin') == 1:
        return redirect('/')
    conn = get_db()
    c = conn.cursor()
    if request.method == 'POST':
        student = request.form['student']
        phone_number = request.form['phone_number']
        status = request.form['status']
        notes = request.form['notes']
        call_date = request.form['call_date']
        c.execute('INSERT INTO calls (user_id, student, phone_number, status, notes, call_date) VALUES (?, ?, ?, ?, ?, ?)',
                  (session['user_id'], student, phone_number, status, notes, call_date))
        conn.commit()
    c.execute('SELECT student, phone_number, status, notes, call_date FROM calls WHERE user_id=?', (session['user_id'],))
    calls = c.fetchall()
    conn.close()
    return render_template('dashboard.html', username=session['username'], calls=calls)

@app.route('/adminpanel')
def adminpanel():
    if 'user_id' not in session or session.get('is_admin') != 1:
        return redirect('/')
    conn = get_db()
    c = conn.cursor()
    c.execute('''
        SELECT u.username, c.student, c.phone_number, c.status, c.notes, c.call_date
        FROM calls c JOIN users u ON c.user_id = u.id
        ORDER BY c.call_date DESC
    ''')
    reports = c.fetchall()
    conn.close()
    return render_template('report.html', reports=reports)

@app.route('/export_excel')
def export_excel():
    if 'user_id' not in session or session.get('is_admin') != 1:
        return redirect('/')
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''
        SELECT u.username, c.student, c.phone_number, c.status, c.notes, c.call_date
        FROM calls c JOIN users u ON c.user_id = u.id
        ORDER BY c.call_date DESC
    ''')
    data = c.fetchall()
    conn.close()
    df = pd.DataFrame(data, columns=["Faculty", "Student", "Phone Number", "Status", "Notes", "Date"])
    file_path = 'faculty_call_reports.xlsx'
    df.to_excel(file_path, index=False)
    return send_file(file_path, as_attachment=True)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    init_db()
    app.run(debug=True)


















