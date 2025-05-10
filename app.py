from flask import Flask, render_template, request, redirect, session, send_file
import sqlite3
import os
import pandas as pd

app = Flask(__name__)
app.secret_key = 'your_secret_key'
DATABASE = 'calls.db'

def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        is_admin INTEGER DEFAULT 0
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS calls (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        student TEXT,
        status TEXT,
        notes TEXT,
        call_date TEXT,
        phone_number TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
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
        return redirect('/adminpanel' if user[3] == 1 else '/dashboard')
    return 'Invalid credentials'

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        is_admin = 1 if 'is_admin' in request.form else 0
        conn = get_db()
        c = conn.cursor()
        c.execute('INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)',
                  (username, password, is_admin))
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
        c.execute('''INSERT INTO calls (user_id, student, phone_number, status, notes, call_date)
                     VALUES (?, ?, ?, ?, ?, ?)''',
                  (session['user_id'], student, phone_number, status, notes, call_date))
        conn.commit()
    c.execute('SELECT student, phone_number, status, notes, call_date FROM calls WHERE user_id=?',
              (session['user_id'],))
    calls = c.fetchall()
    conn.close()
    return render_template('dashboard.html', username=session['username'], calls=calls)

@app.route('/adminpanel')
def adminpanel():
    if 'user_id' not in session or session.get('is_admin') != 1:
        return redirect('/')
    conn = get_db()
    c = conn.cursor()
    c.execute('''SELECT DISTINCT u.id, u.username FROM users u
                 JOIN calls c ON u.id = c.user_id WHERE u.is_admin = 0''')
    faculty_list = c.fetchall()

    c.execute('''SELECT u.username, c.student, c.phone_number, c.status, c.notes, c.call_date
                 FROM calls c JOIN users u ON c.user_id = u.id
                 ORDER BY c.call_date DESC''')
    reports = c.fetchall()
    conn.close()
    return render_template('report.html', reports=reports, faculty_list=faculty_list, selected_user=None)

@app.route('/faculty/<int:user_id>')
def faculty_report(user_id):
    if 'user_id' not in session or session.get('is_admin') != 1:
        return redirect('/')
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT username FROM users WHERE id=?', (user_id,))
    selected_user = c.fetchone()[0]

    c.execute('''SELECT DISTINCT u.id, u.username FROM users u
                 JOIN calls c ON u.id = c.user_id WHERE u.is_admin = 0''')
    faculty_list = c.fetchall()

    c.execute('''SELECT u.username, c.student, c.phone_number, c.status, c.notes, c.call_date
                 FROM calls c JOIN users u ON c.user_id = u.id
                 WHERE u.id=? ORDER BY c.call_date DESC''', (user_id,))
    reports = c.fetchall()
    conn.close()
    return render_template('report.html', reports=reports, faculty_list=faculty_list, selected_user=selected_user)

@app.route('/export_excel')
def export_excel():
    if 'user_id' not in session or session.get('is_admin') != 1:
        return redirect('/')
    conn = get_db()
    c = conn.cursor()
    c.execute('''SELECT u.username, c.student, c.phone_number, c.status, c.notes, c.call_date
                 FROM calls c JOIN users u ON c.user_id = u.id
                 ORDER BY c.call_date DESC''')
    data = c.fetchall()
    conn.close()
    df = pd.DataFrame(data, columns=["Faculty", "Student", "Phone Number", "Status", "Notes", "Date"])
    file_path = 'faculty_call_reports.xlsx'
    df.to_excel(file_path, index=False)
    return send_file(file_path, as_attachment=True)

@app.route('/export_my_excel')
def export_my_excel():
    if 'user_id' not in session or session.get('is_admin') == 1:
        return redirect('/')
    conn = get_db()
    c = conn.cursor()
    c.execute('''SELECT student, phone_number, status, notes, call_date
                 FROM calls WHERE user_id=? ORDER BY call_date DESC''', (session['user_id'],))
    data = c.fetchall()
    conn.close()
    df = pd.DataFrame(data, columns=["Student", "Phone Number", "Status", "Notes", "Date"])
    file_path = f"{session['username']}_call_report.xlsx"
    df.to_excel(file_path, index=False)
    return send_file(file_path, as_attachment=True)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    init_db()
    app.run(debug=True)



























