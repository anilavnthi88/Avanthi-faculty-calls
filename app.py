from flask import Flask, render_template, request, redirect, session, send_file, flash
import sqlite3
import os
import pandas as pd
import openpyxl # Needed for reading/writing .xlsx files
from datetime import datetime # Import datetime for explicit timestamping

app = Flask(__name__)
app.secret_key = 'your_secret_key_here_a_long_random_string' # IMPORTANT: Change this to a strong, random key for production!
DATABASE = 'calls.db'

def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        is_admin INTEGER DEFAULT 0
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS calls (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        student TEXT,
        phone_number TEXT,
        status TEXT,
        notes TEXT,
        call_date TEXT,
        exam_type TEXT,
        hall_ticket_no TEXT,
        rank TEXT,
        address TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS assigned_students (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        faculty_id INTEGER,
        student TEXT,
        phone_number TEXT,
        hall_ticket_no TEXT,
        rank TEXT,
        exam_type TEXT,
        address TEXT,
        status TEXT DEFAULT 'Pending',
        notes TEXT DEFAULT '',
        call_date TEXT DEFAULT '',
        assignment_date TEXT DEFAULT CURRENT_TIMESTAMP, -- New column: records when student was assigned
        FOREIGN KEY (faculty_id) REFERENCES users(id)
    )''')

    # --- Add assignment_date column if it doesn't exist (for existing databases) ---
    c.execute("PRAGMA table_info(assigned_students)")
    columns = [col[1] for col in c.fetchall()]
    if 'assignment_date' not in columns:
        c.execute("ALTER TABLE assigned_students ADD COLUMN assignment_date TEXT DEFAULT CURRENT_TIMESTAMP")
        print("Added 'assignment_date' column to 'assigned_students' table.")
    # --- End of column addition check ---

    # Add a default admin user if one doesn't exist (for easy testing)
    c.execute("SELECT * FROM users WHERE username='admin' AND is_admin=1")
    if not c.fetchone():
        c.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)", ('admin', 'adminpass', 1))
        print("Default admin user created: username='admin', password='adminpass'")

    conn.commit()
    conn.close()

def get_db():
    return sqlite3.connect(DATABASE)

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()

    if not username or not password:
        flash('Please enter both username and password.', 'danger')
        return redirect('/')

    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT id, username, password, is_admin FROM users WHERE username=?', (username,))
    user = c.fetchone()
    conn.close()

    if user and user[2] == password:
        session['user_id'] = user[0]
        session['username'] = user[1]
        session['is_admin'] = user[3]
        flash(f'Welcome, {user[1]}!', 'success')
        return redirect('/adminpanel' if user[3] == 1 else '/dashboard')
    
    flash('Invalid credentials.', 'danger')
    return redirect('/')

@app.route('/register', methods=['GET', 'POST'])
def register_faculty():
    if 'user_id' not in session or session.get('is_admin') != 1:
        flash('Unauthorized access.', 'danger')
        return redirect('/')

    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        is_admin = 0

        if not username or not password:
            flash('Username and password cannot be empty.', 'danger')
            return render_template('register.html', role='Faculty')

        conn = get_db()
        c = conn.cursor()
        try:
            c.execute('INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)',
                      (username, password, is_admin))
            conn.commit()
            flash(f'Faculty "{username}" registered successfully!', 'success')
            return redirect('/adminpanel')
        except sqlite3.IntegrityError:
            flash(f'Username "{username}" already exists. Please choose a different one.', 'danger')
        finally:
            conn.close()
    return render_template('register.html', role='Faculty')

@app.route('/register/admin', methods=['GET', 'POST'])
def register_admin():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        is_admin = 1

        if not username or not password:
            flash('Username and password cannot be empty.', 'danger')
            return render_template('register.html', role='Admin')

        conn = get_db()
        c = conn.cursor()
        try:
            c.execute('INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)',
                      (username, password, is_admin))
            conn.commit()
            flash(f'Admin "{username}" registered successfully!', 'success')
            return redirect('/')
        except sqlite3.IntegrityError:
            flash(f'Username "{username}" already exists. Please choose a different one.', 'danger')
        finally:
            conn.close()
    return render_template('register.html', role='Admin')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session or session.get('is_admin') == 1:
        flash('Unauthorized access.', 'danger')
        return redirect('/')

    conn = get_db()
    c = conn.cursor()

    if request.method == "POST":
        student_id = request.form.get('student_id')
        status = request.form.get('status')
        notes = request.form.get('notes')
        call_date = request.form.get('call_date')

        if student_id:
            c.execute('''UPDATE assigned_students 
                         SET status=?, notes=?, call_date=?
                         WHERE id=? AND faculty_id=?''',
                      (status, notes, call_date, student_id, session['user_id']))
            conn.commit()
            flash('Student record updated successfully!', 'success')
        else:
            flash('Error: Student ID not provided for update.', 'danger')

    c.execute('''SELECT id, student, phone_number, hall_ticket_no, rank, exam_type, address, status, notes, call_date, assignment_date
                 FROM assigned_students WHERE faculty_id=? ORDER BY assignment_date DESC, id DESC''',
              (session['user_id'],))
    assigned_data = c.fetchall() # Renamed to avoid conflict with 'assigned' below
    conn.close()

    # Add S.No. to the data for rendering
    # Each item in assigned_data is a tuple. We convert it to a list to prepend S.No.
    assigned_with_sno = []
    for i, row in enumerate(assigned_data):
        assigned_with_sno.append((i + 1,) + row) # Prepend S.No. (starts from 1)

    return render_template('dashboard.html', username=session['username'], assigned=assigned_with_sno)


@app.route('/adminpanel', methods=['GET'])
def adminpanel():
    if 'user_id' not in session or session.get('is_admin') != 1:
        flash('Unauthorized access.', 'danger')
        return redirect('/')

    conn = get_db()
    c = conn.cursor()

    c.execute('SELECT id, username FROM users WHERE is_admin=0')
    faculty_list = c.fetchall()
    
    faculty_filter = request.args.get('faculty', '')

    reports_data = [] # Renamed to avoid conflict with 'reports' below
    if faculty_filter:
        c.execute('''SELECT u.username, a.student, a.phone_number, a.hall_ticket_no, a.rank, a.exam_type, 
                            a.status, a.notes, a.address, a.call_date, a.assignment_date
                       FROM assigned_students a JOIN users u ON a.faculty_id = u.id
                       WHERE u.id=? ORDER BY a.assignment_date DESC, a.id DESC''', (faculty_filter,))
        reports_data = c.fetchall()
    else:
        c.execute('''SELECT u.username, a.student, a.phone_number, a.hall_ticket_no, a.rank, a.exam_type, 
                            a.status, a.notes, a.address, a.call_date, a.assignment_date
                       FROM assigned_students a JOIN users u ON a.faculty_id = u.id
                       ORDER BY a.assignment_date DESC, a.id DESC''')
        reports_data = c.fetchall()
    
    conn.close()

    # Add S.No. to the data for rendering
    reports_with_sno = []
    for i, row in enumerate(reports_data):
        reports_with_sno.append((i + 1,) + row) # Prepend S.No. (starts from 1)

    return render_template('adminpanel.html', reports=reports_with_sno, faculty_list=faculty_list, selected_user=faculty_filter, username=session['username'])

@app.route('/assign_students', methods=['GET', 'POST'])
def assign_students():
    if 'user_id' not in session or session.get('is_admin') != 1:
        flash('Unauthorized access.', 'danger')
        return redirect('/')

    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT id, username FROM users WHERE is_admin=0')
    faculty_list = c.fetchall()

    if request.method == 'POST':
        faculty_id = request.form.get('faculty_id')
        file = request.files.get('file')

        if not faculty_id:
            flash('Please select a faculty member.', 'danger')
            conn.close()
            return render_template('assign_students.html', faculty_list=faculty_list)
        
        if not file:
            flash('No file selected.', 'danger')
            conn.close()
            return render_template('assign_students.html', faculty_list=faculty_list)

        if not file.filename.endswith(('.xlsx', '.xls')):
            flash('Invalid file type. Please upload an Excel file (.xlsx or .xls).', 'danger')
            conn.close()
            return render_template('assign_students.html', faculty_list=faculty_list)

        try:
            df = pd.read_excel(file)
            expected_columns = ['Student', 'Phone Number', 'Hall Ticket No', 'Rank', 'Exam Type', 'Address']
            
            if not all(col in df.columns for col in expected_columns):
                missing_cols = [col for col in expected_columns if col not in df.columns]
                flash(f'Missing required columns in Excel file: {", ".join(missing_cols)}. Please check your Excel file headers.', 'danger')
                conn.close()
                return render_template('assign_students.html', faculty_list=faculty_list)

            rows_inserted = 0
            current_timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S') # Get current timestamp
            for _, row in df.iterrows():
                student = str(row.get('Student', '') or '').strip()
                phone_number = str(row.get('Phone Number', '') or '').strip()
                hall_ticket_no = str(row.get('Hall Ticket No', '') or '').strip()
                rank = str(row.get('Rank', '') or '').strip()
                exam_type = str(row.get('Exam Type', '') or '').strip()
                address = str(row.get('Address', '') or '').strip()

                c.execute('''INSERT INTO assigned_students 
                                (faculty_id, student, phone_number, hall_ticket_no, rank, exam_type, address, assignment_date)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                                (faculty_id, student, phone_number, hall_ticket_no, rank, exam_type, address, current_timestamp))
                rows_inserted += 1
            conn.commit()
            flash(f'{rows_inserted} students assigned successfully to faculty!', 'success')
            return redirect('/adminpanel')
        except Exception as e:
            conn.rollback()
            flash(f'Error processing file: {e}. Please ensure the file is a valid Excel format and columns are correct.', 'danger')
            print(f"Error during file processing: {e}")
        finally:
            conn.close()
    
    conn.close()
    return render_template('assign_students.html', faculty_list=faculty_list)


@app.route('/export_excel')
def export_excel():
    if 'user_id' not in session or session.get('is_admin') != 1:
        flash('Unauthorized access.', 'danger')
        return redirect('/')

    conn = get_db()
    c = conn.cursor()
    # Export all assigned students for admin, including assignment_date
    c.execute('''SELECT u.username, a.student, a.phone_number, a.hall_ticket_no, a.rank, a.exam_type, a.status, a.notes, a.address, a.call_date, a.assignment_date
                 FROM assigned_students a JOIN users u ON a.faculty_id = u.id
                 ORDER BY a.assignment_date DESC, a.id DESC''')
    data = c.fetchall()
    conn.close()

    if not data:
        flash('No assigned student data to export.', 'info')
        return redirect('/adminpanel')

    # Prepare data for DataFrame with S.No.
    data_with_sno = []
    for i, row in enumerate(data):
        data_with_sno.append((i + 1,) + row) # Prepend S.No. (starts from 1)

    df = pd.DataFrame(data_with_sno, columns=["S.No.", "Faculty", "Student", "Phone Number", "Hall Ticket No", "Rank", "Exam Type", "Status", "Notes", "Address", "Call Date", "Assignment Date"])
    file_path = 'all_assigned_students_report.xlsx'
    df.to_excel(file_path, index=False)
    return send_file(file_path, as_attachment=True)

@app.route('/export_assigned_excel')
def export_assigned_excel():
    if 'user_id' not in session or session.get('is_admin') == 1:
        flash('Unauthorized access.', 'danger')
        return redirect('/')

    conn = get_db()
    c = conn.cursor()
    # Export faculty's assigned students, including assignment_date
    c.execute('''SELECT student, phone_number, hall_ticket_no, rank, exam_type, status, notes, address, call_date, assignment_date
                 FROM assigned_students WHERE faculty_id=? ORDER BY assignment_date DESC, id DESC''', (session['user_id'],))
    data = c.fetchall()
    conn.close()

    if not data:
        flash('No assigned students data to export for you.', 'info')
        return redirect('/dashboard')

    # Prepare data for DataFrame with S.No.
    data_with_sno = []
    for i, row in enumerate(data):
        data_with_sno.append((i + 1,) + row) # Prepend S.No. (starts from 1)

    df = pd.DataFrame(data_with_sno, columns=["S.No.", "Student", "Phone Number", "Hall Ticket No", "Rank", "Exam Type", "Status", "Notes", "Address", "Call Date", "Assignment Date"])
    file_path = f"{session['username']}_assigned_students_report.xlsx"
    df.to_excel(file_path, index=False)
    return send_file(file_path, as_attachment=True)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect('/')

if __name__ == '__main__':
    init_db()
    app.run(debug=True)













































































































































































































