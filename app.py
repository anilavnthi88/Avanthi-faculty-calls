from flask import Flask, render_template, request, redirect, session, send_file, flash
import sqlite3
import os
import pandas as pd
import openpyxl # Needed for reading/writing .xlsx files
from datetime import datetime # Import datetime for explicit timestamping
import json # Import json for handling bulk student IDs

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
    # Only an admin can register faculty
    if 'user_id' not in session or session.get('is_admin') != 1:
        flash('Unauthorized access. Only administrators can register faculty.', 'danger')
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
    # Removed security restriction: Anyone can now register a new admin
    # This was done based on a previous user request.
    # For production, it's highly recommended to re-enable this check.

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
            # Redirect to login page after successful registration
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
        # Check if it's a bulk update submission
        bulk_student_ids_json = request.form.get('bulk_student_ids')
        
        if bulk_student_ids_json:
            try:
                # Parse the JSON string back to a list of IDs
                selected_ids = json.loads(bulk_student_ids_json)
                bulk_status = request.form.get('bulk_status')
                bulk_notes = request.form.get('bulk_notes')
                bulk_call_date = request.form.get('bulk_call_date')

                if not selected_ids:
                    flash('No students selected for bulk update.', 'danger')
                else:
                    updated_count = 0
                    for student_id in selected_ids:
                        # Only update fields that are provided in the bulk form
                        update_parts = []
                        update_values = []

                        if bulk_status:
                            update_parts.append('status=?')
                            update_values.append(bulk_status)
                        if bulk_notes:
                            update_parts.append('notes=?')
                            update_values.append(bulk_notes)
                        if bulk_call_date:
                            update_parts.append('call_date=?')
                            update_values.append(bulk_call_date)
                        
                        if update_parts: # Only proceed if there's something to update
                            update_query = f"UPDATE assigned_students SET {', '.join(update_parts)} WHERE id=? AND faculty_id=?"
                            update_values.extend([student_id, session['user_id']])
                            c.execute(update_query, tuple(update_values))
                            updated_count += 1
                    conn.commit()
                    flash(f'{updated_count} student records updated successfully in bulk!', 'success')
            except json.JSONDecodeError:
                flash('Error processing bulk update: Invalid student IDs format.', 'danger')
            except Exception as e:
                conn.rollback()
                flash(f'An error occurred during bulk update: {e}', 'danger')
                print(f"Bulk update error: {e}")
        else:
            # Existing individual update logic (if no bulk_student_ids are present)
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

    # Fetch data for display
    c.execute('''SELECT id, student, phone_number, hall_ticket_no, rank, exam_type, address, status, notes, call_date, assignment_date
                 FROM assigned_students WHERE faculty_id=? ORDER BY assignment_date DESC, id DESC''',
              (session['user_id'],))
    assigned_data = c.fetchall()
    conn.close()

    # Add S.No. to the data for rendering
    assigned_with_sno = []
    for i, row in enumerate(assigned_data):
        assigned_with_sno.append((i + 1,) + row)

    return render_template('dashboard.html', username=session['username'], assigned=assigned_with_sno)

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session:
        flash('Please log in to change your password.', 'warning')
        return redirect('/')

    # This route is specifically for faculty, admins will use /admin_change_password
    if session.get('is_admin') == 1:
        flash('Administrators use the "Change Admin Password" link in the Admin Panel.', 'info')
        return redirect('/adminpanel')

    conn = get_db()
    c = conn.cursor()

    if request.method == 'POST':
        current_password = request.form.get('current_password', '').strip()
        new_password = request.form.get('new_password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()

        # Fetch the user's current password from the database
        c.execute('SELECT password FROM users WHERE id=?', (session['user_id'],))
        user_db_password_tuple = c.fetchone()
        user_db_password = user_db_password_tuple[0] if user_db_password_tuple else None

        if not current_password or not new_password or not confirm_password:
            flash('All fields are required.', 'danger')
        elif user_db_password is None or current_password != user_db_password:
            flash('Current password incorrect.', 'danger')
        elif new_password != confirm_password:
            flash('New password and confirm password do not match.', 'danger')
        elif len(new_password) < 6: # Basic password strength check
            flash('New password must be at least 6 characters long.', 'danger')
        else:
            try:
                c.execute('UPDATE users SET password=? WHERE id=?', (new_password, session['user_id']))
                conn.commit()
                flash('Your password has been changed successfully!', 'success')
                conn.close()
                return redirect('/dashboard')
            except Exception as e:
                flash(f'An error occurred while changing password: {e}', 'danger')
                print(f"Password change error: {e}")
        conn.close()
        return render_template('change_password.html', username=session['username'])

    conn.close()
    return render_template('change_password.html', username=session['username'])

@app.route('/admin_change_password', methods=['GET', 'POST'])
def admin_change_password():
    if 'user_id' not in session or session.get('is_admin') != 1:
        flash('Unauthorized access. Only administrators can change admin passwords.', 'danger')
        return redirect('/')

    conn = get_db()
    c = conn.cursor()

    if request.method == 'POST':
        current_password = request.form.get('current_password', '').strip()
        new_password = request.form.get('new_password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()

        # Fetch the admin's current password from the database
        c.execute('SELECT password FROM users WHERE id=?', (session['user_id'],))
        user_db_password_tuple = c.fetchone()
        user_db_password = user_db_password_tuple[0] if user_db_password_tuple else None

        if not current_password or not new_password or not confirm_password:
            flash('All fields are required.', 'danger')
        elif user_db_password is None or current_password != user_db_password:
            flash('Current password incorrect.', 'danger')
        elif new_password != confirm_password:
            flash('New password and confirm password do not match.', 'danger')
        elif len(new_password) < 6: # Basic password strength check
            flash('New password must be at least 6 characters long.', 'danger')
        else:
            try:
                c.execute('UPDATE users SET password=? WHERE id=?', (new_password, session['user_id']))
                conn.commit()
                flash('Your admin password has been changed successfully!', 'success')
                conn.close()
                return redirect('/adminpanel') # Redirect back to admin panel
            except Exception as e:
                flash(f'An error occurred while changing password: {e}', 'danger')
                print(f"Admin password change error: {e}")
        conn.close()
        return render_template('admin_change_password.html', username=session['username'])

    conn.close()
    return render_template('admin_change_password.html', username=session['username'])


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

    reports_data = []
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
        reports_with_sno.append((i + 1,) + row)

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


































































































































































































