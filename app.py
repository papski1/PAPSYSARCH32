from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Change this to a secure key

def init_db():
    """Initialize the database and ensure all necessary columns exist."""
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    # Create users table if it doesn't exist
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin BOOLEAN DEFAULT 0,
            is_staff BOOLEAN DEFAULT 0,
            year_level TEXT
        )
    ''')

    # Add missing columns if they don't exist
    try:
        c.execute("ALTER TABLE users ADD COLUMN full_name TEXT;")
    except sqlite3.OperationalError:
        pass  # Column already exists

    try:
        c.execute("ALTER TABLE users ADD COLUMN email TEXT;")
    except sqlite3.OperationalError:
        pass

    try:
        c.execute("ALTER TABLE users ADD COLUMN course TEXT;")
    except sqlite3.OperationalError:
        pass

    try:
        c.execute("ALTER TABLE users ADD COLUMN student_id TEXT;")
    except sqlite3.OperationalError:
        pass

    # Create reservations table if it doesn't exist
    c.execute('''
        CREATE TABLE IF NOT EXISTS reservations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            date TEXT NOT NULL,
            time TEXT NOT NULL
        )
    ''')

    # Create sit-in records table if it doesn't exist
    c.execute('''
        CREATE TABLE IF NOT EXISTS sit_in_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            date TEXT NOT NULL,
            purpose TEXT NOT NULL
        )
    ''')

    # Ensure an admin user exists
    c.execute("SELECT * FROM users WHERE username = 'admin'")
    if not c.fetchone():
        hashed_password = generate_password_hash('users')
        c.execute("INSERT INTO users (username, password, is_admin, is_staff) VALUES (?, ?, ?, ?)",
                  ('admin', hashed_password, 1, 0))

    # Ensure a staff user exists
    c.execute("SELECT * FROM users WHERE username = 'staff'")
    if not c.fetchone():
        hashed_password = generate_password_hash('staff_pass')
        c.execute("INSERT INTO users (username, password, is_admin, is_staff) VALUES (?, ?, ?, ?)",
                  ('staff', hashed_password, 0, 1))

    conn.commit()
    conn.close()

@app.route('/')
def home():
    """Redirect users based on their role."""
    if 'username' in session:
        if session.get('is_admin'):
            return redirect(url_for('admin'))
        return redirect(url_for('student_dashboard'))
    return redirect(url_for('login'))

@app.route('/student_dashboard', defaults={'section': 'dashboard'})
@app.route('/student_dashboard/<section>')
def student_dashboard(section):
    valid_sections = ["dashboard", "info", "announcement", "remaining_session",
                      "sit_in_rules", "lab_rules", "sit_in_history", "reservation"]

    if section not in valid_sections:
        section = "dashboard"  # Default to dashboard if invalid

    print(f"Loading section: {section}")  # Debugging print

    return render_template("student_dashboard.html", section=section, username=session.get('username', 'Student'))

@app.route('/admin')
def admin():
    """Admin Dashboard."""
    if 'username' not in session or not session.get('is_admin'):
        flash('Access denied.')
        return redirect(url_for('home'))  # Redirect non-admin users

    return render_template('admin.html', username=session['username'])

@app.route('/view_users')
def view_users():
    """View Users Page (Admin Only) - Excludes logged-in admin."""
    if 'username' not in session or not session.get('is_admin'):
        flash('Access denied.')
        return redirect(url_for('home'))

    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    # Exclude the logged-in admin from the user list
    c.execute('SELECT id, username FROM users WHERE username != ?', (session['username'],))
    users = c.fetchall()
    
    conn.close()

    # Ensure the route returns a valid response
    return render_template('view_users.html', users=users)

@app.route('/info')
def info():
    """Display user profile details."""
    if 'username' not in session:
        return redirect(url_for('login'))

    user_id = session.get('user_id')

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    # Fetch user details
    c.execute('SELECT id, username, full_name, email, year_level, course, student_id FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()
    
    conn.close()

    if not user:
        flash("User not found.")
        return redirect(url_for('student_dashboard'))  # Redirect if user is missing

    return render_template("sections/info.html", user=user)

@app.route('/announcement')
def announcement():
    """Announcements page."""
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('sections/announcement.html', username=session['username'])


@app.route('/remaining_session')
def remaining_session():
    """Remaining session page."""
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('sections/remaining_session.html', username=session['username'])

@app.route('/sit_in_rules')
def sit_in_rules():
    """Sit-in rules page."""
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('sections/sit_in_rules.html', username=session['username'])

@app.route('/lab_rules')
def lab_rules():
    """Lab rules page."""
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('sections/lab_rules.html', username=session['username'])

@app.route('/reservation', methods=['GET', 'POST'])
def reservation():
    """Reservation system for users."""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    username = session['username']

    if request.method == 'POST':
        date = request.form['date']
        time = request.form['time']

        print(f"Inserting reservation: username={username}, date={date}, time={time}")

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('INSERT INTO reservations (username, date, time) VALUES (?, ?, ?)', (username, date, time))
        conn.commit()
        conn.close()

        flash('Reservation successful!')
        return redirect(url_for('reservation'))

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT date, time FROM reservations WHERE username = ?', (username,))
    reservations = c.fetchall()
    conn.close()

    return render_template('sections/reservation.html', username=username, reservations=reservations)

@app.route('/logout')
def logout():
    """Log the user out."""
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('login'))

@app.route('/staff', methods=['GET', 'POST'])
def staff_dashboard():
    """Staff Dashboard - Includes search, reset sessions, sit-in records, and reports."""
    if 'username' not in session or not session.get('is_staff'):
        flash('Access denied.')
        return redirect(url_for('login'))

    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    search_query = request.form.get('query', '').strip()

    # Handle Search Users
    if search_query:
        c.execute("SELECT id, username FROM users WHERE is_admin = 0 AND is_staff = 0 AND username LIKE ?", ('%' + search_query + '%',))
    else:
        c.execute("SELECT id, username FROM users WHERE is_admin = 0 AND is_staff = 0")
    
    users = c.fetchall()

    # Handle Reset Session
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        reset_all = request.form.get('reset_all')

        if reset_all:  # Reset all sessions
            c.execute("DELETE FROM sit_in_records")
            conn.commit()
            flash('All sessions reset successfully.')

        elif user_id:  # Reset individual session
            c.execute("DELETE FROM sit_in_records WHERE username = (SELECT username FROM users WHERE id = ?)", (user_id,))
            conn.commit()
            flash(f"Session for User ID {user_id} reset successfully.")

    # Fetch sit-in records
    c.execute("""
        SELECT users.id, users.username, sit_in_records.date, sit_in_records.purpose 
        FROM sit_in_records
        JOIN users ON sit_in_records.username = users.username
        ORDER BY sit_in_records.date DESC
    """)
    records = c.fetchall()

    # Reports by Purpose
    c.execute("SELECT purpose, COUNT(*) FROM sit_in_records GROUP BY purpose")
    purpose_report = c.fetchall()

    # Reports by Year Level
    c.execute("SELECT year_level, COUNT(*) FROM users GROUP BY year_level")
    level_report = c.fetchall()

    conn.close()

    return render_template(
        'staff.html',
        users=users,
        records=records,
        purpose_report=purpose_report,
        level_report=level_report,
        search_query=search_query
    )

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Unified Login for Staff, Admin, and Regular Users."""
    if request.method == 'POST':
        user_input = request.form['user_input']  # Accepts username or ID number
        password = request.form['password']
        
        # Hardcoded Staff Credentials
        if user_input == 'staff' and password == 'staff_pass':
            session.clear()  # Clear previous session data
            session['username'] = user_input
            session['is_staff'] = True
            session['is_admin'] = False  
            session['user_id'] = None  # No ID for hardcoded staff
            flash('Login successful as Staff.')
            return redirect(url_for('staff_dashboard'))

        # Check Database for Other Users
        conn = sqlite3.connect('database.db')
        c = conn.cursor()

        # Determine whether input is a username or ID number
        if user_input.isdigit():
            query = 'SELECT id, username, password, is_admin, is_staff FROM users WHERE id = ?'
        else:
            query = 'SELECT id, username, password, is_admin, is_staff FROM users WHERE username = ?'

        c.execute(query, (user_input,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
            session.clear()  # Clear previous session data
            session['username'] = user[1]
            session['user_id'] = user[0]  # Store user ID
            session['is_admin'] = bool(user[3])
            session['is_staff'] = bool(user[4])

            flash('Login successful.')
            if session['is_admin']:
                return redirect(url_for('admin'))
            elif session['is_staff']:
                return redirect(url_for('staff_dashboard'))
            else:
                return redirect(url_for('student_dashboard'))
        else:
            flash("Invalid username/ID or password", "error")

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration."""
    if request.method == 'POST':
        # Get form fields
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        full_name = f"{request.form['firstname']} {request.form['lastname']} {request.form['midname']}"
        email = request.form['email']
        course = request.form['course']
        year_level = request.form['year_level']
        student_id = request.form['idno']

        # Check if passwords match
        if password != confirm_password:
            flash('Passwords do not match.')
            return redirect(url_for('register'))

        # Hash the password
        hashed_password = generate_password_hash(password)

        try:
            conn = sqlite3.connect('database.db')
            c = conn.cursor()

            # Insert new user into the users table
            c.execute('''INSERT INTO users 
                         (username, password, full_name, email, course, year_level, student_id, is_admin) 
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                      (username, hashed_password, full_name, email, course, year_level, student_id, 0))  # Set is_admin to 0 for regular users
            conn.commit()
            conn.close()

            flash('Registration successful! Please login.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists')

    return render_template('register.html')

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    """Allow users to edit their profile."""
    
    if 'username' not in session:
        return redirect(url_for('login'))

    is_admin = session.get('is_admin', False)
    logged_in_user_id = session.get('user_id')

    # Prevent regular users from editing other users
    if not is_admin and logged_in_user_id != user_id:
        flash("You can only edit your own profile.")
        return redirect(url_for('info'))  # Redirect to user's info page

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    # Fetch user details
    c.execute('SELECT id, username, full_name, email, year_level, course, student_id FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()
    
    if not user:
        flash('User not found.')
        conn.close()
        return redirect(url_for('info'))

    if request.method == 'POST':
        new_username = request.form['username']
        new_full_name = request.form['full_name']
        new_email = request.form['email']
        new_year_level = request.form['year_level']
        new_course = request.form['course']
        new_student_id = request.form['student_id']
        new_password = request.form['password']

        if new_password:  # Only update the password if provided
            hashed_password = generate_password_hash(new_password)
            c.execute('''
                UPDATE users 
                SET username = ?, full_name = ?, email = ?, year_level = ?, course = ?, student_id = ?, password = ?
                WHERE id = ?
            ''', (new_username, new_full_name, new_email, new_year_level, new_course, new_student_id, hashed_password, user_id))
        else:
            c.execute('''
                UPDATE users 
                SET username = ?, full_name = ?, email = ?, year_level = ?, course = ?, student_id = ?
                WHERE id = ?
            ''', (new_username, new_full_name, new_email, new_year_level, new_course, new_student_id, user_id))
        
        conn.commit()
        conn.close()

        # Update session values if the user updated their own profile
        if logged_in_user_id == user_id:
            if logged_in_user_id == user_id:
                session['username'] = new_username
                session['full_name'] = new_full_name
                session['email'] = new_email
                session['year_level'] = new_year_level
                session['course'] = new_course
                session['student_id'] = new_student_id

        flash('Profile updated successfully.')
        return redirect(url_for('info'))  # Redirect to info page after updating

    conn.close()
    return render_template('edit_user.html', user=user)

@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    """Allow only regular users (sit-in monitoring users) to be deleted. Prevent deleting Admins and Staff."""
    if 'username' not in session or (not session.get('is_admin') and not session.get('is_staff')):
        flash('Access denied.')
        return redirect(url_for('login'))

    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    # Check if the user being deleted is an admin or staff
    c.execute('SELECT is_admin, is_staff FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()

    if user and (user[0] or user[1]):  # If is_admin is True (1) or is_staff is True (1)
        flash('Admins and Staff cannot be deleted!')
        conn.close()
        return redirect(url_for('admin') if session.get('is_admin') else url_for('search_users'))

    # Proceed with deletion if the user is a regular user
    c.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()

    flash('User deleted successfully.')
    return redirect(url_for('admin') if session.get('is_admin') else url_for('search_users'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)