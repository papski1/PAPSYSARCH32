import sqlite3
from werkzeug.security import generate_password_hash

def init_db():
    """Initialize the database and enable WAL mode to avoid locking issues."""
    conn = sqlite3.connect('database.db', check_same_thread=False)
    c = conn.cursor()
    
    # Enable Write-Ahead Logging
    c.execute("PRAGMA journal_mode=WAL;")  
    c.execute("PRAGMA synchronous=NORMAL;") 
    c.execute("PRAGMA temp_store=MEMORY;")   # Enables Write-Ahead Logging for better concurrency
    
    # Create users table if it doesn't exist
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin BOOLEAN DEFAULT 0,
            is_staff BOOLEAN DEFAULT 0,
            year_level TEXT,
            full_name TEXT,
            email TEXT,
            course TEXT,
            student_id TEXT
        )
    ''')

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
        hashed_password = generate_password_hash('admin_password')
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

import sqlite3

def get_db_connection():
    """Create a new database connection with proper timeout to avoid locking issues."""
    conn = sqlite3.connect('database.db', check_same_thread=False, timeout=10)  # Increased timeout
    conn.row_factory = sqlite3.Row
    return conn
