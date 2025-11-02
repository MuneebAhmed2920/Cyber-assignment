"""
Secure FinTech Application
A cybersecurity-focused mini banking application with secure features
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
import sqlite3
import os
import hashlib
import secrets
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
import json
import re

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['ALLOWED_EXTENSIONS'] = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx'}

# Initialize encryption key
def get_encryption_key():
    key_file = 'encryption.key'
    if os.path.exists(key_file):
        with open(key_file, 'rb') as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(key_file, 'wb') as f:
            f.write(key)
        return key

ENCRYPTION_KEY = get_encryption_key()
cipher = Fernet(ENCRYPTION_KEY)

# Database initialization
def init_db():
    conn = sqlite3.connect('fintech.db')
    c = conn.cursor()
    
    # Users table with secure password storage
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  email TEXT UNIQUE NOT NULL,
                  password_hash TEXT NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Transactions table with encrypted sensitive data
    c.execute('''CREATE TABLE IF NOT EXISTS transactions
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER NOT NULL,
                  transaction_type TEXT NOT NULL,
                  amount REAL NOT NULL,
                  description_encrypted TEXT NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (user_id) REFERENCES users (id))''')
    
    # Audit logs table
    c.execute('''CREATE TABLE IF NOT EXISTS audit_logs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER,
                  action TEXT NOT NULL,
                  ip_address TEXT,
                  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (user_id) REFERENCES users (id))''')
    
    # User profiles table
    c.execute('''CREATE TABLE IF NOT EXISTS user_profiles
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER UNIQUE NOT NULL,
                  full_name_encrypted TEXT,
                  phone_encrypted TEXT,
                  address_encrypted TEXT,
                  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (user_id) REFERENCES users (id))''')
    
    conn.commit()
    conn.close()

# Password validation
def validate_password(password):
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit"
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    return True, "Password is valid"

# Input sanitization
def sanitize_input(input_str):
    """Sanitize user input to prevent XSS"""
    if not input_str:
        return ""
    # Remove potentially dangerous characters
    input_str = input_str.replace('<', '&lt;')
    input_str = input_str.replace('>', '&gt;')
    input_str = input_str.replace('"', '&quot;')
    input_str = input_str.replace("'", '&#x27;')
    input_str = input_str.replace('/', '&#x2F;')
    return input_str[:500]  # Limit length

# Encryption/Decryption helpers
def encrypt_data(data):
    """Encrypt sensitive data"""
    if not data:
        return ""
    return cipher.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data):
    """Decrypt sensitive data"""
    if not encrypted_data:
        return ""
    try:
        return cipher.decrypt(encrypted_data.encode()).decode()
    except:
        return ""

# Audit logging
def log_activity(user_id, action, ip_address=None):
    """Log user activities for audit trail"""
    conn = sqlite3.connect('fintech.db')
    c = conn.cursor()
    c.execute('''INSERT INTO audit_logs (user_id, action, ip_address)
                 VALUES (?, ?, ?)''', (user_id, action, ip_address or request.remote_addr))
    conn.commit()
    conn.close()

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Session management
@app.before_request
def check_session():
    """Check session expiry"""
    if 'user_id' in session:
        if 'last_activity' in session:
            last_activity = datetime.fromisoformat(session['last_activity'])
            if datetime.now() - last_activity > timedelta(minutes=5):
                session.clear()
                flash('Session expired. Please login again', 'info')
                return redirect(url_for('login'))
        session['last_activity'] = datetime.now().isoformat()

# Routes
@app.route('/')
def index():
    """Home page"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration with password validation"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Input validation
        if not username or not email or not password:
            flash('All fields are required', 'error')
            return render_template('register.html')
        
        # Sanitize inputs
        username = sanitize_input(username)
        email = sanitize_input(email)
        
        # Email validation
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            flash('Invalid email format', 'error')
            return render_template('register.html')
        
        # Password match validation
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('register.html')
        
        # Password strength validation
        is_valid, message = validate_password(password)
        if not is_valid:
            flash(message, 'error')
            return render_template('register.html')
        
        # Check for duplicate username
        conn = sqlite3.connect('fintech.db')
        c = conn.cursor()
        c.execute('SELECT id FROM users WHERE username = ?', (username,))
        if c.fetchone():
            conn.close()
            flash('Username already exists', 'error')
            return render_template('register.html')
        
        # Check for duplicate email
        c.execute('SELECT id FROM users WHERE email = ?', (email,))
        if c.fetchone():
            conn.close()
            flash('Email already exists', 'error')
            return render_template('register.html')
        
        # Hash password securely
        password_hash = generate_password_hash(password, method='pbkdf2:sha256')
        
        # Insert user
        try:
            c.execute('''INSERT INTO users (username, email, password_hash)
                         VALUES (?, ?, ?)''', (username, email, password_hash))
            user_id = c.lastrowid
            conn.commit()
            conn.close()
            
            log_activity(user_id, 'User registered', request.remote_addr)
            flash('Registration successful! Please login', 'success')
            return redirect(url_for('login'))
        except sqlite3.Error as e:
            conn.close()
            flash('Registration failed. Please try again.', 'error')
            return render_template('register.html')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login with session management"""
    # Check for lockout
    if 'login_attempts' in session:
        if session['login_attempts'] >= 5:
            flash('Account temporarily locked due to too many failed attempts', 'error')
            return render_template('login.html')
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        # Input validation (prevent SQL injection)
        if not username or not password:
            flash('Username and password are required', 'error')
            if 'login_attempts' not in session:
                session['login_attempts'] = 0
            session['login_attempts'] = session.get('login_attempts', 0) + 1
            return render_template('login.html')
        
        # Sanitize username
        username = sanitize_input(username)
        
        conn = sqlite3.connect('fintech.db')
        c = conn.cursor()
        
        # Use parameterized query to prevent SQL injection
        c.execute('SELECT id, username, password_hash FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()
        
        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['last_activity'] = datetime.now().isoformat()
            session.pop('login_attempts', None)
            
            log_activity(user[0], 'User logged in', request.remote_addr)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            if 'login_attempts' not in session:
                session['login_attempts'] = 0
            session['login_attempts'] = session.get('login_attempts', 0) + 1
            flash('Invalid username or password', 'error')
            return render_template('login.html')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """Secure logout with session destruction"""
    user_id = session.get('user_id')
    log_activity(user_id, 'User logged out', request.remote_addr)
    session.clear()
    flash('You have been logged out successfully', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard with transaction overview"""
    conn = sqlite3.connect('fintech.db')
    c = conn.cursor()
    
    # Get user transactions
    c.execute('''SELECT id, transaction_type, amount, description_encrypted, created_at
                 FROM transactions WHERE user_id = ? ORDER BY created_at DESC LIMIT 10''',
              (session['user_id'],))
    transactions = c.fetchall()
    
    # Decrypt transaction descriptions
    decrypted_transactions = []
    for t in transactions:
        decrypted_transactions.append({
            'id': t[0],
            'type': t[1],
            'amount': t[2],
            'description': decrypt_data(t[3]),
            'date': t[4]
        })
    
    # Calculate balance
    c.execute('''SELECT SUM(CASE WHEN transaction_type = 'deposit' THEN amount 
                                 ELSE -amount END) FROM transactions WHERE user_id = ?''',
              (session['user_id'],))
    balance = c.fetchone()[0] or 0.0
    
    conn.close()
    return render_template('dashboard.html', 
                          transactions=decrypted_transactions,
                          balance=balance)

@app.route('/transaction', methods=['GET', 'POST'])
@login_required
def transaction():
    """Create new transaction with validation"""
    if request.method == 'POST':
        transaction_type = request.form.get('type', '')
        amount = request.form.get('amount', '')
        description = request.form.get('description', '').strip()
        
        # Input validation
        if not transaction_type or not amount or not description:
            flash('All fields are required', 'error')
            return render_template('transaction.html')
        
        # Validate transaction type
        if transaction_type not in ['deposit', 'withdrawal']:
            flash('Invalid transaction type', 'error')
            return render_template('transaction.html')
        
        # Validate amount (numeric and positive)
        try:
            amount = float(amount)
            if amount <= 0:
                raise ValueError("Amount must be positive")
            if amount > 1000000:
                raise ValueError("Amount exceeds maximum limit")
        except ValueError:
            flash('Invalid amount. Please enter a valid positive number', 'error')
            return render_template('transaction.html')
        
        # Sanitize description
        description = sanitize_input(description)
        
        # Encrypt description
        description_encrypted = encrypt_data(description)
        
        # Store transaction
        conn = sqlite3.connect('fintech.db')
        c = conn.cursor()
        c.execute('''INSERT INTO transactions (user_id, transaction_type, amount, description_encrypted)
                     VALUES (?, ?, ?, ?)''',
                  (session['user_id'], transaction_type, amount, description_encrypted))
        conn.commit()
        conn.close()
        
        log_activity(session['user_id'], f'Transaction created: {transaction_type} ${amount}', 
                    request.remote_addr)
        flash('Transaction created successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('transaction.html')

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """User profile management with encryption"""
    conn = sqlite3.connect('fintech.db')
    c = conn.cursor()
    
    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        phone = request.form.get('phone', '').strip()
        address = request.form.get('address', '').strip()
        
        # Validate phone (numeric only)
        if phone:
            if not re.match(r'^[\d\s\-\+\(\)]+$', phone):
                flash('Invalid phone number format', 'error')
                return redirect(url_for('profile'))
        
        # Sanitize inputs
        full_name = sanitize_input(full_name)
        phone = sanitize_input(phone)
        address = sanitize_input(address)
        
        # Encrypt sensitive data
        full_name_enc = encrypt_data(full_name) if full_name else None
        phone_enc = encrypt_data(phone) if phone else None
        address_enc = encrypt_data(address) if address else None
        
        # Update or insert profile
        c.execute('''SELECT id FROM user_profiles WHERE user_id = ?''', (session['user_id'],))
        if c.fetchone():
            c.execute('''UPDATE user_profiles 
                         SET full_name_encrypted = ?, phone_encrypted = ?, 
                             address_encrypted = ?, updated_at = CURRENT_TIMESTAMP
                         WHERE user_id = ?''',
                      (full_name_enc, phone_enc, address_enc, session['user_id']))
        else:
            c.execute('''INSERT INTO user_profiles (user_id, full_name_encrypted, 
                         phone_encrypted, address_encrypted)
                         VALUES (?, ?, ?, ?)''',
                      (session['user_id'], full_name_enc, phone_enc, address_enc))
        
        conn.commit()
        log_activity(session['user_id'], 'Profile updated', request.remote_addr)
        flash('Profile updated successfully!', 'success')
    
    # Get current profile
    c.execute('''SELECT full_name_encrypted, phone_encrypted, address_encrypted
                 FROM user_profiles WHERE user_id = ?''', (session['user_id'],))
    profile_data = c.fetchone()
    conn.close()
    
    # Decrypt profile data
    profile = {}
    if profile_data:
        profile = {
            'full_name': decrypt_data(profile_data[0]) if profile_data[0] else '',
            'phone': decrypt_data(profile_data[1]) if profile_data[1] else '',
            'address': decrypt_data(profile_data[2]) if profile_data[2] else ''
        }
    
    return render_template('profile.html', profile=profile)

@app.route('/encrypt_decrypt', methods=['GET', 'POST'])
@login_required
def encrypt_decrypt():
    """Encryption/Decryption utility"""
    if request.method == 'POST':
        action = request.form.get('action', '')
        data = request.form.get('data', '').strip()
        
        if not data:
            flash('Please enter data to process', 'error')
            return render_template('encrypt_decrypt.html')
        
        try:
            if action == 'encrypt':
                encrypted = encrypt_data(data)
                flash(f'Encrypted: {encrypted}', 'success')
                return render_template('encrypt_decrypt.html', result=encrypted, action='encrypt')
            elif action == 'decrypt':
                decrypted = decrypt_data(data)
                flash(f'Decrypted: {decrypted}', 'success')
                return render_template('encrypt_decrypt.html', result=decrypted, action='decrypt')
            else:
                flash('Invalid action', 'error')
        except Exception as e:
            flash('Error processing data. Please check your input.', 'error')
            log_activity(session['user_id'], f'Encryption error: {str(e)}', request.remote_addr)
    
    return render_template('encrypt_decrypt.html')

@app.route('/audit_logs')
@login_required
def audit_logs():
    """View audit logs"""
    conn = sqlite3.connect('fintech.db')
    c = conn.cursor()
    c.execute('''SELECT action, ip_address, timestamp 
                 FROM audit_logs WHERE user_id = ? 
                 ORDER BY timestamp DESC LIMIT 50''',
              (session['user_id'],))
    logs = c.fetchall()
    conn.close()
    return render_template('audit_logs.html', logs=logs)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    """Secure file upload with validation"""
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected', 'error')
            return render_template('upload.html')
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected', 'error')
            return render_template('upload.html')
        
        # Validate file extension
        if not allowed_file(file.filename):
            flash('File type not allowed. Allowed types: txt, pdf, png, jpg, jpeg, gif, doc, docx', 'error')
            return render_template('upload.html')
        
        # Validate file size (already handled by MAX_CONTENT_LENGTH)
        
        # Secure filename
        filename = secure_filename(file.filename)
        
        # Create uploads directory if it doesn't exist
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])
        
        # Save file with timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{session['user_id']}_{timestamp}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        log_activity(session['user_id'], f'File uploaded: {filename}', request.remote_addr)
        flash(f'File uploaded successfully: {filename}', 'success')
        return render_template('upload.html')
    
    return render_template('upload.html')

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Error handlers
@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors without exposing sensitive info"""
    return render_template('error.html', error_code=404, 
                         message="Page not found"), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors without exposing sensitive info"""
    return render_template('error.html', error_code=500,
                         message="An internal error occurred"), 500

@app.errorhandler(413)
def request_entity_too_large(error):
    """Handle file size errors"""
    flash('File too large. Maximum size is 16MB', 'error')
    return redirect(url_for('upload_file'))

if __name__ == '__main__':
    init_db()
    # Create uploads directory
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    app.run(debug=True, host='0.0.0.0', port=8080)

