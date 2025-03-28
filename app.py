from flask import Flask, render_template, request, redirect, url_for, session, flash
import random
import string
from flask_mail import Mail, Message
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import re

app = Flask(__name__)
app.secret_key = 'CodeNinja2025'  

# Database configuration
DATABASE = 'users.db'

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'abc@gmail.com'  
app.config['MAIL_PASSWORD'] = '@abc123'  
app.config['MAIL_DEFAULT_SENDER'] = 'abc@gmail.com'  

mail = Mail(app)

# Initialize database
def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            contact_no TEXT UNIQUE,
            password TEXT,
            is_verified INTEGER DEFAULT 0,
            user_type TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# Helper functions
def generate_otp(length=6):
    return ''.join(random.choices(string.digits, k=length))

def is_valid_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email)

def is_valid_phone(phone):
    pattern = r'^[0-9]{10}$'  # Simple 10-digit phone number validation
    return re.match(pattern, phone)

# Routes
@app.route("/")
def home():
    return render_template("home.html")

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identifier = request.form['identifier']
        password = request.form['password']
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Check if identifier is email or phone
        if is_valid_email(identifier):
            cursor.execute('SELECT * FROM users WHERE email = ?', (identifier,))
        elif is_valid_phone(identifier):
            cursor.execute('SELECT * FROM users WHERE contact_no = ?', (identifier,))
        else:
            flash('Invalid email or phone number format', 'error')
            return redirect(url_for('login'))
        
        user = cursor.fetchone()
        conn.close()
        
        if user and check_password_hash(user[3], password):
            if user[4]:  # If verified
                session['user_id'] = user[0]
                session['user_type'] = user[5]
                
                if user[5] == 'ngo':
                    return redirect(url_for('ngo_dashboard'))
                else:
                    return redirect(url_for('student_dashboard'))
            else:
                flash('Account not verified. Please verify your account.', 'error')
                return redirect(url_for('login'))
        else:
            flash('Invalid credentials', 'error')
            return redirect(url_for('login'))
    
    return render_template("login.html")

@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        contact_no = request.form.get('contact_no')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        user_type = request.form.get('user_type')  # 'ngo' or 'student'
        
        # Validation
        if not is_valid_email(email):
            flash('Invalid email address', 'error')
            return redirect(url_for('register'))
        
        if not is_valid_phone(contact_no):
            flash('Invalid phone number (must be 10 digits)', 'error')
            return redirect(url_for('register'))
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('register'))
        
        if len(password) < 8:
            flash('Password must be at least 8 characters', 'error')
            return redirect(url_for('register'))
        
        # Check if user already exists
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM users WHERE email = ? OR contact_no = ?', (email, contact_no))
        if cursor.fetchone():
            conn.close()
            flash('Email or phone number already registered', 'error')
            return redirect(url_for('register'))
        
        # Generate OTP
        otp = generate_otp()
        session['registration_data'] = {
            'email': email,
            'contact_no': contact_no,
            'password': generate_password_hash(password),
            'user_type': user_type,
            'otp': otp
        }
        
        # Send OTP via email
        try:
            msg = Message('Your OTP for Verification', recipients=[email])
            msg.body = f'Your OTP is: {otp}'
            mail.send(msg)
            flash('OTP sent to your email', 'success')
        except Exception as e:
            flash('Failed to send OTP. Please try again.', 'error')
            return redirect(url_for('register'))
        
        conn.close()
        return redirect(url_for('verify_otp'))
    
    return render_template("register.html")

@app.route("/verify-otp", methods=['GET', 'POST'])
def verify_otp():
    if 'registration_data' not in session:
        return redirect(url_for('register'))
    
    if request.method == 'POST':
        user_otp = request.form.get('otp')
        
        if user_otp == session['registration_data']['otp']:
            # Save user to database
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO users (email, contact_no, password, is_verified, user_type)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                session['registration_data']['email'],
                session['registration_data']['contact_no'],
                session['registration_data']['password'],
                1,  # Verified
                session['registration_data']['user_type']
            ))
            conn.commit()
            conn.close()
            
            # Clear session data
            session.pop('registration_data', None)
            
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid OTP', 'error')
            return redirect(url_for('verify_otp'))
    
    return render_template("verify_otp.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route("/ngo-dashboard")
def ngo_dashboard():
    if 'user_id' not in session or session.get('user_type') != 'ngo':
        return redirect(url_for('login'))
    return render_template("ngoDash.html")

@app.route("/student-dashboard")
def student_dashboard():
    if 'user_id' not in session or session.get('user_type') != 'student':
        return redirect(url_for('login'))
    return render_template("studentDash.html")

if __name__ == "__main__":
    app.run(debug=True) 