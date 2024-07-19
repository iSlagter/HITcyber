from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
import MySQLdb
import hashlib
import os
import random
import string
import re
import smtplib
from email.mime.text import MIMEText
import logging
from config import *

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = os.urandom(24)

db = MySQLdb.connect(
    host="localhost",
    user="root",
    passwd="qwe123",
    db="communication_ltd"
)

def generate_salt():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=16))

def hash_password(password, salt):
    return hashlib.sha256((password + salt).encode('utf-8')).hexdigest()

def is_password_in_dictionary(password):
    if DICTIONARY_CHECK:
        for word in DICTIONARY:
            if word in password:
                return True
    return False

def is_password_valid(password):
    if len(password) < PASSWORD_LENGTH:
        return False
    if PASSWORD_COMPLEXITY:
        if not re.search(r"[A-Z]", password):
            return False
        if not re.search(r"[a-z]", password):
            return False
        if not re.search(r"[0-9]", password):
            return False
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            return False
    if is_password_in_dictionary(password):
        return False
    return True

def is_password_in_history(user_id, password_hash):
    cursor = db.cursor()
    cursor.execute("SELECT password_hash FROM password_history WHERE user_id = %s ORDER BY change_date DESC LIMIT %s", (user_id, PASSWORD_HISTORY))
    history = cursor.fetchall()
    for old_password_hash in history:
        if password_hash == old_password_hash[0]:
            return True
    return False

def send_reset_email(to_email, reset_token, user_id):
    try:
        msg = MIMEText(f"Use this token to reset your password: {reset_token}")
        msg['Subject'] = 'Password Reset Request - HIT Final project cyber'
        msg['From'] = EMAIL_FROM
        msg['To'] = to_email

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)
            logging.debug("The email was sent successfully.")
        
            # שמירת ה-token במסד הנתונים
            cursor = db.cursor()
            cursor.execute("INSERT INTO reset_tokens (user_id, token) VALUES (%s, %s)", (user_id, reset_token))
            db.commit()
            cursor.close()
    except Exception as e:
        logging.error(f"Failed to send email: {e}")
        

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        if not is_password_valid(password):
            flash("Password does not meet complexity requirements or is too common.")
        
        salt = generate_salt()
        password_hash = hash_password(password, salt)
        
        cursor = db.cursor()
        cursor.execute("INSERT INTO users (username, email, password_hash, salt) VALUES (%s, %s, %s, %s)", (username, email, password_hash, salt))
        user_id = cursor.lastrowid
        cursor.execute("INSERT INTO password_history (user_id, password_hash) VALUES (%s, %s)", (user_id, password_hash))
        db.commit()
        cursor.close()
        
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        cursor = db.cursor()
        cursor.execute("SELECT id, password_hash, salt FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        
        if user and hash_password(password, user[2]) == user[1]:
            session['user_id'] = user[0]
            session.pop('login_attempts', None)  # Reset login attempts
            return redirect(url_for('dashboard'))
        else:
            if 'login_attempts' not in session:
                session['login_attempts'] = 0
            session['login_attempts'] += 1
            remaining_attempts = LOGIN_ATTEMPTS - session['login_attempts']
            if remaining_attempts > 0:
                flash(f"Invalid username or password. You have {remaining_attempts} attempts left.")
            else:
                flash("You have exceeded the maximum number of login attempts. Please try again later.")
                session.pop('login_attempts', None)  # Reset after exceeding
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    cursor = db.cursor()
    cursor.execute("SELECT first_name, last_name, address FROM customers")
    customers = cursor.fetchall()
    cursor.close()
    
    return render_template('dashboard.html', customers=customers)

@app.route('/add_customer', methods=['GET', 'POST'])
def add_customer():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        address = request.form['address']
        
        cursor = db.cursor()
        cursor.execute("INSERT INTO customers (first_name, last_name, address) VALUES (%s, %s, %s)", (first_name, last_name, address))
        db.commit()
        cursor.close()
        
        return redirect(url_for('dashboard'))
    return render_template('add_customer.html')

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if request.method == 'POST':
        user_id = session.get('user_id')
        current_password = request.form['current_password']
        new_password = request.form['new_password']

        # בדיקה אם הסיסמא הנוכחית נכונה
        cursor = db.cursor()
        cursor.execute("SELECT password_hash, salt FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        if not user or hash_password(current_password, user[1]) != user[0]:
            return "Current password is incorrect"
        
        # בדיקת תקינות הסיסמא החדשה לפי הקונפיגורציה
        if not is_password_valid(new_password):
            return "Password does not meet complexity requirements"
        
        new_password_hash = hash_password(new_password, user[1])

        # בדיקת היסטוריית הסיסמאות
        if is_password_in_history(user_id, new_password_hash):
            return "New password was used recently. Please choose a different password."

        # שמירת הסיסמא החדשה והוספתה להיסטוריית הסיסמאות
        cursor.execute("UPDATE users SET password_hash = %s WHERE id = %s", (new_password_hash, user_id))
        cursor.execute("INSERT INTO password_history (user_id, password_hash) VALUES (%s, %s)", (user_id, new_password_hash))
        db.commit()
        cursor.close()

        flash("Password changed successfully")
    return render_template('change_password.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        
        cursor = db.cursor()
        cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        
        if user:
            user_id = user[0]
            reset_token = hashlib.sha1(os.urandom(24)).hexdigest()
            send_reset_email(email, reset_token, user_id)
            return redirect(url_for('verify_token', email=email))
        else:
            flash("Email not found")
    return render_template('forgot_password.html')

@app.route('/verify_token', methods=['GET', 'POST'])
def verify_token():
    if request.method == 'POST':
        email = request.form['email']
        token = request.form['token']
        
        cursor = db.cursor()
        cursor.execute("""
            SELECT rt.user_id
            FROM reset_tokens rt
            JOIN users u ON rt.user_id = u.id
            WHERE rt.token = %s AND u.email = %s
        """, (token, email))
        result = cursor.fetchone()
        
        if result:
            user_id = result[0]
            session['reset_user_id'] = user_id
            return redirect(url_for('reset_password'))
        else:
            flash("Invalid token or email")
    return render_template('verify_token.html', email=request.args.get('email'))


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        user_id = session.get('reset_user_id')
        new_password = request.form['new_password']
        
        cursor = db.cursor()
        cursor.execute("SELECT salt FROM users WHERE id = %s", (user_id,))
        result = cursor.fetchone()
        
        if result:
            salt = result[0]
            new_password_hash = hash_password(new_password, salt)
            
            if is_password_valid(new_password) and not is_password_in_history(user_id, new_password_hash):
                logging.debug("the password is good")
                cursor.execute("UPDATE users SET password_hash = %s WHERE id = %s", (new_password_hash, user_id))
                cursor.execute("INSERT INTO password_history (user_id, password_hash) VALUES (%s, %s)", (user_id, new_password_hash))
                db.commit()
                session.pop('reset_user_id', None)
                flash("Password has been reset successfully, Redirecting you to the home page...")
                return redirect(url_for('dashboard'))

            else:
                flash("New password does not meet requirements or was used recently.")
        else:
            flash("User not found")
    return render_template('reset_password.html')

if __name__ == '__main__':
    app.run(debug=True)
