from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash, send_from_directory
import mysql.connector
import hashlib
import random
import string
import os
from functools import wraps 
import smtplib
from email.mime.text import MIMEText
import logging
from config import *
from dotenv import load_dotenv

logging.basicConfig(level=logging.DEBUG)

load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24)

cnx = mysql.connector.connect(
    host="hit-slagter-mysql.mysql.database.azure.com",
    user=os.getenv('MySQLuser'),
    passwd=os.getenv('MySQLpasswd'),
    database="communication_ltd_secure",
    port=3306,
    ssl_disabled=True
)

def generate_salt():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=16))

def hash_password(password, salt):
    return hashlib.sha256((password + salt).encode('utf-8')).hexdigest()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("You need to be logged in to access this page", 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def is_password_in_history(user_id, new_password_hash):
    cursor = cnx.cursor()
    cursor.callproc('get_password_history', (user_id, PASSWORD_HISTORY))
    for result in cursor.stored_results():
        history = result.fetchall()
        for old_password_hash in history:
            if new_password_hash == old_password_hash[0]:
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
        
            cursor = cnx.cursor()
            cursor.callproc('add_reset_token', (user_id, reset_token))
            cnx.commit()
            cursor.close()
    except Exception as e:
        logging.error(f"Failed to send email: {e}")

@app.route('/static/background')
def static_files(filename):
    return send_from_directory(app.static_folder, filename)
        
@app.route('/')
def default():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        salt = generate_salt()
        password_hash = hash_password(password, salt)

        cursor = cnx.cursor()
        try:
            cursor.callproc('add_user', (username, email, password_hash, salt))
            cnx.commit()
            flash(f"User {username} added successfully! Email: {email}", category='success')
        except mysql.connector.Error as e:
            cnx.rollback()
            flash(f"An error occurred: {e}", 'danger')
            print(f"An error occurred: {e}")  
        finally:
            cursor.close()

        return redirect(url_for('login'))
    return render_template('register.html', password_length=PASSWORD_LENGTH, dictionary=DICTIONARY)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        cursor = cnx.cursor()
        cursor.callproc('get_user_by_username', (username,))
        user = next(cursor.stored_results()).fetchone()
        cursor.close()

        if not user:
            flash(f"User: {username} does not exist.", category='danger')
            return redirect(url_for('login'))

        if hash_password(password, user[2]) == user[1]:
            session['user_id'] = user[0]
            session.pop('login_attempts', None)  # Reset login attempts
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'redirect': url_for('dashboard')})
            else:
                return redirect(url_for('dashboard'))
        else:
            if 'login_attempts' not in session:
                session['login_attempts'] = 0
            session['login_attempts'] += 1
            remaining_attempts = 3 - session['login_attempts']
            if remaining_attempts > 0:
                flash(f"Invalid password. You have {remaining_attempts} attempts left.", 'danger')
            else:
                flash("You have exceeded the maximum number of login attempts. Please try again later.", 'danger')
                session.pop('login_attempts', None)  # Reset after exceeding
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'redirect': url_for('login')})
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session.get('user_id')
    cursor = cnx.cursor()
    
    cursor.callproc('get_username_by_id', (user_id,))
    result = next(cursor.stored_results()).fetchone()
    
    if result:
        logging.debug(result)
        username = result[0]
    else:
        flash("User not found", 'danger')
        return redirect(url_for('login'))
    
    cursor.callproc('get_all_customers')
    customers = next(cursor.stored_results()).fetchall()
    cursor.close()

    return render_template('dashboard.html', customers=customers, username=username)

@app.route('/add_customer', methods=['GET', 'POST'])
@login_required
def add_customer():
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        address = request.form.get('address')

        cursor = cnx.cursor()
        try:
            cursor.callproc('add_customer', (first_name, last_name, address))
            cnx.commit()
            flash(f"Customer added successfully! First Name: {first_name}, Last Name: {last_name}, Address: {address}", 'success')
        except mysql.connector.Error as e:
            cnx.rollback()
            flash(f"An error occurred: {e}", 'danger')
            print(f"An error occurred: {e}")  
        finally:
            cursor.close()

        return redirect(url_for('add_customer'))
    return render_template('add_customer.html')

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    user_id = session.get('user_id')

    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        
        cursor = cnx.cursor()
        cursor.callproc('get_user_by_id', (user_id,))
        user = next(cursor.stored_results()).fetchone()
        
        if not user or hash_password(current_password, user[2]) != user[1]:
            flash("Current password is incorrect", 'danger')
            return redirect(url_for('change_password'))
        
        if not is_password_valid(new_password):
            flash("Password does not meet complexity requirements", 'danger')
            return redirect(url_for('change_password'))
        
        new_password_hash = hash_password(new_password, user[2])

        if is_password_in_history(user_id, new_password_hash):
            flash("New password was used recently. Please choose a different password.", 'danger')
            return redirect(url_for('change_password'))

        cursor.callproc('update_password', (user_id, new_password_hash))
        cursor.callproc('add_password_history', (user_id, new_password_hash))
        cnx.commit()
        cursor.close()

        flash("Password changed successfully", category='success')
        return redirect(url_for('change_password'))
    return render_template('change_password.html', password_length=PASSWORD_LENGTH, dictionary=DICTIONARY)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        
        cursor = cnx.cursor()
        cursor.callproc('get_user_by_email', (email,))
        user = next(cursor.stored_results()).fetchone()
        cursor.close()

        if user:
            user_id = user[0]
            reset_token = hashlib.sha1(os.urandom(24)).hexdigest()
            send_reset_email(email, reset_token, user_id)
            return redirect(url_for('verify_token', email=email))
        else:
            flash("Email not found", 'danger')
    return render_template('forgot_password.html')

@app.route('/verify_token', methods=['GET', 'POST'])
def verify_token():
    if request.method == 'POST':
        email = request.form['email']
        token = request.form['token']
        
        cursor = cnx.cursor()
        cursor.callproc('get_user_by_reset_token', (token, email))
        result = next(cursor.stored_results()).fetchone()
        cursor.close()
        
        if result:
            user_id = result[0]
            session['reset_user_id'] = user_id
            return redirect(url_for('reset_password'))
        else:
            flash("Invalid token or email", 'danger')
    return render_template('verify_token.html', email=request.args.get('email'))

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        user_id = session.get('reset_user_id')
        new_password = request.form['new_password']
        
        cursor = cnx.cursor()
        cursor.callproc('get_user_by_id', (user_id,))
        result = next(cursor.stored_results()).fetchone()
        
        if result:
            salt = result[2]
            new_password_hash = hash_password(new_password, salt)
            
            if is_password_valid(new_password) and not is_password_in_history(user_id, new_password_hash):
                cursor.callproc('update_password', (user_id, new_password_hash))
                cursor.callproc('add_password_history', (user_id, new_password_hash))
                cnx.commit()
                session.pop('reset_user_id', None)
                flash("Password has been reset successfully, Redirecting you to the login page...", 'success')
                return redirect(url_for('login'))
            else:
                flash("New password does not meet requirements or was used recently.", 'danger')
        else:
            flash("User not found", 'danger')
    return render_template('reset_password.html')

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=80, debug=True)
