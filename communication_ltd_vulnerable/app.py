from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash, send_from_directory
import mysql.connector
from dotenv import load_dotenv
import hashlib
import os
from functools import wraps  # ייבוא wraps
import smtplib
from email.mime.text import MIMEText
import logging
from config import *

logging.basicConfig(level=logging.DEBUG)

load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24)

cnx = mysql.connector.connect(
    host="hit-slagter-mysql.mysql.database.azure.com",
    user=os.getenv('MySQLuser'),
    passwd=os.getenv('MySQLpasswd'),
    database="communication_ltd_vulnerable",
    port=3306,
    ssl_disabled=True
)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("You need to be logged in to access this page", 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def is_password_in_history(user_id, password):
    cursor = cnx.cursor()
    cursor.execute("SELECT password FROM password_history_vulnerable WHERE user_id = %s ORDER BY change_date DESC LIMIT %s", (user_id, PASSWORD_HISTORY))
    history = cursor.fetchall()
    for old_password_hash in history:
        if password == old_password_hash[0]:
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
            cursor = cnx.cursor()
            cursor.execute("INSERT INTO reset_tokens_vulnerable (user_id, token) VALUES (%s, %s)", (user_id, reset_token))
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

        # הדפסת הנתונים שנשלחים
        print(f"Received data: username='{username}', email='{email}', password='{password}'")

        # בניית השאילתה
        query_user = f"INSERT INTO users_vulnerable (username, email, password) VALUES ('{username}', '{email}', '{password}')"
        print(f"Constructed query: {query_user}")

        cursor = cnx.cursor()
        try:
            for result in cursor.execute(query_user, multi=True):
                if result.with_rows:
                    injection_result = result.fetchall()
                    flash(f"{injection_result}", category='danger')
            cnx.commit()
            
            flash(f"User {username} added successfully! Email: {email}", category='success')
        except mysql.connector.Error as e:
            cnx.rollback()
            flash(f"An error occurred: {e}", 'danger')
            print(f"An error occurred: {e}")  # הדפסת השגיאה לקונסול
        finally:
            cursor.close()

        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'redirect': url_for('register')})
        return redirect(url_for('register'))
    return render_template('register.html', password_length=8, dictionary=[])

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        query_if_exist = f"SELECT username FROM users_vulnerable WHERE (username = '{username}') LIMIT 1"
        cursor = cnx.cursor()
        query = f"SELECT * FROM users_vulnerable WHERE (username = '{username}' ) AND (password = '{password}' ) LIMIT 1"
        logging.debug(f"Executing query: {query}")
        
        cursor.execute(query)
        user = cursor.fetchone()
        cursor.execute(query_if_exist)
        user_exist = cursor.fetchone()


        
        # קריאת כל התוצאות שנותרו מהשאילתה הקודמת לפני ביצוע פעולות נוספות
        while cursor.nextset():
            try:
                cursor.fetchall()
            except mysql.connector.errors.InterfaceError:
                break
        
        cursor.close()
        if not user_exist:
            flash(f"User: {username} not exist.", category='danger')
        else:
            if user:
                session['user_id'] = user[0]
                session['username'] = user[1]
                session.pop('login_attempts', None)  # Reset login attempts
                
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({'redirect': url_for('dashboard')})
                return redirect(url_for('dashboard'))
            else:
                if 'login_attempts' not in session:
                    session['login_attempts'] = 0
                session['login_attempts'] += 1
                remaining_attempts = 3 - session['login_attempts']
                if remaining_attempts > 0:
                    flash(f"Invalid password. You have {remaining_attempts} attempts left.", category='danger')
                else:
                    flash("You have exceeded the maximum number of login attempts. Please try again later.", 'danger')
                    session.pop('login_attempts', None)  # Reset after exceeding
                
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({'redirect': url_for('login')})
                return redirect(url_for('login'))
    return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    user_id = session.get('user_id')
    cursor = cnx.cursor()
    
    cursor.execute(f"SELECT username FROM users_vulnerable WHERE id = '{user_id}'")
    result = cursor.fetchone()
    
    if result:
        username = result[0]
        print(username)
    else:
        flash("User not found", 'danger')
        return redirect(url_for('login'))
    
    cursor.execute("SELECT first_name, last_name, address FROM customers_vulnerable")
    customers = cursor.fetchall()
    # קריאת כל התוצאות שנותרו מהשאילתה הקודמת לפני ביצוע פעולות נוספות
    while cursor.nextset():
        try:
            cursor.fetchall()
        except mysql.connector.errors.InterfaceError:
            break
    
    cursor.close()

    return render_template('dashboard.html', customers=customers, username=session['username'] )


@app.route('/add_customer', methods=['GET', 'POST'])
@login_required
def add_customer():
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        address = request.form.get('address')

        # הדפסת הנתונים שנשלחים
        print(f"Received data: first_name='{first_name}', last_name='{last_name}', address='{address}'")

        # בניית השאילתה
        query = f"INSERT INTO customers_vulnerable (first_name, last_name, address) VALUES ('{first_name}', '{last_name}', '{address}')"
        print(f"Constructed query: {query}")  

        cursor = cnx.cursor()
        try:
            for result in cursor.execute(query, multi=True):
                if result.with_rows:
                    injection_result = result.fetchall()
                    flash(f"{injection_result}", category='danger')
            cnx.commit()

            flash(f"Customer added successfully! First Name: {first_name}, Last Name: {last_name}, Address: {address}", 'success')
        except mysql.connector.Error as e:
            cnx.rollback()
            flash(f"An error occurred: {e}", 'danger')
            print(f"An error occurred: {e}")  # הדפסת השגיאה לקונסול
        finally:
            cursor.close()

        return redirect(url_for('add_customer'))
    return render_template('add_customer.html')

    # if request.method == 'POST':
    #     first_name = request.form['first_name']
    #     last_name = request.form['last_name']
    #     address = request.form['address']
        
    #     cursor = cnx.cursor()
    #     cursor.execute(f"INSERT INTO customers_vulnerable (first_name, last_name, address) VALUES ('{first_name}', '{last_name}', '{address}')")
    #     logging.debug(f"INSERT INTO customers_vulnerable (first_name, last_name, address) VALUES ('{first_name}', '{last_name}', '{address}')")
    #     cnx.commit()
    #     cursor.close()
        
    #     return redirect(url_for('dashboard'))
    # return render_template('add_customer.html')


@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    user_id = session.get('user_id')

    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        
        cursor = cnx.cursor()
        cursor.execute(f"SELECT password FROM users_vulnerable WHERE password = '{current_password}' AND id = '{user_id}'")
        user = cursor.fetchone()
        if not user or (current_password != user[0]):
            flash("Current password is incorrect", 'danger')
            return redirect(url_for('change_password'))
        
        if not is_password_valid(new_password):
            flash("Password does not meet complexity requirements", 'danger')
            return redirect(url_for('change_password'))
        
        if is_password_in_history(user_id, new_password):
            flash("New password was used recently. Please choose a different password.", 'danger')
            return redirect(url_for('change_password'))

        cursor.execute("UPDATE users_vulnerable SET password = %s WHERE id = %s", (new_password, user_id))
        cursor.execute("INSERT INTO password_history_vulnerable (user_id, password) VALUES (%s, %s)", (user_id, new_password))
        cnx.commit()
        cursor.close()

        flash("Password changed successfully")
        return redirect(url_for('dashboard'))
    return render_template('change_password.html', 
                           password_length=PASSWORD_LENGTH, 
                           dictionary=DICTIONARY)


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        
        cursor = cnx.cursor()
        cursor.execute("SELECT id FROM users_vulnerable WHERE email = %s", (email,))
        user = cursor.fetchone()
        cnx.commit()
        cursor.close()

        if user:
            user_id = user[0]
            reset_token = hashlib.sha1(os.urandom(24)).hexdigest()
            send_reset_email(email, reset_token, user_id)
            return redirect(url_for('verify_token', email=email))
        else:
            flash("Email not found", 'danger')
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return render_template('forgot_password.html')
            else:
                return redirect(url_for('forgot_password'))
    return render_template('forgot_password.html')



@app.route('/verify_token', methods=['GET', 'POST'])
def verify_token():
    if request.method == 'POST':
        email = request.form['email']
        token = request.form['token']
        
        cursor = cnx.cursor()
        cursor.execute("""
            SELECT rt.user_id
            FROM reset_tokens_vulnerable rt
            JOIN users_vulnerable u ON rt.user_id = u.id
            WHERE rt.token = %s AND u.email = %s
        """, (token, email))
        result = cursor.fetchone()
        cnx.commit()
        cursor.close()
        
        if result:
            user_id = result[0]
            session['reset_user_id'] = user_id
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'redirect': url_for('reset_password')})
            else:
                return redirect(url_for('reset_password'))
        else:
            flash("Invalid token or email", 'danger')
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'error': 'Invalid token or email'})
            else:
                return redirect(url_for('verify_token', email=email))
    return render_template('verify_token.html', email=request.args.get('email'))


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        user_id = session.get('reset_user_id')
        new_password = request.form['new_password']
        
        cursor = cnx.cursor()
        cursor.execute("SELECT password FROM users_vulnerable WHERE id = %s", (user_id,))
        result = cursor.fetchone()
        
        if result:
            if is_password_valid(new_password) and not is_password_in_history(user_id, new_password):
                logging.debug("the password is good")
                cursor.execute("UPDATE users_vulnerable SET password = %s WHERE id = %s", (new_password, user_id))
                cursor.execute("INSERT INTO password_history_vulnerable (user_id, password) VALUES (%s, %s)", (user_id, new_password))
                cnx.commit()
                cursor.close()
                session.pop('reset_user_id', None)
                flash("Password has been reset successfully, Redirecting you to the login page...", 'success')
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({'redirect': url_for('login')})
                else:
                    return redirect(url_for('login'))

            else:
                flash("New password does not meet requirements or was used recently.", 'danger')
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return render_template('reset_password.html')
                else:
                    return redirect(url_for('reset_password'))
        else:
            flash("User not found", 'danger')
            cnx.commit()
            cursor.close()
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return render_template('reset_password.html')
            else:
                return redirect(url_for('reset_password'))
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
