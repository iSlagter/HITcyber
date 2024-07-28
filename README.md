# Communication_LTD Project

## Project Overview

This project is a web-based information system developed for a fictional company named Communication_LTD, which markets internet packages. The system includes functionalities for user registration, login, password management, and customer management. The backend is built using Python with Flask, and the data is stored in a MySQL database. The system also demonstrates techniques to prevent SQL Injection and Cross-Site Scripting (XSS) attacks.

## Project Structure

/

├───.github

│ └───workflows/

├───communication_ltd_secure/

│ ├───static/

│ ├───templates/

│ ├───app.py

│ ├───config.py

│ ├───Dockerfile

│ ├───requirements.txt


├───communication_ltd_vulnerable/

│ ├───static/

│ ├───templates/

│ ├───app.py

│ ├───config.py

│ ├───Dockerfile

│ ├───requirements.txt


## Local Setup Instructions

### Prerequisites

1. Python 3.11
1. Docker
1. MySQL

### Step-by-Step Setup

1. **Clone the repository:**

```bash

git clone <repository-url>

cd <repository-directory>
```
2. **Set up virtual environment and install dependencies:**
```bash
python3 -m venv venv

source venv/bin/activate
# On Windows use `venv\Scripts\activate`

pip install -r requirements.txt

```
3. **Set up environment variables:**

- Create a .env file in the root directory and add the following variables:
```ini
MySQLuser=<your_mysql_user>

MySQLpasswd=<your_mysql_password>
```

4. **Set up MySQL database:**

- Start MySQL Docker container:

```bash
docker run --name mysql-communication -e MYSQL_ROOT_PASSWORD=root -e MYSQL_DATABASE=communication_ltd -p 3306:3306 -d mysql:latest
```
- Import SQL commands to create database structure and stored procedures:

```bash
docker exec -i mysql-communication mysql -uroot -proot communication_ltd < sql/sql-commands.sql

docker exec -i mysql-communication mysql -uroot -proot communication_ltd < sql/SQL-createSP.sql
```

4. **Run the Flask application:**
- note: you need to update the mysql cred at the .env file

```python

python app.py
```

5. **Access the application:**

- Open a web browser and navigate to http://localhost:80.

## with Docker
1. **Build the Docker image:**


```bash
docker build -t secure ./communication_ltd_secure .
docker build -t vulnerable ./communication_ltd_vulnerable .
```
Run the Docker container:

```bash
docker run --name communication_ltd_secure -p 80:80 --env-file .env secure
docker run --name communication_ltd_vulnerable -p 80:80 --env-file .env cvulnerable
```

2. Access the application:

- Open a web browser and navigate to http://localhost:80.


## Folder Details

**app.py**

- This is the main application file for the Flask web server. It handles routing and business logic.

**config.py**

- Configuration file for managing environment-specific settings such as password policies.

**templates/**

- This directory contains HTML template files. The base template (base.html) is extended by other templates like login.html, register.html, dashboard.html, and forgot\_password.html.

**static/**

- This directory contains static files such as CSS, JavaScript, and images.


## Security Measures

The project implements several security measures to prevent SQL Injection and Cross-Site Scripting (XSS) attacks:

Use of Stored Procedures: All SQL queries are executed via stored procedures to prevent SQL Injection.

Input Validation and Sanitization: User inputs are validated and sanitized to prevent XSS attacks.

Password Hashing with Salt: Passwords are hashed using SHA-256 along with a salt for additional security.

Secure Email Handling: Password reset tokens are securely generated and emailed to users.

## Appendix

**sql-commands.sql**

- This file contains SQL commands to set up the database schema, including table creation.

**SQL-createSP.sql**

- This file contains SQL commands to create stored procedures used in the application.

## Contact

For any questions or issues, please contact me at [dslagter99@gmail.com].
