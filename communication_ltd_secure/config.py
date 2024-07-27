# config.py
SMTP_SERVER = 'smtp.mailersend.net'
SMTP_PORT = 587
SMTP_USERNAME = 'MS_nsqVnY@trial-pr9084zxed8lw63d.mlsender.net'
SMTP_PASSWORD = 'vbfZzJ1rDkqzAwuk'
EMAIL_FROM = 'HIT <MS_nsqVnY@trial-pr9084zxed8lw63d.mlsender.net>'

PASSWORD_LENGTH = 8
PASSWORD_COMPLEXITY = True
PASSWORD_HISTORY = 3
DICTIONARY_CHECK = True
LOGIN_ATTEMPTS = 3
DICTIONARY = ["password", "123456", "qwerty", "letmein", "monkey", "football"]

import re

def is_password_valid(password):
    if len(password) < PASSWORD_LENGTH:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[!@#$%^&*]", password):
        return False
    if DICTIONARY_CHECK and password in DICTIONARY:
        return False
    return True