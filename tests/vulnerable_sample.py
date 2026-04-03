import os
import subprocess
import hashlib
import pickle
import sqlite3

# ── SECRET SCANNER will catch these ──────────────────────────────
AWS_ACCESS_KEY    = "sample"
AWS_SECRET_KEY    = "sample"
DATABASE_PASSWORD = "Sample"
API_KEY           = "sample"
GITHUB_TOKEN      = "sample"

# ── BANDIT (SAST) will catch these ───────────────────────────────

# B101 — assert used for security check (stripped in optimized mode)
def verify_admin(user):
    assert user == "admin", "Not admin!"
    return True

# B102 — exec used (dangerous)
def run_code(user_input):
    exec(user_input)

# B105 — hardcoded password
def connect_db():
    password = "hardcoded_password_123"
    return sqlite3.connect(f"db_{password}.sqlite")

# B106 — hardcoded password as function argument
def login(username, password="admin123"):
    pass

# B301 — pickle.loads is insecure (arbitrary code execution)
def load_data(data):
    return pickle.loads(data)

# B307 — eval is dangerous
def calculate(expression):
    return eval(expression)

# B404 + B602 — subprocess with shell=True (command injection)
def run_command(user_input):
    subprocess.call(user_input, shell=True)

# B501 — SSL verification disabled
def fetch_data(url):
    import urllib.request
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return urllib.request.urlopen(url, context=ctx)

# B303 — MD5 is insecure for cryptographic use
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

# B608 — SQL injection vulnerability
def get_user(username):
    conn = sqlite3.connect("users.db")
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return conn.execute(query)
