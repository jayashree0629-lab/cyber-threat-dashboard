from flask import Flask, render_template, request, redirect, url_for
import sqlite3
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
import requests

# Password Hashing
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# -----------------------------
# HASHED PASSWORD
# -----------------------------

stored_password = generate_password_hash("1234")

# -----------------------------
# GEO LOCATION FUNCTION
# -----------------------------

def get_location(ip_address):

    try:

        url = f"http://ip-api.com/json/{ip_address}"

        response = requests.get(url)

        data = response.json()

        country = data.get("country", "Unknown")

        city = data.get("city", "Unknown")

        return country, city

    except:

        return "Unknown", "Unknown"

# -----------------------------
# EMAIL ALERT FUNCTION
# -----------------------------

def send_alert_email():

    sender_email = "jayy290506@gmail.com"

    app_password = "lars qsbn qong htcn"

    receiver_email = "jayy290506@gmail.com"

    subject = "Cyber Threat Alert"

    body = """
    Warning!

    Suspicious login activity detected
    in your Cyber Threat Dashboard.
    """

    msg = MIMEText(body)

    msg['Subject'] = subject
    msg['From'] = sender_email
    msg['To'] = receiver_email

    server = smtplib.SMTP('smtp.gmail.com', 587)

    server.starttls()

    server.login(sender_email, app_password)

    server.send_message(msg)

    server.quit()

# -----------------------------
# DATABASE SETUP
# -----------------------------

def init_db():

    conn = sqlite3.connect('database.db')

    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            username TEXT,

            status TEXT,

            time TEXT,

            ip_address TEXT,

            country TEXT,

            city TEXT
        )
    ''')

    conn.commit()

    conn.close()


init_db()

# -----------------------------
# GLOBAL VARIABLES
# -----------------------------

failed_attempts = 0

threat_message = "✅ System Safe"

# -----------------------------
# LOGIN PAGE
# -----------------------------

@app.route('/', methods=['GET', 'POST'])
def home():

    global failed_attempts
    global threat_message

    message = ""

    # Lock account after 3 attempts
    if failed_attempts >= 3:

        message = "🚫 Account Temporarily Locked"

        return render_template(
            'login.html',
            message=message
        )

    if request.method == 'POST':

        username = request.form['username']

        password = request.form['password']

        # IP Address
        ip_address = "8.8.8.8"

        # Geo Location
        country, city = get_location(ip_address)

        # -----------------------------
        # CORRECT LOGIN
        # -----------------------------

        if username == "admin" and check_password_hash(
            stored_password,
            password
        ):

            conn = sqlite3.connect('database.db')

            cursor = conn.cursor()

            cursor.execute(
                """
                INSERT INTO logs
                (username, status, time,
                 ip_address, country, city)

                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    username,
                    "Success",
                    str(datetime.now()),
                    ip_address,
                    country,
                    city
                )
            )

            conn.commit()

            conn.close()

            failed_attempts = 0

            threat_message = "✅ System Safe"

            return redirect(url_for('dashboard'))

        # -----------------------------
        # WRONG LOGIN
        # -----------------------------

        else:

            failed_attempts += 1

            conn = sqlite3.connect('database.db')

            cursor = conn.cursor()

            cursor.execute(
                """
                INSERT INTO logs
                (username, status, time,
                 ip_address, country, city)

                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    username,
                    "Failed",
                    str(datetime.now()),
                    ip_address,
                    country,
                    city
                )
            )

            conn.commit()

            conn.close()

            message = f"❌ Login Failed - Attempt {failed_attempts}"

            # Threat Detection
            if failed_attempts >= 3:

                threat_message = "🚨 Suspicious Activity Detected!"

                # Send Email Alert
                send_alert_email()

    return render_template(
        'login.html',
        message=message
    )

# -----------------------------
# DASHBOARD
# -----------------------------

@app.route('/dashboard')
def dashboard():

    conn = sqlite3.connect('database.db')

    cursor = conn.cursor()

    # Fetch Logs
    cursor.execute("SELECT * FROM logs")

    logs = cursor.fetchall()

    # Success Count
    cursor.execute(
        "SELECT COUNT(*) FROM logs WHERE status='Success'"
    )

    success_count = cursor.fetchone()[0]

    # Failed Count
    cursor.execute(
        "SELECT COUNT(*) FROM logs WHERE status='Failed'"
    )

    failed_count = cursor.fetchone()[0]

    conn.close()

    return render_template(
        'dashboard.html',

        attempts=failed_attempts,

        threat=threat_message,

        logs=logs,

        success_count=success_count,

        failed_count=failed_count
    )

# -----------------------------
# RUN APP
# -----------------------------

if __name__ == '__main__':

    app.run(debug=True)