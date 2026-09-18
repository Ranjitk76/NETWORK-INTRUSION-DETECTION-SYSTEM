from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime
import os
import time

app = Flask(__name__)
app.secret_key = "basic-nids-secret-key"

DATABASE = "nids.db"

# Password recovery key for the local educational NIDS project
PASSWORD_RESET_KEY = "NIDS-RESET-2026"

DETECTOR_STATUS_FILE = "detector_status.txt"


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_database():

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            destination_ip TEXT NOT NULL,
            source_port INTEGER,
            destination_port INTEGER,
            protocol TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT
        )
    """)

    user = cursor.execute(
        "SELECT id FROM users WHERE username = ?",
        ("admin",)
    ).fetchone()

    if user is None:

        cursor.execute("""
            INSERT INTO users (
                username,
                password,
                created_at
            )
            VALUES (?, ?, ?)
        """, (
            "admin",
            generate_password_hash("admin123"),
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))

    conn.commit()
    conn.close()


def login_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if "username" not in session:
            return redirect(url_for("login"))

        return function(*args, **kwargs)

    return wrapper


def get_detector_status():

    if not os.path.exists(DETECTOR_STATUS_FILE):

        return {
            "online": False,
            "status": "OFFLINE",
            "last_seen": None
        }

    try:

        modified_time = os.path.getmtime(
            DETECTOR_STATUS_FILE
        )

        current_time = time.time()

        age = current_time - modified_time

        if age <= 15:

            with open(
                DETECTOR_STATUS_FILE,
                "r",
                encoding="utf-8"
            ) as file:

                last_seen = file.read().strip()

            return {
                "online": True,
                "status": "ONLINE",
                "last_seen": last_seen
            }

    except Exception:
        pass

    return {
        "online": False,
        "status": "OFFLINE",
        "last_seen": None
    }


def get_dashboard_data():

    conn = get_db()

    total_alerts = conn.execute(
        "SELECT COUNT(*) FROM alerts"
    ).fetchone()[0]

    high_alerts = conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE severity = 'HIGH'"
    ).fetchone()[0]

    medium_alerts = conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE severity = 'MEDIUM'"
    ).fetchone()[0]

    low_alerts = conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE severity = 'LOW'"
    ).fetchone()[0]

    port_scan_count = conn.execute(
        "SELECT COUNT(*) FROM alerts "
        "WHERE attack_type LIKE '%Port Scan%'"
    ).fetchone()[0]

    alerts = conn.execute("""
        SELECT *
        FROM alerts
        ORDER BY id DESC
        LIMIT 50
    """).fetchall()

    attack_types = conn.execute("""
        SELECT attack_type, COUNT(*) AS count
        FROM alerts
        GROUP BY attack_type
        ORDER BY count DESC
    """).fetchall()

    protocols = conn.execute("""
        SELECT protocol, COUNT(*) AS count
        FROM alerts
        GROUP BY protocol
        ORDER BY count DESC
    """).fetchall()

    source_ips = conn.execute("""
        SELECT source_ip, COUNT(*) AS count
        FROM alerts
        GROUP BY source_ip
        ORDER BY count DESC
        LIMIT 5
    """).fetchall()

    conn.close()

    return {
        "total_alerts": total_alerts,
        "high_alerts": high_alerts,
        "medium_alerts": medium_alerts,
        "low_alerts": low_alerts,
        "port_scan_count": port_scan_count,
        "alerts": [dict(alert) for alert in alerts],
        "attack_types": [dict(row) for row in attack_types],
        "protocols": [dict(row) for row in protocols],
        "source_ips": [dict(row) for row in source_ips]
    }


@app.route("/", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        conn = get_db()

        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        conn.close()

        if user and check_password_hash(
            user["password"],
            password
        ):

            session["username"] = username

            return redirect(
                url_for("dashboard")
            )

        flash(
            "Invalid username or password.",
            "error"
        )

    return render_template(
        "login.html"
    )


@app.route("/dashboard")
@login_required
def dashboard():

    data = get_dashboard_data()

    detector = get_detector_status()

    return render_template(
        "dashboard.html",
        username=session["username"],
        detector=detector,
        **data
    )


@app.route("/api/alerts")
@login_required
def api_alerts():

    data = get_dashboard_data()

    data["detector"] = get_detector_status()

    return jsonify(data)


@app.route("/api/detector-status")
@login_required
def detector_status():

    return jsonify(
        get_detector_status()
    )


@app.route("/add-test-alert", methods=["POST"])
@login_required
def add_test_alert():

    conn = get_db()

    conn.execute("""
        INSERT INTO alerts (
            timestamp,
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            protocol,
            attack_type,
            severity,
            description
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        "192.168.1.100",
        "192.168.1.1",
        52341,
        22,
        "TCP",
        "Possible Port Scan",
        "HIGH",
        "Multiple destination ports detected in a short period."
    ))

    conn.commit()
    conn.close()

    flash(
        "Test security alert added successfully.",
        "success"
    )

    return redirect(
        url_for("dashboard")
    )


@app.route("/clear-alerts", methods=["POST"])
@login_required
def clear_alerts():

    conn = get_db()

    conn.execute(
        "DELETE FROM alerts"
    )

    conn.commit()
    conn.close()

    flash(
        "All alerts cleared.",
        "success"
    )

    return redirect(
        url_for("dashboard")
    )


@app.route("/export-alerts")
@login_required
def export_alerts():
    import csv
    from io import StringIO
    from flask import Response

    conn = get_db()

    rows = conn.execute("""
        SELECT
            id,
            timestamp,
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            protocol,
            attack_type,
            severity,
            description
        FROM alerts
        ORDER BY id DESC
    """).fetchall()

    conn.close()

    output = StringIO()

    writer = csv.writer(output)

    writer.writerow([
        "ID",
        "Timestamp",
        "Source IP",
        "Destination IP",
        "Source Port",
        "Destination Port",
        "Protocol",
        "Attack Type",
        "Severity",
        "Description"
    ])

    for row in rows:
        writer.writerow([
            row["id"],
            row["timestamp"],
            row["source_ip"],
            row["destination_ip"],
            row["source_port"],
            row["destination_port"],
            row["protocol"],
            row["attack_type"],
            row["severity"],
            row["description"]
        ])

    response = Response(
        output.getvalue(),
        mimetype="text/csv"
    )

    response.headers["Content-Disposition"] = (
        "attachment; filename=nids_alert_report.csv"
    )

    return response

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )



# -----------------------------
# Forgot Password / Reset
# -----------------------------
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        recovery_key = request.form.get("recovery_key", "").strip()
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not username or not recovery_key or not new_password or not confirm_password:
            flash("All fields are required.", "error")
            return render_template("forgot_password.html")

        if recovery_key != PASSWORD_RESET_KEY:
            flash("Invalid recovery code.", "error")
            return render_template("forgot_password.html")

        if new_password != confirm_password:
            flash("New passwords do not match.", "error")
            return render_template("forgot_password.html")

        if len(new_password) < 6:
            flash("Password must be at least 6 characters.", "error")
            return render_template("forgot_password.html")

        conn = get_db()

        user = conn.execute(
            "SELECT id FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        if user is None:
            conn.close()
            flash("Username not found.", "error")
            return render_template("forgot_password.html")

        hashed_password = generate_password_hash(new_password)

        conn.execute(
            "UPDATE users SET password = ? WHERE username = ?",
            (hashed_password, username)
        )

        conn.commit()
        conn.close()

        flash("Password reset successfully. Please login.", "success")

        return redirect(url_for("login"))

    return render_template("forgot_password.html")

if __name__ == "__main__":

    init_database()

    print("=" * 50)
    print("        BASIC NIDS WEB APPLICATION")
    print("=" * 50)
    print()
    print("Login URL:")
    print("http://127.0.0.1:5000")
    print()
    print("Default Username: admin")
    print("Default Password: admin123")
    print()
    print("=" * 50)

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )




