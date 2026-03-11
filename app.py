import os
import sqlite3
import hashlib
import secrets
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta
from functools import wraps
from uuid import uuid4

from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    session,
    redirect,
    url_for,
    g,
)

# ==========================
# Config & Environment
# ==========================
APP_NAME = "attendance_app"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ── PERSISTENCE FIX ──────────────────────────────────────────────────────────
# DATA_DIR is where both the SQLite database file and logs live.
# On Render / Railway / Fly.io, mount a persistent volume at this path so data
# survives redeploys.  Locally it defaults to <project>/data/.
DATA_DIR = os.getenv("DATA_DIR", os.path.join(BASE_DIR, "data"))
os.makedirs(DATA_DIR, exist_ok=True)

# Database configuration
DATABASE_URL = os.environ.get("DATABASE_URL")  # PostgreSQL on Render (optional)
USE_POSTGRESQL = bool(DATABASE_URL)

# SQLite DB path (used when DATABASE_URL is not set)
SQLITE_DB_PATH = os.path.join(DATA_DIR, "app.db")

# ── SECRET KEY ────────────────────────────────────────────────────────────────
# CRITICAL: If SECRET_KEY is regenerated on every restart all existing browser
# sessions become invalid and users are logged out.
# Solution: persist the key to disk so restarts re-use the same value.
# On PaaS platforms you should set SECRET_KEY as an environment variable instead.
_SECRET_KEY_FILE = os.path.join(DATA_DIR, ".secret_key")

def _load_or_create_secret_key() -> str:
    """Return a stable secret key, generating and saving one if it doesn't exist."""
    env_key = os.environ.get("SECRET_KEY")
    if env_key:
        return env_key  # Always prefer an explicit env var

    if os.path.isfile(_SECRET_KEY_FILE):
        with open(_SECRET_KEY_FILE, "r") as fh:
            key = fh.read().strip()
            if key:
                return key

    # First run: generate and persist the key
    key = secrets.token_hex(32)
    try:
        with open(_SECRET_KEY_FILE, "w") as fh:
            fh.write(key)
        # Restrict permissions so only the process owner can read it
        os.chmod(_SECRET_KEY_FILE, 0o600)
    except OSError:
        pass  # Non-fatal; key will still work this session
    return key

SECRET_KEY = _load_or_create_secret_key()

SESSION_COOKIE_SECURE   = os.environ.get("SESSION_COOKIE_SECURE",  "False").lower() == "true"
SESSION_COOKIE_SAMESITE = os.environ.get("SESSION_COOKIE_SAMESITE", "Lax")

# Logging config
LOG_LEVEL        = os.environ.get("LOG_LEVEL", "INFO").upper()
LOG_FILE         = os.path.join(DATA_DIR, f"{APP_NAME}.log")
LOG_MAX_BYTES    = int(os.environ.get("LOG_MAX_BYTES",    str(5 * 1024 * 1024)))
LOG_BACKUP_COUNT = int(os.environ.get("LOG_BACKUP_COUNT", "5"))

# ==========================
# Flask app
# ==========================
app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = SECRET_KEY
app.debug = os.environ.get("FLASK_DEBUG", "False").lower() == "true"

# Sessions last 30 days when session.permanent = True (set on login/signup)
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=30)
app.config["SESSION_COOKIE_HTTPONLY"]    = True
app.config["SESSION_COOKIE_SECURE"]      = SESSION_COOKIE_SECURE
app.config["SESSION_COOKIE_SAMESITE"]    = SESSION_COOKIE_SAMESITE

# ==========================
# Logging Setup
# ==========================
def setup_logging():
    root = logging.getLogger()
    root.setLevel(LOG_LEVEL)
    if root.handlers:
        return

    fmt_simple  = logging.Formatter("%(asctime)s %(levelname)s %(name)s - %(message)s")
    fmt_verbose = logging.Formatter("%(asctime)s %(levelname)s %(name)s [%(filename)s:%(lineno)d] - %(message)s")

    ch = logging.StreamHandler()
    ch.setLevel(LOG_LEVEL)
    ch.setFormatter(fmt_simple)
    root.addHandler(ch)

    try:
        fh = RotatingFileHandler(LOG_FILE, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUP_COUNT)
        fh.setLevel(LOG_LEVEL)
        fh.setFormatter(fmt_verbose)
        root.addHandler(fh)
    except OSError:
        pass  # Non-fatal if log file can't be created


setup_logging()
logger = logging.getLogger(__name__)
logger.info(
    "Starting application – DB backend: %s | DB path: %s",
    "PostgreSQL" if USE_POSTGRESQL else "SQLite",
    DATABASE_URL if USE_POSTGRESQL else SQLITE_DB_PATH,
)

# ==========================
# Utility functions
# ==========================
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def verify_password(password: str, hashed: str) -> bool:
    return hash_password(password) == hashed

def now_iso() -> str:
    return datetime.utcnow().isoformat()

# ==========================
# Database helpers
# ==========================
def get_db():
    return get_postgres_db() if USE_POSTGRESQL else get_sqlite_db()

def get_sqlite_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = sqlite3.connect(
            SQLITE_DB_PATH,
            detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES,
            check_same_thread=False,
        )
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL;")
        db.execute("PRAGMA foreign_keys=ON;")
        g._database = db
    return db

def get_postgres_db():
    db = getattr(g, "_database", None)
    if db is not None:
        return db

    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not set but get_postgres_db was called.")

    # Try psycopg2 first, then psycopg v3
    try:
        import psycopg2
        import psycopg2.extras
        conn = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
        g._database = conn
        logger.info("Using psycopg2 for PostgreSQL")
        return conn
    except Exception as e_psycopg2:
        logger.warning("psycopg2 failed: %s", e_psycopg2)

    try:
        import psycopg
        from psycopg.rows import dict_row
        conn = psycopg.connect(DATABASE_URL, row_factory=dict_row)
        g._database = conn
        logger.info("Using psycopg (v3) for PostgreSQL")
        return conn
    except Exception as e_psycopg:
        logger.warning("psycopg (v3) failed: %s", e_psycopg)

    raise RuntimeError(
        "No compatible PostgreSQL driver found. "
        "Install psycopg2-binary or psycopg, or remove DATABASE_URL to use SQLite."
    )

@app.teardown_appcontext
def close_db(error=None):
    db = getattr(g, "_database", None)
    if db is not None:
        try:
            db.close()
        except Exception:
            pass
        g._database = None

# ==========================
# Schema initialisation
# ==========================
_SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id           TEXT PRIMARY KEY,
    username     TEXT UNIQUE NOT NULL,
    password     TEXT NOT NULL,
    role         TEXT NOT NULL,
    fullName     TEXT,
    matricNumber TEXT UNIQUE,
    isApproved   INTEGER DEFAULT 0,
    createdAt    TEXT
);

CREATE TABLE IF NOT EXISTS attendance (
    id           TEXT PRIMARY KEY,
    studentId    TEXT NOT NULL,
    studentName  TEXT,
    matricNumber TEXT,
    courseCode   TEXT,
    latitude     REAL,
    longitude    REAL,
    faceImage    TEXT,
    timestamp    TEXT,
    date         TEXT,
    time         TEXT,
    deviceType   TEXT,
    -- One record per student per course per day
    UNIQUE(studentId, courseCode, date)
);

CREATE TABLE IF NOT EXISTS reset_tokens (
    token   TEXT PRIMARY KEY,
    user_id TEXT,
    expires TEXT
);
"""

_PG_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id           TEXT PRIMARY KEY,
    username     TEXT UNIQUE NOT NULL,
    password     TEXT NOT NULL,
    role         TEXT NOT NULL,
    "fullName"   TEXT,
    "matricNumber" TEXT UNIQUE,
    "isApproved" INTEGER DEFAULT 0,
    "createdAt"  TEXT
);

CREATE TABLE IF NOT EXISTS attendance (
    id            TEXT PRIMARY KEY,
    "studentId"   TEXT NOT NULL,
    "studentName" TEXT,
    "matricNumber" TEXT,
    "courseCode"  TEXT,
    latitude      REAL,
    longitude     REAL,
    "faceImage"   TEXT,
    timestamp     TEXT,
    date          TEXT,
    time          TEXT,
    "deviceType"  TEXT,
    UNIQUE("studentId", "courseCode", date)
);

CREATE TABLE IF NOT EXISTS reset_tokens (
    token   TEXT PRIMARY KEY,
    user_id TEXT,
    expires TEXT
);
"""

def init_db():
    db = get_db()
    cur = db.cursor()
    schema = _PG_SCHEMA if USE_POSTGRESQL else _SQLITE_SCHEMA
    for statement in schema.strip().split(";"):
        stmt = statement.strip()
        if stmt:
            cur.execute(stmt)
    db.commit()
    logger.info("Database schema initialised (%s)", "PostgreSQL" if USE_POSTGRESQL else "SQLite")


def _ensure_admin():
    """Create the default admin account if it doesn't already exist."""
    db  = get_db()
    cur = db.cursor()

    if USE_POSTGRESQL:
        cur.execute("SELECT id FROM users WHERE username = %s LIMIT 1", ("admin",))
    else:
        cur.execute("SELECT id FROM users WHERE username = ? LIMIT 1", ("admin",))

    if cur.fetchone():
        return  # Admin already exists

    admin = {
        "id":           str(uuid4()),
        "username":     "admin",
        "password":     hash_password("admin123"),
        "role":         "admin",
        "fullName":     "System Administrator",
        "matricNumber": None,
        "isApproved":   True,
        "createdAt":    now_iso(),
    }
    _insert_user(cur, admin)
    db.commit()
    logger.info("Default admin user created (username: admin, password: admin123)")


def _insert_user(cur, user: dict):
    if USE_POSTGRESQL:
        cur.execute(
            """INSERT INTO users (id, username, password, role, "fullName", "matricNumber", "isApproved", "createdAt")
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
            (user["id"], user["username"], user["password"], user["role"],
             user.get("fullName"), user.get("matricNumber"),
             1 if user.get("isApproved") else 0, user.get("createdAt", now_iso())),
        )
    else:
        cur.execute(
            """INSERT INTO users (id, username, password, role, fullName, matricNumber, isApproved, createdAt)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (user["id"], user["username"], user["password"], user["role"],
             user.get("fullName"), user.get("matricNumber"),
             1 if user.get("isApproved") else 0, user.get("createdAt", now_iso())),
        )


with app.app_context():
    try:
        init_db()
        _ensure_admin()
    except Exception as exc:
        logger.exception("Fatal: could not initialise DB – %s", exc)
        raise

# ==========================
# DB CRUD helpers
# ==========================
def create_user(user: dict):
    db  = get_db()
    cur = db.cursor()
    _insert_user(cur, user)
    db.commit()


def get_user_by_username_or_matric(identifier: str):
    db  = get_db()
    cur = db.cursor()
    if USE_POSTGRESQL:
        cur.execute(
            'SELECT * FROM users WHERE username = %s OR "matricNumber" = %s LIMIT 1',
            (identifier, identifier),
        )
    else:
        cur.execute(
            "SELECT * FROM users WHERE username = ? OR matricNumber = ? LIMIT 1",
            (identifier, identifier),
        )
    row = cur.fetchone()
    return dict(row) if row else None


def get_user_by_id(user_id: str):
    db  = get_db()
    cur = db.cursor()
    if USE_POSTGRESQL:
        cur.execute("SELECT * FROM users WHERE id = %s LIMIT 1", (user_id,))
    else:
        cur.execute("SELECT * FROM users WHERE id = ? LIMIT 1", (user_id,))
    row = cur.fetchone()
    return dict(row) if row else None


def list_users_safely():
    db  = get_db()
    cur = db.cursor()
    if USE_POSTGRESQL:
        cur.execute(
            'SELECT id, username, role, "fullName", "matricNumber", "isApproved", "createdAt" FROM users'
        )
    else:
        cur.execute(
            "SELECT id, username, role, fullName, matricNumber, isApproved, createdAt FROM users"
        )
    return [dict(r) for r in cur.fetchall()]


def count_admin_users() -> int:
    db  = get_db()
    cur = db.cursor()
    cur.execute("SELECT COUNT(*) as count FROM users WHERE role = 'admin'")
    result = cur.fetchone()
    return (result["count"] if isinstance(result, dict) else result[0]) if result else 0


def approve_lecturer_by_id(user_id: str) -> bool:
    db  = get_db()
    cur = db.cursor()
    if USE_POSTGRESQL:
        cur.execute("UPDATE users SET \"isApproved\" = 1 WHERE id = %s AND role = 'lecturer'", (user_id,))
    else:
        cur.execute("UPDATE users SET isApproved = 1 WHERE id = ? AND role = 'lecturer'", (user_id,))
    db.commit()
    return cur.rowcount > 0


def delete_user_by_id(user_id: str) -> bool:
    db  = get_db()
    cur = db.cursor()
    if USE_POSTGRESQL:
        cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
    else:
        cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    return cur.rowcount > 0


# ── Attendance ────────────────────────────────────────────────────────────────

def check_existing_attendance(student_id: str, course_code: str, date: str) -> bool:
    db  = get_db()
    cur = db.cursor()
    if USE_POSTGRESQL:
        cur.execute(
            'SELECT id FROM attendance WHERE "studentId" = %s AND "courseCode" = %s AND date = %s LIMIT 1',
            (student_id, course_code, date),
        )
    else:
        cur.execute(
            "SELECT id FROM attendance WHERE studentId = ? AND courseCode = ? AND date = ? LIMIT 1",
            (student_id, course_code, date),
        )
    return cur.fetchone() is not None


def add_attendance_record(record: dict):
    db  = get_db()
    cur = db.cursor()
    if USE_POSTGRESQL:
        cur.execute(
            """INSERT INTO attendance
               (id, "studentId", "studentName", "matricNumber", "courseCode",
                latitude, longitude, "faceImage", timestamp, date, time, "deviceType")
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
            (record["id"], record["studentId"], record.get("studentName"),
             record.get("matricNumber"), record.get("courseCode"),
             record.get("latitude"), record.get("longitude"), record.get("faceImage"),
             record.get("timestamp"), record.get("date"), record.get("time"),
             record.get("deviceType")),
        )
    else:
        cur.execute(
            """INSERT INTO attendance
               (id, studentId, studentName, matricNumber, courseCode,
                latitude, longitude, faceImage, timestamp, date, time, deviceType)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (record["id"], record["studentId"], record.get("studentName"),
             record.get("matricNumber"), record.get("courseCode"),
             record.get("latitude"), record.get("longitude"), record.get("faceImage"),
             record.get("timestamp"), record.get("date"), record.get("time"),
             record.get("deviceType")),
        )
    db.commit()


def get_attendance_all():
    db  = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM attendance ORDER BY timestamp DESC")
    return [dict(r) for r in cur.fetchall()]


def get_attendance_by_student(student_id: str):
    db  = get_db()
    cur = db.cursor()
    if USE_POSTGRESQL:
        cur.execute(
            'SELECT * FROM attendance WHERE "studentId" = %s ORDER BY timestamp DESC',
            (student_id,),
        )
    else:
        cur.execute(
            "SELECT * FROM attendance WHERE studentId = ? ORDER BY timestamp DESC",
            (student_id,),
        )
    return [dict(r) for r in cur.fetchall()]


def delete_attendance_by_id(record_id: str) -> bool:
    """
    Permanently delete a single attendance record.
    This function should ONLY be called after verifying the caller is a
    lecturer or admin (see api_delete_attendance below).
    """
    db  = get_db()
    cur = db.cursor()
    if USE_POSTGRESQL:
        cur.execute("DELETE FROM attendance WHERE id = %s", (record_id,))
    else:
        cur.execute("DELETE FROM attendance WHERE id = ?", (record_id,))
    db.commit()
    return cur.rowcount > 0


# ── Reset tokens ──────────────────────────────────────────────────────────────

def add_reset_token(token: str, user_id: str, expires_iso: str):
    db  = get_db()
    cur = db.cursor()
    if USE_POSTGRESQL:
        cur.execute(
            "INSERT INTO reset_tokens (token, user_id, expires) VALUES (%s, %s, %s)",
            (token, user_id, expires_iso),
        )
    else:
        cur.execute(
            "INSERT INTO reset_tokens (token, user_id, expires) VALUES (?, ?, ?)",
            (token, user_id, expires_iso),
        )
    db.commit()


def get_reset_token(token: str):
    db  = get_db()
    cur = db.cursor()
    if USE_POSTGRESQL:
        cur.execute("SELECT * FROM reset_tokens WHERE token = %s LIMIT 1", (token,))
    else:
        cur.execute("SELECT * FROM reset_tokens WHERE token = ? LIMIT 1", (token,))
    row = cur.fetchone()
    return dict(row) if row else None


def delete_reset_token(token: str):
    db  = get_db()
    cur = db.cursor()
    if USE_POSTGRESQL:
        cur.execute("DELETE FROM reset_tokens WHERE token = %s", (token,))
    else:
        cur.execute("DELETE FROM reset_tokens WHERE token = ?", (token,))
    db.commit()


# ==========================
# Auth decorators
# ==========================
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if session.get("role") not in roles:
                return redirect(url_for("index"))
            return f(*args, **kwargs)
        return decorated
    return decorator


# ==========================
# Page routes
# ==========================
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/login")
def login():
    if "user_id" in session:
        return redirect(url_for(f"{session['role']}_dashboard"))
    return render_template("login.html")

@app.route("/signup")
def signup():
    if "user_id" in session:
        return redirect(url_for(f"{session['role']}_dashboard"))
    return render_template("signup.html")

@app.route("/forgot-password")
def forgot_password():
    return render_template("forgot_password.html")

@app.route("/admin-dashboard")
@login_required
@role_required("admin")
def admin_dashboard():
    return render_template("admin_dashboard.html")

@app.route("/lecturer-dashboard")
@login_required
@role_required("lecturer")
def lecturer_dashboard():
    return render_template("lecturer_dashboard.html")

@app.route("/student-dashboard")
@login_required
@role_required("student")
def student_dashboard():
    return render_template("student_dashboard.html")


# ==========================
# API – Authentication
# ==========================
@app.route("/api/login", methods=["POST"])
def api_login():
    try:
        data     = request.json or {}
        username = data.get("username", "").strip()
        password = data.get("password", "")
        remember = bool(data.get("remember", False))

        if not username or not password:
            return jsonify({"success": False, "message": "Username and password are required"}), 400

        user = get_user_by_username_or_matric(username)

        if not user or not verify_password(password, user["password"]):
            logger.warning("Failed login attempt for: %s", username)
            return jsonify({"success": False, "message": "Invalid username or password"}), 401

        if user["role"] == "lecturer" and not user.get("isApproved"):
            return jsonify({"success": False, "message": "Your account is pending approval by an admin"}), 403

        # Populate session
        session.permanent = remember  # True → cookie valid for PERMANENT_SESSION_LIFETIME (30 days)
        session.update({
            "user_id":      user["id"],
            "username":     user["username"],
            "role":         user["role"],
            "full_name":    user.get("fullName"),
            "matric_number": user.get("matricNumber"),
        })

        logger.info("Login: %s (role=%s, remember=%s)", user["username"], user["role"], remember)
        return jsonify({"success": True, "role": user["role"], "message": "Login successful"})

    except Exception as exc:
        logger.exception("api_login error: %s", exc)
        return jsonify({"success": False, "message": "Server error"}), 500


@app.route("/api/signup", methods=["POST"])
def api_signup():
    try:
        data         = request.json or {}
        username     = (data.get("username") or "").strip()
        password     = data.get("password", "")
        role         = data.get("role", "")
        fullName     = (data.get("fullName") or "").strip()
        matricNumber = (data.get("matricNumber") or "").strip() or None
        remember     = bool(data.get("remember", False))

        if not username or not password or not role:
            return jsonify({"success": False, "message": "Username, password and role are required"}), 400

        if role not in ("admin", "lecturer", "student"):
            return jsonify({"success": False, "message": "Invalid role"}), 400

        # Only one admin is allowed
        if role == "admin" and count_admin_users() >= 1:
            return jsonify({
                "success": False,
                "message": "An admin account already exists. Only one admin is permitted.",
            }), 403

        if get_user_by_username_or_matric(username):
            return jsonify({"success": False, "message": "Username already exists"}), 409

        if role == "student" and matricNumber and get_user_by_username_or_matric(matricNumber):
            return jsonify({"success": False, "message": "Matric number already registered"}), 409

        new_user = {
            "id":           str(uuid4()),
            "username":     username,
            "password":     hash_password(password),
            "role":         role,
            "fullName":     fullName or None,
            "matricNumber": matricNumber if role == "student" else None,
            # Lecturers need admin approval; everyone else is immediately active
            "isApproved":   role != "lecturer",
            "createdAt":    now_iso(),
        }

        create_user(new_user)

        # Auto-login for students and admins (not pending lecturers)
        if role != "lecturer":
            session.permanent = remember
            session.update({
                "user_id":      new_user["id"],
                "username":     new_user["username"],
                "role":         new_user["role"],
                "full_name":    new_user["fullName"],
                "matric_number": new_user["matricNumber"],
            })

        logger.info("New user: %s (role=%s)", username, role)
        msg = "Account created successfully"
        if role == "lecturer":
            msg += " – your account is pending admin approval"
        return jsonify({"success": True, "role": role, "message": msg})

    except Exception as exc:
        logger.exception("api_signup error: %s", exc)
        return jsonify({"success": False, "message": "Server error"}), 500


@app.route("/api/logout", methods=["POST"])
def api_logout():
    username = session.get("username", "unknown")
    session.clear()
    logger.info("User logged out: %s", username)
    return jsonify({"success": True})


@app.route("/api/forgot-password", methods=["POST"])
def api_forgot_password():
    try:
        data     = request.json or {}
        username = (data.get("username") or "").strip()
        user     = get_user_by_username_or_matric(username)

        if not user:
            return jsonify({"success": False, "message": "Username not found"}), 404

        token   = secrets.token_urlsafe(32)
        expires = (datetime.utcnow() + timedelta(hours=1)).isoformat()
        add_reset_token(token, user["id"], expires)

        logger.info("Password reset token issued for: %s", username)
        return jsonify({
            "success": True,
            "message": "Password reset instructions sent to your email",
            "demo_token": token,  # Remove this line in production
        })

    except Exception as exc:
        logger.exception("api_forgot_password error: %s", exc)
        return jsonify({"success": False, "message": "Server error"}), 500


@app.route("/api/reset-password", methods=["POST"])
def api_reset_password():
    try:
        data         = request.json or {}
        token        = data.get("token", "")
        new_password = data.get("password", "")

        if not token or not new_password:
            return jsonify({"success": False, "message": "Token and new password are required"}), 400

        token_data = get_reset_token(token)
        if not token_data or datetime.fromisoformat(token_data["expires"]) <= datetime.utcnow():
            return jsonify({"success": False, "message": "Invalid or expired reset token"}), 400

        user = get_user_by_id(token_data["user_id"])
        if not user:
            return jsonify({"success": False, "message": "User not found"}), 404

        db  = get_db()
        cur = db.cursor()
        if USE_POSTGRESQL:
            cur.execute("UPDATE users SET password = %s WHERE id = %s", (hash_password(new_password), user["id"]))
        else:
            cur.execute("UPDATE users SET password = ? WHERE id = ?", (hash_password(new_password), user["id"]))
        db.commit()

        delete_reset_token(token)
        logger.info("Password reset for user id: %s", user["id"])
        return jsonify({"success": True, "message": "Password reset successfully"})

    except Exception as exc:
        logger.exception("api_reset_password error: %s", exc)
        return jsonify({"success": False, "message": "Server error"}), 500


# ==========================
# API – Attendance
# ==========================
@app.route("/api/submit-attendance", methods=["POST"])
@login_required
@role_required("student")
def api_submit_attendance():
    try:
        data        = request.json or {}
        course_code = (data.get("courseCode") or "").strip()

        if not course_code:
            return jsonify({"success": False, "message": "Course code is required"}), 400

        today = datetime.utcnow().strftime("%Y-%m-%d")

        if check_existing_attendance(session["user_id"], course_code, today):
            return jsonify({
                "success": False,
                "message": "You have already submitted attendance for this course today.",
            }), 400

        record = {
            "id":           str(uuid4()),
            "studentId":    session["user_id"],
            "studentName":  session.get("full_name"),
            "matricNumber": data.get("matricNumber") or session.get("matric_number"),
            "courseCode":   course_code,
            "latitude":     data.get("latitude"),
            "longitude":    data.get("longitude"),
            "faceImage":    data.get("faceImage"),
            "timestamp":    now_iso(),
            "date":         today,
            "time":         datetime.utcnow().strftime("%H:%M"),
            "deviceType":   data.get("deviceType", "Desktop"),
        }

        try:
            add_attendance_record(record)
        except Exception as db_exc:
            # Unique constraint violation = duplicate attempt that slipped through the check
            logger.warning("Duplicate attendance blocked by DB constraint: %s", db_exc)
            return jsonify({
                "success": False,
                "message": "You have already submitted attendance for this course today.",
            }), 400

        logger.info("Attendance recorded: student=%s course=%s date=%s",
                    session.get("username"), course_code, today)
        return jsonify({"success": True, "message": "Attendance submitted successfully"})

    except Exception as exc:
        logger.exception("api_submit_attendance error: %s", exc)
        return jsonify({"success": False, "message": "Server error"}), 500


@app.route("/api/check-attendance-status", methods=["GET"])
@login_required
@role_required("student")
def api_check_attendance_status():
    try:
        course_code = (request.args.get("courseCode") or "").strip()
        if not course_code:
            return jsonify({"success": False, "message": "courseCode query param is required"}), 400

        today       = datetime.utcnow().strftime("%Y-%m-%d")
        submitted   = check_existing_attendance(session["user_id"], course_code, today)
        return jsonify({"success": True, "hasSubmitted": submitted})

    except Exception as exc:
        logger.exception("api_check_attendance_status error: %s", exc)
        return jsonify({"success": False, "message": "Server error"}), 500


@app.route("/api/get-attendance", methods=["GET"])
@login_required
def api_get_attendance():
    """
    Students see only their own records.
    Lecturers and admins see all records.
    Records are stored permanently; only lecturers/admins may delete them.
    """
    try:
        role = session.get("role")
        if role == "student":
            attendance = get_attendance_by_student(session["user_id"])
        elif role in ("lecturer", "admin"):
            attendance = get_attendance_all()
        else:
            attendance = []
        return jsonify({"success": True, "attendance": attendance})

    except Exception as exc:
        logger.exception("api_get_attendance error: %s", exc)
        return jsonify({"success": False, "message": "Server error"}), 500


@app.route("/api/delete-attendance/<record_id>", methods=["DELETE"])
@login_required
@role_required("lecturer", "admin")   # ← ONLY lecturers and admins may delete
def api_delete_attendance(record_id):
    """
    Permanently remove an attendance record.
    Students cannot delete any records.
    Lecturers and admins can delete any record.
    """
    try:
        deleted = delete_attendance_by_id(record_id)
        if deleted:
            logger.info("Attendance record %s deleted by %s (%s)",
                        record_id, session.get("username"), session.get("role"))
            return jsonify({"success": True, "message": "Record deleted successfully"})
        return jsonify({"success": False, "message": "Record not found"}), 404

    except Exception as exc:
        logger.exception("api_delete_attendance error: %s", exc)
        return jsonify({"success": False, "message": "Server error"}), 500


# ==========================
# API – User management
# ==========================
@app.route("/api/get-users", methods=["GET"])
@login_required
@role_required("admin")
def api_get_users():
    try:
        return jsonify({"success": True, "users": list_users_safely()})
    except Exception as exc:
        logger.exception("api_get_users error: %s", exc)
        return jsonify({"success": False, "message": "Server error"}), 500


@app.route("/api/approve-lecturer/<user_id>", methods=["POST"])
@login_required
@role_required("admin")
def api_approve_lecturer(user_id):
    try:
        if approve_lecturer_by_id(user_id):
            logger.info("Lecturer approved: %s", user_id)
            return jsonify({"success": True, "message": "Lecturer approved successfully"})
        return jsonify({"success": False, "message": "User not found or not a lecturer"}), 404
    except Exception as exc:
        logger.exception("api_approve_lecturer error: %s", exc)
        return jsonify({"success": False, "message": "Server error"}), 500


@app.route("/api/reject-lecturer/<user_id>", methods=["POST"])
@login_required
@role_required("admin")
def api_reject_lecturer(user_id):
    try:
        if delete_user_by_id(user_id):
            logger.info("Lecturer rejected: %s", user_id)
            return jsonify({"success": True, "message": "Lecturer rejected and removed"})
        return jsonify({"success": False, "message": "User not found"}), 404
    except Exception as exc:
        logger.exception("api_reject_lecturer error: %s", exc)
        return jsonify({"success": False, "message": "Server error"}), 500


@app.route("/api/current-user", methods=["GET"])
def api_current_user():
    if "user_id" not in session:
        return jsonify({"success": False})
    user = get_user_by_id(session["user_id"])
    if not user:
        session.clear()
        return jsonify({"success": False})
    return jsonify({
        "success": True,
        "user": {
            "id":           session["user_id"],
            "username":     session.get("username"),
            "role":         session.get("role"),
            "fullName":     session.get("full_name"),
            "matricNumber": user.get("matricNumber", ""),
        },
    })


# ==========================
# Misc
# ==========================
@app.route("/health")
def health_check():
    return jsonify({"status": "healthy"}), 200


@app.errorhandler(404)
def page_not_found(e):
    return render_template("error.html", message="Page not found"), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template("error.html", message="Internal server error. Please try again later."), 500


# ==========================
# Dev runner
# ==========================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    logger.info("Dev server starting on port %s", port)
    app.run(host="0.0.0.0", port=port, debug=app.debug)