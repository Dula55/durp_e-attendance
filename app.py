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

# DATA_DIR: mount a persistent volume here on Render/Railway/Fly.io
DATA_DIR = os.getenv("DATA_DIR", os.path.join(BASE_DIR, "data"))
os.makedirs(DATA_DIR, exist_ok=True)

DATABASE_URL   = os.environ.get("DATABASE_URL")
USE_POSTGRESQL = bool(DATABASE_URL)
SQLITE_DB_PATH = os.path.join(DATA_DIR, "app.db")

# ── Stable secret key ────────────────────────────────────────────────────────
_SECRET_KEY_FILE = os.path.join(DATA_DIR, ".secret_key")

def _load_or_create_secret_key() -> str:
    env_key = os.environ.get("SECRET_KEY")
    if env_key:
        return env_key
    if os.path.isfile(_SECRET_KEY_FILE):
        with open(_SECRET_KEY_FILE, "r") as fh:
            key = fh.read().strip()
            if key:
                return key
    key = secrets.token_hex(32)
    try:
        with open(_SECRET_KEY_FILE, "w") as fh:
            fh.write(key)
        os.chmod(_SECRET_KEY_FILE, 0o600)
    except OSError:
        pass
    return key

SECRET_KEY              = _load_or_create_secret_key()
SESSION_COOKIE_SECURE   = os.environ.get("SESSION_COOKIE_SECURE",  "False").lower() == "true"
SESSION_COOKIE_SAMESITE = os.environ.get("SESSION_COOKIE_SAMESITE", "Lax")

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

app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=30)
app.config["SESSION_COOKIE_HTTPONLY"]    = True
app.config["SESSION_COOKIE_SECURE"]      = SESSION_COOKIE_SECURE
app.config["SESSION_COOKIE_SAMESITE"]    = SESSION_COOKIE_SAMESITE

# ==========================
# Logging
# ==========================
def setup_logging():
    root = logging.getLogger()
    root.setLevel(LOG_LEVEL)
    if root.handlers:
        return
    fmt_s = logging.Formatter("%(asctime)s %(levelname)s %(name)s - %(message)s")
    fmt_v = logging.Formatter("%(asctime)s %(levelname)s %(name)s [%(filename)s:%(lineno)d] - %(message)s")
    ch = logging.StreamHandler()
    ch.setLevel(LOG_LEVEL)
    ch.setFormatter(fmt_s)
    root.addHandler(ch)
    try:
        fh = RotatingFileHandler(LOG_FILE, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUP_COUNT)
        fh.setLevel(LOG_LEVEL)
        fh.setFormatter(fmt_v)
        root.addHandler(fh)
    except OSError:
        pass

setup_logging()
logger = logging.getLogger(__name__)
logger.info("Starting – backend: %s | path: %s",
            "PostgreSQL" if USE_POSTGRESQL else "SQLite",
            DATABASE_URL if USE_POSTGRESQL else SQLITE_DB_PATH)

# ==========================
# Utilities
# ==========================
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def verify_password(password: str, hashed: str) -> bool:
    return hash_password(password) == hashed

def now_iso() -> str:
    return datetime.utcnow().isoformat()

# ==========================
# Database connection
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
        raise RuntimeError("DATABASE_URL is not set.")
    try:
        import psycopg2, psycopg2.extras
        conn = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
        g._database = conn
        logger.info("Using psycopg2")
        return conn
    except Exception as e1:
        logger.warning("psycopg2 failed: %s", e1)
    try:
        import psycopg
        from psycopg.rows import dict_row
        conn = psycopg.connect(DATABASE_URL, row_factory=dict_row)
        g._database = conn
        logger.info("Using psycopg v3")
        return conn
    except Exception as e2:
        logger.warning("psycopg v3 failed: %s", e2)
    raise RuntimeError("No compatible PostgreSQL driver found.")

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
# Schema
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

CREATE TABLE IF NOT EXISTS courses (
    id           TEXT PRIMARY KEY,
    courseCode   TEXT NOT NULL,
    courseName   TEXT,
    lecturerId   TEXT NOT NULL,
    createdAt    TEXT,
    UNIQUE(courseCode, lecturerId),
    FOREIGN KEY(lecturerId) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS attendance (
    id           TEXT PRIMARY KEY,
    studentId    TEXT NOT NULL,
    studentName  TEXT,
    matricNumber TEXT,
    courseCode   TEXT NOT NULL,
    latitude     REAL,
    longitude    REAL,
    faceImage    TEXT,
    timestamp    TEXT,
    date         TEXT,
    time         TEXT,
    deviceType   TEXT,
    UNIQUE(studentId, courseCode, date),
    FOREIGN KEY(studentId) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS reset_tokens (
    token   TEXT PRIMARY KEY,
    user_id TEXT,
    expires TEXT
)
"""

_PG_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id             TEXT PRIMARY KEY,
    username       TEXT UNIQUE NOT NULL,
    password       TEXT NOT NULL,
    role           TEXT NOT NULL,
    "fullName"     TEXT,
    "matricNumber" TEXT UNIQUE,
    "isApproved"   INTEGER DEFAULT 0,
    "createdAt"    TEXT
);

CREATE TABLE IF NOT EXISTS courses (
    id           TEXT PRIMARY KEY,
    "courseCode" TEXT NOT NULL,
    "courseName" TEXT,
    "lecturerId" TEXT NOT NULL,
    "createdAt"  TEXT,
    UNIQUE("courseCode", "lecturerId")
);

CREATE TABLE IF NOT EXISTS attendance (
    id             TEXT PRIMARY KEY,
    "studentId"    TEXT NOT NULL,
    "studentName"  TEXT,
    "matricNumber" TEXT,
    "courseCode"   TEXT NOT NULL,
    latitude       REAL,
    longitude      REAL,
    "faceImage"    TEXT,
    timestamp      TEXT,
    date           TEXT,
    time           TEXT,
    "deviceType"   TEXT,
    UNIQUE("studentId", "courseCode", date)
);

CREATE TABLE IF NOT EXISTS reset_tokens (
    token   TEXT PRIMARY KEY,
    user_id TEXT,
    expires TEXT
)
"""

def init_db():
    db  = get_db()
    cur = db.cursor()
    schema = _PG_SCHEMA if USE_POSTGRESQL else _SQLITE_SCHEMA
    for stmt in schema.strip().split(";"):
        s = stmt.strip()
        if s:
            cur.execute(s)
    db.commit()
    logger.info("Schema initialised (%s)", "PostgreSQL" if USE_POSTGRESQL else "SQLite")

def _ensure_admin():
    db  = get_db()
    cur = db.cursor()
    if USE_POSTGRESQL:
        cur.execute("SELECT id FROM users WHERE username = %s LIMIT 1", ("admin",))
    else:
        cur.execute("SELECT id FROM users WHERE username = ? LIMIT 1", ("admin",))
    if cur.fetchone():
        return
    admin = {
        "id": str(uuid4()), "username": "admin",
        "password": hash_password("admin123"), "role": "admin",
        "fullName": "System Administrator", "matricNumber": None,
        "isApproved": True, "createdAt": now_iso(),
    }
    _insert_user(cur, admin)
    db.commit()
    logger.info("Default admin created (admin / admin123)")

def _insert_user(cur, user: dict):
    if USE_POSTGRESQL:
        cur.execute(
            """INSERT INTO users (id, username, password, role, "fullName", "matricNumber", "isApproved", "createdAt")
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
            (user["id"], user["username"], user["password"], user["role"],
             user.get("fullName"), user.get("matricNumber"),
             1 if user.get("isApproved") else 0, user.get("createdAt", now_iso())),
        )
    else:
        cur.execute(
            """INSERT INTO users (id, username, password, role, fullName, matricNumber, isApproved, createdAt)
               VALUES (?,?,?,?,?,?,?,?)""",
            (user["id"], user["username"], user["password"], user["role"],
             user.get("fullName"), user.get("matricNumber"),
             1 if user.get("isApproved") else 0, user.get("createdAt", now_iso())),
        )

with app.app_context():
    try:
        init_db()
        _ensure_admin()
    except Exception as exc:
        logger.exception("Fatal DB init: %s", exc)
        raise

# ==========================
# DB helpers – Users
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
            'SELECT * FROM users WHERE username=%s OR "matricNumber"=%s LIMIT 1',
            (identifier, identifier),
        )
    else:
        cur.execute(
            "SELECT * FROM users WHERE username=? OR matricNumber=? LIMIT 1",
            (identifier, identifier),
        )
    row = cur.fetchone()
    return dict(row) if row else None

def get_user_by_id(user_id: str):
    db  = get_db()
    cur = db.cursor()
    if USE_POSTGRESQL:
        cur.execute("SELECT * FROM users WHERE id=%s LIMIT 1", (user_id,))
    else:
        cur.execute("SELECT * FROM users WHERE id=? LIMIT 1", (user_id,))
    row = cur.fetchone()
    return dict(row) if row else None

def list_users_safely():
    db  = get_db()
    cur = db.cursor()
    if USE_POSTGRESQL:
        cur.execute('SELECT id,username,role,"fullName","matricNumber","isApproved","createdAt" FROM users')
    else:
        cur.execute("SELECT id,username,role,fullName,matricNumber,isApproved,createdAt FROM users")
    return [dict(r) for r in cur.fetchall()]

def count_admin_users() -> int:
    db  = get_db()
    cur = db.cursor()
    cur.execute("SELECT COUNT(*) as count FROM users WHERE role='admin'")
    result = cur.fetchone()
    return (result["count"] if isinstance(result, dict) else result[0]) if result else 0

def approve_lecturer_by_id(user_id: str) -> bool:
    db  = get_db()
    cur = db.cursor()
    if USE_POSTGRESQL:
        cur.execute("UPDATE users SET \"isApproved\"=1 WHERE id=%s AND role='lecturer'", (user_id,))
    else:
        cur.execute("UPDATE users SET isApproved=1 WHERE id=? AND role='lecturer'", (user_id,))
    db.commit()
    return cur.rowcount > 0

def delete_user_by_id(user_id: str) -> bool:
    db  = get_db()
    cur = db.cursor()
    if USE_POSTGRESQL:
        cur.execute("DELETE FROM users WHERE id=%s", (user_id,))
    else:
        cur.execute("DELETE FROM users WHERE id=?", (user_id,))
    db.commit()
    return cur.rowcount > 0

# ==========================
# DB helpers – Courses
# ==========================
def create_course(course: dict):
    """Register a course under a lecturer."""
    db  = get_db()
    cur = db.cursor()
    if USE_POSTGRESQL:
        cur.execute(
            'INSERT INTO courses (id,"courseCode","courseName","lecturerId","createdAt") VALUES (%s,%s,%s,%s,%s)',
            (course["id"], course["courseCode"], course.get("courseName"),
             course["lecturerId"], course.get("createdAt", now_iso())),
        )
    else:
        cur.execute(
            "INSERT INTO courses (id,courseCode,courseName,lecturerId,createdAt) VALUES (?,?,?,?,?)",
            (course["id"], course["courseCode"], course.get("courseName"),
             course["lecturerId"], course.get("createdAt", now_iso())),
        )
    db.commit()

def get_courses_by_lecturer(lecturer_id: str) -> list:
    """Return all courses owned by a lecturer."""
    db  = get_db()
    cur = db.cursor()
    if USE_POSTGRESQL:
        cur.execute(
            'SELECT * FROM courses WHERE "lecturerId"=%s ORDER BY "createdAt" DESC',
            (lecturer_id,),
        )
    else:
        cur.execute(
            "SELECT * FROM courses WHERE lecturerId=? ORDER BY createdAt DESC",
            (lecturer_id,),
        )
    return [dict(r) for r in cur.fetchall()]

def get_all_courses() -> list:
    """Return every registered course (admin view)."""
    db  = get_db()
    cur = db.cursor()
    if USE_POSTGRESQL:
        cur.execute('SELECT * FROM courses ORDER BY "createdAt" DESC')
    else:
        cur.execute("SELECT * FROM courses ORDER BY createdAt DESC")
    return [dict(r) for r in cur.fetchall()]

def get_distinct_course_codes() -> list:
    """
    Return every unique course code from the courses table.
    Students use this to pick a course when marking attendance.
    """
    db  = get_db()
    cur = db.cursor()
    if USE_POSTGRESQL:
        cur.execute('SELECT DISTINCT "courseCode", "courseName" FROM courses ORDER BY "courseCode"')
    else:
        cur.execute("SELECT DISTINCT courseCode, courseName FROM courses ORDER BY courseCode")
    rows = cur.fetchall()
    return [dict(r) for r in rows]

def delete_course(course_id: str, lecturer_id: str) -> bool:
    """Delete a course; lecturers may only delete their own."""
    db  = get_db()
    cur = db.cursor()
    if USE_POSTGRESQL:
        cur.execute('DELETE FROM courses WHERE id=%s AND "lecturerId"=%s', (course_id, lecturer_id))
    else:
        cur.execute("DELETE FROM courses WHERE id=? AND lecturerId=?", (course_id, lecturer_id))
    db.commit()
    return cur.rowcount > 0

# ==========================
# DB helpers – Attendance
# ==========================
def check_existing_attendance(student_id: str, course_code: str, date: str) -> bool:
    db  = get_db()
    cur = db.cursor()
    if USE_POSTGRESQL:
        cur.execute(
            'SELECT id FROM attendance WHERE "studentId"=%s AND "courseCode"=%s AND date=%s LIMIT 1',
            (student_id, course_code, date),
        )
    else:
        cur.execute(
            "SELECT id FROM attendance WHERE studentId=? AND courseCode=? AND date=? LIMIT 1",
            (student_id, course_code, date),
        )
    return cur.fetchone() is not None

def add_attendance_record(record: dict):
    db  = get_db()
    cur = db.cursor()
    if USE_POSTGRESQL:
        cur.execute(
            """INSERT INTO attendance
               (id,"studentId","studentName","matricNumber","courseCode",
                latitude,longitude,"faceImage",timestamp,date,time,"deviceType")
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (record["id"], record["studentId"], record.get("studentName"),
             record.get("matricNumber"), record["courseCode"],
             record.get("latitude"), record.get("longitude"), record.get("faceImage"),
             record["timestamp"], record["date"], record["time"],
             record.get("deviceType")),
        )
    else:
        cur.execute(
            """INSERT INTO attendance
               (id,studentId,studentName,matricNumber,courseCode,
                latitude,longitude,faceImage,timestamp,date,time,deviceType)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (record["id"], record["studentId"], record.get("studentName"),
             record.get("matricNumber"), record["courseCode"],
             record.get("latitude"), record.get("longitude"), record.get("faceImage"),
             record["timestamp"], record["date"], record["time"],
             record.get("deviceType")),
        )
    db.commit()

def get_attendance_all() -> list:
    """All attendance records – for admin."""
    db  = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM attendance ORDER BY timestamp DESC")
    return [dict(r) for r in cur.fetchall()]

def get_attendance_by_course_codes(course_codes: list) -> list:
    """
    PRIMARY query used by the lecturer dashboard.
    Returns every attendance record whose courseCode is in the supplied list.
    """
    if not course_codes:
        return []
    db  = get_db()
    cur = db.cursor()
    if USE_POSTGRESQL:
        placeholders = ",".join(["%s"] * len(course_codes))
        cur.execute(
            f'SELECT * FROM attendance WHERE "courseCode" IN ({placeholders}) ORDER BY timestamp DESC',
            tuple(course_codes),
        )
    else:
        placeholders = ",".join(["?"] * len(course_codes))
        cur.execute(
            f"SELECT * FROM attendance WHERE courseCode IN ({placeholders}) ORDER BY timestamp DESC",
            tuple(course_codes),
        )
    return [dict(r) for r in cur.fetchall()]

def get_attendance_by_course_code(course_code: str) -> list:
    """All attendance records for a single course code."""
    db  = get_db()
    cur = db.cursor()
    if USE_POSTGRESQL:
        cur.execute(
            'SELECT * FROM attendance WHERE "courseCode"=%s ORDER BY timestamp DESC',
            (course_code,),
        )
    else:
        cur.execute(
            "SELECT * FROM attendance WHERE courseCode=? ORDER BY timestamp DESC",
            (course_code,),
        )
    return [dict(r) for r in cur.fetchall()]

def get_attendance_by_student(student_id: str) -> list:
    db  = get_db()
    cur = db.cursor()
    if USE_POSTGRESQL:
        cur.execute(
            'SELECT * FROM attendance WHERE "studentId"=%s ORDER BY timestamp DESC',
            (student_id,),
        )
    else:
        cur.execute(
            "SELECT * FROM attendance WHERE studentId=? ORDER BY timestamp DESC",
            (student_id,),
        )
    return [dict(r) for r in cur.fetchall()]

def _normalise_record(r: dict) -> dict:
    """
    Normalise a raw DB row to consistent camelCase keys regardless of
    whether the backend is SQLite (lowercase keys) or PostgreSQL (quoted keys).
    """
    return {
        "id":           r.get("id"),
        "studentId":    r.get("studentId")    or r.get("studentid"),
        "studentName":  r.get("studentName")  or r.get("studentname"),
        "matricNumber": r.get("matricNumber") or r.get("matricnumber"),
        "courseCode":   r.get("courseCode")   or r.get("coursecode"),
        "latitude":     r.get("latitude"),
        "longitude":    r.get("longitude"),
        "faceImage":    r.get("faceImage")    or r.get("faceimage"),
        "timestamp":    r.get("timestamp"),
        "date":         r.get("date"),
        "time":         r.get("time"),
        "deviceType":   r.get("deviceType")   or r.get("devicetype"),
    }

def get_attendance_summary_by_course(course_code: str) -> dict:
    """Aggregated stats for a single course (for dashboard charts)."""
    records = get_attendance_by_course_code(course_code)
    if not records:
        return {"courseCode": course_code, "total": 0, "uniqueStudents": 0,
                "dates": [], "perDate": {}}
    students = {r.get("studentId") or r.get("studentid") for r in records}
    per_date: dict = {}
    for r in records:
        d = r.get("date") or (r.get("timestamp") or "")[:10]
        per_date[d] = per_date.get(d, 0) + 1
    return {
        "courseCode":     course_code,
        "total":          len(records),
        "uniqueStudents": len(students),
        "dates":          sorted(per_date.keys()),
        "perDate":        per_date,
    }

def delete_attendance_by_id(record_id: str) -> bool:
    db  = get_db()
    cur = db.cursor()
    if USE_POSTGRESQL:
        cur.execute("DELETE FROM attendance WHERE id=%s", (record_id,))
    else:
        cur.execute("DELETE FROM attendance WHERE id=?", (record_id,))
    db.commit()
    return cur.rowcount > 0

def delete_attendance_by_course(course_code: str, lecturer_id: str) -> int:
    """
    Delete ALL attendance records for a course after verifying ownership.
    Returns number of rows deleted, or -1 if ownership check fails.
    """
    db  = get_db()
    cur = db.cursor()
    if USE_POSTGRESQL:
        cur.execute(
            'SELECT id FROM courses WHERE "courseCode"=%s AND "lecturerId"=%s LIMIT 1',
            (course_code, lecturer_id),
        )
    else:
        cur.execute(
            "SELECT id FROM courses WHERE courseCode=? AND lecturerId=? LIMIT 1",
            (course_code, lecturer_id),
        )
    if not cur.fetchone():
        return -1
    if USE_POSTGRESQL:
        cur.execute('DELETE FROM attendance WHERE "courseCode"=%s', (course_code,))
    else:
        cur.execute("DELETE FROM attendance WHERE courseCode=?", (course_code,))
    db.commit()
    return cur.rowcount

# ==========================
# Reset tokens
# ==========================
def add_reset_token(token: str, user_id: str, expires_iso: str):
    db  = get_db()
    cur = db.cursor()
    if USE_POSTGRESQL:
        cur.execute("INSERT INTO reset_tokens(token,user_id,expires) VALUES(%s,%s,%s)",
                    (token, user_id, expires_iso))
    else:
        cur.execute("INSERT INTO reset_tokens(token,user_id,expires) VALUES(?,?,?)",
                    (token, user_id, expires_iso))
    db.commit()

def get_reset_token(token: str):
    db  = get_db()
    cur = db.cursor()
    if USE_POSTGRESQL:
        cur.execute("SELECT * FROM reset_tokens WHERE token=%s LIMIT 1", (token,))
    else:
        cur.execute("SELECT * FROM reset_tokens WHERE token=? LIMIT 1", (token,))
    row = cur.fetchone()
    return dict(row) if row else None

def delete_reset_token(token: str):
    db  = get_db()
    cur = db.cursor()
    if USE_POSTGRESQL:
        cur.execute("DELETE FROM reset_tokens WHERE token=%s", (token,))
    else:
        cur.execute("DELETE FROM reset_tokens WHERE token=?", (token,))
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
# API – Auth
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
            logger.warning("Failed login: %s", username)
            return jsonify({"success": False, "message": "Invalid username or password"}), 401

        if user["role"] == "lecturer" and not user.get("isApproved"):
            return jsonify({"success": False,
                            "message": "Your account is pending approval by an admin"}), 403

        session.permanent = remember
        session.update({
            "user_id":       user["id"],
            "username":      user["username"],
            "role":          user["role"],
            "full_name":     user.get("fullName"),
            "matric_number": user.get("matricNumber"),
        })
        logger.info("Login: %s role=%s remember=%s", user["username"], user["role"], remember)
        return jsonify({"success": True, "role": user["role"], "message": "Login successful"})

    except Exception as exc:
        logger.exception("api_login: %s", exc)
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
            return jsonify({"success": False,
                            "message": "Username, password and role are required"}), 400
        if role not in ("admin", "lecturer", "student"):
            return jsonify({"success": False, "message": "Invalid role"}), 400
        if role == "admin" and count_admin_users() >= 1:
            return jsonify({"success": False,
                            "message": "An admin account already exists."}), 403
        if get_user_by_username_or_matric(username):
            return jsonify({"success": False, "message": "Username already exists"}), 409
        if role == "student" and matricNumber and get_user_by_username_or_matric(matricNumber):
            return jsonify({"success": False,
                            "message": "Matric number already registered"}), 409

        new_user = {
            "id": str(uuid4()), "username": username,
            "password": hash_password(password), "role": role,
            "fullName": fullName or None,
            "matricNumber": matricNumber if role == "student" else None,
            "isApproved": role != "lecturer",
            "createdAt": now_iso(),
        }
        create_user(new_user)

        if role != "lecturer":
            session.permanent = remember
            session.update({
                "user_id":       new_user["id"],
                "username":      new_user["username"],
                "role":          new_user["role"],
                "full_name":     new_user["fullName"],
                "matric_number": new_user["matricNumber"],
            })

        msg = "Account created successfully"
        if role == "lecturer":
            msg += " – pending admin approval"
        logger.info("Signup: %s role=%s", username, role)
        return jsonify({"success": True, "role": role, "message": msg})

    except Exception as exc:
        logger.exception("api_signup: %s", exc)
        return jsonify({"success": False, "message": "Server error"}), 500

@app.route("/api/logout", methods=["POST"])
def api_logout():
    username = session.get("username", "unknown")
    session.clear()
    logger.info("Logout: %s", username)
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
        logger.info("Reset token issued for: %s", username)
        return jsonify({"success": True,
                        "message": "Password reset instructions sent",
                        "demo_token": token})  # remove in production
    except Exception as exc:
        logger.exception("api_forgot_password: %s", exc)
        return jsonify({"success": False, "message": "Server error"}), 500

@app.route("/api/reset-password", methods=["POST"])
def api_reset_password():
    try:
        data         = request.json or {}
        token        = data.get("token", "")
        new_password = data.get("password", "")
        if not token or not new_password:
            return jsonify({"success": False,
                            "message": "Token and new password are required"}), 400
        token_data = get_reset_token(token)
        if not token_data or datetime.fromisoformat(token_data["expires"]) <= datetime.utcnow():
            return jsonify({"success": False,
                            "message": "Invalid or expired reset token"}), 400
        user = get_user_by_id(token_data["user_id"])
        if not user:
            return jsonify({"success": False, "message": "User not found"}), 404
        db  = get_db()
        cur = db.cursor()
        if USE_POSTGRESQL:
            cur.execute("UPDATE users SET password=%s WHERE id=%s",
                        (hash_password(new_password), user["id"]))
        else:
            cur.execute("UPDATE users SET password=? WHERE id=?",
                        (hash_password(new_password), user["id"]))
        db.commit()
        delete_reset_token(token)
        logger.info("Password reset for user id: %s", user["id"])
        return jsonify({"success": True, "message": "Password reset successfully"})
    except Exception as exc:
        logger.exception("api_reset_password: %s", exc)
        return jsonify({"success": False, "message": "Server error"}), 500

# ==========================
# API – Courses
# ==========================
@app.route("/api/courses", methods=["GET"])
@login_required
def api_get_courses():
    """
    Lecturer  → their own courses only
    Admin     → all courses
    Student   → all distinct course codes (to pick when marking attendance)
    """
    try:
        role = session.get("role")
        if role == "lecturer":
            courses = get_courses_by_lecturer(session["user_id"])
        elif role == "admin":
            courses = get_all_courses()
        else:
            # Students need courseCode + courseName to display a picker
            courses = get_distinct_course_codes()
        return jsonify({"success": True, "courses": courses})
    except Exception as exc:
        logger.exception("api_get_courses: %s", exc)
        return jsonify({"success": False, "message": "Server error"}), 500

@app.route("/api/courses", methods=["POST"])
@login_required
@role_required("lecturer")
def api_create_course():
    """Lecturer registers a new course so students can mark attendance for it."""
    try:
        data       = request.json or {}
        courseCode = (data.get("courseCode") or "").strip().upper()
        courseName = (data.get("courseName") or "").strip()
        if not courseCode:
            return jsonify({"success": False, "message": "courseCode is required"}), 400

        course = {
            "id":         str(uuid4()),
            "courseCode": courseCode,
            "courseName": courseName or None,
            "lecturerId": session["user_id"],
            "createdAt":  now_iso(),
        }
        try:
            create_course(course)
        except Exception as db_exc:
            if "UNIQUE" in str(db_exc).upper() or "unique" in str(db_exc).lower():
                return jsonify({"success": False,
                                "message": f"You already registered course {courseCode}"}), 409
            raise
        logger.info("Course created: %s by %s", courseCode, session.get("username"))
        return jsonify({"success": True,
                        "message": f"Course {courseCode} registered",
                        "course": course}), 201

    except Exception as exc:
        logger.exception("api_create_course: %s", exc)
        return jsonify({"success": False, "message": "Server error"}), 500

@app.route("/api/courses/<course_id>", methods=["DELETE"])
@login_required
@role_required("lecturer", "admin")
def api_delete_course(course_id):
    """Lecturer deletes one of their own courses."""
    try:
        deleted = delete_course(course_id, session["user_id"])
        if deleted:
            logger.info("Course %s deleted by %s", course_id, session.get("username"))
            return jsonify({"success": True, "message": "Course deleted"})
        return jsonify({"success": False, "message": "Course not found or not yours"}), 404
    except Exception as exc:
        logger.exception("api_delete_course: %s", exc)
        return jsonify({"success": False, "message": "Server error"}), 500

# ==========================
# API – Attendance
# ==========================
@app.route("/api/submit-attendance", methods=["POST"])
@login_required
@role_required("student")
def api_submit_attendance():
    """
    Student marks attendance for a course.
    The courseCode must exist in the courses table (lecturer must register it first).
    """
    try:
        data        = request.json or {}
        course_code = (data.get("courseCode") or "").strip().upper()

        if not course_code:
            return jsonify({"success": False, "message": "courseCode is required"}), 400

        # Verify the course exists in the courses table
        db  = get_db()
        cur = db.cursor()
        if USE_POSTGRESQL:
            cur.execute('SELECT id FROM courses WHERE "courseCode"=%s LIMIT 1', (course_code,))
        else:
            cur.execute("SELECT id FROM courses WHERE courseCode=? LIMIT 1", (course_code,))
        if not cur.fetchone():
            return jsonify({"success": False,
                            "message": f"Course '{course_code}' does not exist. "
                                       "Ask your lecturer to register it first."}), 404

        today = datetime.utcnow().strftime("%Y-%m-%d")
        if check_existing_attendance(session["user_id"], course_code, today):
            return jsonify({"success": False,
                            "message": "You have already submitted attendance for this course today."}), 400

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
            logger.warning("Duplicate attendance blocked by DB: %s", db_exc)
            return jsonify({"success": False,
                            "message": "You have already submitted attendance for this course today."}), 400

        logger.info("Attendance: student=%s course=%s date=%s",
                    session.get("username"), course_code, today)
        return jsonify({"success": True, "message": "Attendance submitted successfully"})

    except Exception as exc:
        logger.exception("api_submit_attendance: %s", exc)
        return jsonify({"success": False, "message": "Server error"}), 500

@app.route("/api/check-attendance-status", methods=["GET"])
@login_required
@role_required("student")
def api_check_attendance_status():
    try:
        course_code = (request.args.get("courseCode") or "").strip().upper()
        if not course_code:
            return jsonify({"success": False,
                            "message": "courseCode query param is required"}), 400
        today     = datetime.utcnow().strftime("%Y-%m-%d")
        submitted = check_existing_attendance(session["user_id"], course_code, today)
        return jsonify({"success": True, "hasSubmitted": submitted})
    except Exception as exc:
        logger.exception("api_check_attendance_status: %s", exc)
        return jsonify({"success": False, "message": "Server error"}), 500

@app.route("/api/get-attendance", methods=["GET"])
@login_required
def api_get_attendance():
    """
    GET /api/get-attendance
    Optional query params:
      ?courseCode=CS101   – filter by a single course code
      ?date=2024-06-01    – filter by date

    Role behaviour
    ──────────────
    student  → own records only
    lecturer → records for courses they own (scoped by courseCode if provided)
    admin    → all records
    """
    try:
        role        = session.get("role")
        filter_code = (request.args.get("courseCode") or "").strip().upper() or None
        filter_date = (request.args.get("date") or "").strip() or None

        # ── Fetch base record set ─────────────────────────────────────────
        if role == "student":
            records = get_attendance_by_student(session["user_id"])

        elif role == "lecturer":
            my_courses = get_courses_by_lecturer(session["user_id"])
            my_codes   = [
                c.get("courseCode") or c.get("coursecode") for c in my_courses
            ]
            if filter_code:
                if filter_code not in my_codes:
                    return jsonify({"success": False,
                                    "message": "You do not own that course"}), 403
                records = get_attendance_by_course_code(filter_code)
            else:
                # Return attendance for ALL courses this lecturer owns
                records = get_attendance_by_course_codes(my_codes)

        else:  # admin
            if filter_code:
                records = get_attendance_by_course_code(filter_code)
            else:
                records = get_attendance_all()

        # ── Optional date filter ──────────────────────────────────────────
        if filter_date:
            records = [r for r in records if (r.get("date") or "") == filter_date]

        # ── Normalise to consistent camelCase keys ────────────────────────
        normalised = [_normalise_record(r) for r in records]

        return jsonify({"success": True, "attendance": normalised, "total": len(normalised)})

    except Exception as exc:
        logger.exception("api_get_attendance: %s", exc)
        return jsonify({"success": False, "message": "Server error"}), 500

@app.route("/api/attendance-summary", methods=["GET"])
@login_required
@role_required("lecturer", "admin")
def api_attendance_summary():
    """
    GET /api/attendance-summary?courseCode=CS101
    Returns per-course summary stats for dashboard charts.
    Omit courseCode to get summaries for all owned courses.
    """
    try:
        filter_code = (request.args.get("courseCode") or "").strip().upper() or None
        role        = session.get("role")

        if role == "lecturer":
            my_courses = get_courses_by_lecturer(session["user_id"])
            my_codes   = [c.get("courseCode") or c.get("coursecode") for c in my_courses]
            if filter_code:
                if filter_code not in my_codes:
                    return jsonify({"success": False,
                                    "message": "You do not own that course"}), 403
                codes = [filter_code]
            else:
                codes = my_codes
        else:  # admin
            codes = [filter_code] if filter_code else \
                    [c.get("courseCode") or c.get("coursecode") for c in get_all_courses()]

        summaries = [get_attendance_summary_by_course(c) for c in codes]
        return jsonify({"success": True, "summaries": summaries})

    except Exception as exc:
        logger.exception("api_attendance_summary: %s", exc)
        return jsonify({"success": False, "message": "Server error"}), 500

@app.route("/api/delete-attendance/<record_id>", methods=["DELETE"])
@login_required
@role_required("lecturer", "admin")
def api_delete_attendance(record_id):
    """
    Delete a single attendance record.
    Lecturers may only delete records that belong to their own courses.
    Admins may delete any record.
    Attendance records are permanent and only removed by explicit deletion.
    """
    try:
        if session.get("role") == "lecturer":
            db  = get_db()
            cur = db.cursor()
            if USE_POSTGRESQL:
                cur.execute('SELECT "courseCode" FROM attendance WHERE id=%s LIMIT 1',
                            (record_id,))
            else:
                cur.execute("SELECT courseCode FROM attendance WHERE id=? LIMIT 1",
                            (record_id,))
            row = cur.fetchone()
            if not row:
                return jsonify({"success": False, "message": "Record not found"}), 404
            code       = row["courseCode"] if isinstance(row, dict) else row[0]
            my_courses = get_courses_by_lecturer(session["user_id"])
            my_codes   = [c.get("courseCode") or c.get("coursecode") for c in my_courses]
            if code not in my_codes:
                return jsonify({"success": False,
                                "message": "You cannot delete records for a course you don't own"}), 403

        deleted = delete_attendance_by_id(record_id)
        if deleted:
            logger.info("Attendance %s deleted by %s (%s)",
                        record_id, session.get("username"), session.get("role"))
            return jsonify({"success": True, "message": "Record deleted"})
        return jsonify({"success": False, "message": "Record not found"}), 404

    except Exception as exc:
        logger.exception("api_delete_attendance: %s", exc)
        return jsonify({"success": False, "message": "Server error"}), 500

@app.route("/api/delete-attendance-by-course/<course_code>", methods=["DELETE"])
@login_required
@role_required("lecturer", "admin")
def api_delete_attendance_by_course(course_code):
    """
    Bulk-delete ALL attendance records for a course.
    Lecturer must own the course; admin bypasses ownership check.
    """
    try:
        course_code = course_code.strip().upper()
        if session.get("role") == "admin":
            db  = get_db()
            cur = db.cursor()
            if USE_POSTGRESQL:
                cur.execute('DELETE FROM attendance WHERE "courseCode"=%s', (course_code,))
            else:
                cur.execute("DELETE FROM attendance WHERE courseCode=?", (course_code,))
            db.commit()
            count = cur.rowcount
        else:
            count = delete_attendance_by_course(course_code, session["user_id"])
            if count == -1:
                return jsonify({"success": False,
                                "message": "Course not found or you don't own it"}), 403

        logger.info("Bulk delete: %d records for %s by %s",
                    count, course_code, session.get("username"))
        return jsonify({"success": True,
                        "message": f"{count} attendance record(s) deleted for {course_code}"})
    except Exception as exc:
        logger.exception("api_delete_attendance_by_course: %s", exc)
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
        logger.exception("api_get_users: %s", exc)
        return jsonify({"success": False, "message": "Server error"}), 500

@app.route("/api/approve-lecturer/<user_id>", methods=["POST"])
@login_required
@role_required("admin")
def api_approve_lecturer(user_id):
    try:
        if approve_lecturer_by_id(user_id):
            logger.info("Lecturer approved: %s", user_id)
            return jsonify({"success": True, "message": "Lecturer approved"})
        return jsonify({"success": False,
                        "message": "User not found or not a lecturer"}), 404
    except Exception as exc:
        logger.exception("api_approve_lecturer: %s", exc)
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
        logger.exception("api_reject_lecturer: %s", exc)
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
            "matricNumber": user.get("matricNumber") or user.get("matricnumber", ""),
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
    return render_template("error.html", message="Internal server error"), 500

# ==========================
# Dev runner
# ==========================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    logger.info("Dev server on port %s", port)
    app.run(host="0.0.0.0", port=port, debug=app.debug)