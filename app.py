import os
import sqlite3
import hashlib
import secrets
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta
from functools import wraps
from uuid import uuid4

# NOTE: psycopg2 import removed from top-level to avoid ImportError on incompatible Python builds.
# We'll import a Postgres driver lazily inside get_postgres_db() only when DATABASE_URL is set.

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

# Persistent storage directory (mount a volume here in production if necessary)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATA_DIR = os.getenv(
    "DATA_DIR",
    os.path.join(BASE_DIR, "data")
)

os.makedirs(DATA_DIR, exist_ok=True)

# Database configuration
DATABASE_URL = os.environ.get("DATABASE_URL")  # For PostgreSQL on Render
USE_POSTGRESQL = DATABASE_URL is not None and DATABASE_URL != ""

# SQLite DB path (fallback)
SQLITE_DB_PATH = os.path.join(DATA_DIR, "app.db")

# Secret key and session settings
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))
SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "False").lower() == "true"
SESSION_COOKIE_SAMESITE = os.environ.get("SESSION_COOKIE_SAMESITE", "Lax")
SESSION_TYPE = os.environ.get("SESSION_TYPE", "filesystem")  # Use filesystem for persistent sessions
SESSION_PERMANENT = True  # Make sessions permanent by default
SESSION_USE_SIGNER = True  # Sign cookies to prevent tampering
SESSION_FILE_DIR = os.path.join(DATA_DIR, "flask_sessions")  # Directory for session files

# Create session directory
os.makedirs(SESSION_FILE_DIR, exist_ok=True)

# Logging config
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
LOG_FILE = os.path.join(DATA_DIR, f"{APP_NAME}.log")
LOG_MAX_BYTES = int(os.environ.get("LOG_MAX_BYTES", 5 * 1024 * 1024))  # 5 MB
LOG_BACKUP_COUNT = int(os.environ.get("LOG_BACKUP_COUNT", 5))

# ==========================
# Flask app
# ==========================
app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = SECRET_KEY
app.debug = os.environ.get("FLASK_DEBUG", "False").lower() == "true"

# Make sessions persistent
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=30)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = SESSION_COOKIE_SECURE
app.config["SESSION_COOKIE_SAMESITE"] = SESSION_COOKIE_SAMESITE
app.config["SESSION_REFRESH_EACH_REQUEST"] = True  # Refresh session on each request to keep it alive
app.config["SESSION_FILE_DIR"] = SESSION_FILE_DIR
app.config["SESSION_FILE_THRESHOLD"] = 500  # Max number of session files
app.config["SESSION_FILE_MODE"] = 0o600  # File permissions for session files

# ==========================
# Utility functions
# ==========================
def hash_password(password: str) -> str:
    """Return SHA256 hex digest of password (simple hashing)."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def verify_password(password: str, hashed: str) -> bool:
    """Verify a password against its SHA256 hash."""
    return hash_password(password) == hashed

def now_iso():
    """Return current UTC time in ISO format."""
    return datetime.utcnow().isoformat()

# ==========================
# Logging Setup
# ==========================
def setup_logging():
    root = logging.getLogger()
    root.setLevel(LOG_LEVEL)

    # Avoid adding handlers multiple times if reloaded
    if root.handlers:
        return

    # Console handler (useful for PaaS logs)
    ch = logging.StreamHandler()
    ch.setLevel(LOG_LEVEL)
    ch_formatter = logging.Formatter('%(asctime)s %(levelname)s %(name)s - %(message)s')
    ch.setFormatter(ch_formatter)
    root.addHandler(ch)

    # Rotating file handler (persistent logs)
    fh = RotatingFileHandler(LOG_FILE, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUP_COUNT)
    fh.setLevel(LOG_LEVEL)
    fh_formatter = logging.Formatter('%(asctime)s %(levelname)s %(name)s [%(filename)s:%(lineno)d] - %(message)s')
    fh.setFormatter(fh_formatter)
    root.addHandler(fh)

setup_logging()
logger = logging.getLogger(__name__)
logger.info("Starting application - using %s database", "PostgreSQL" if USE_POSTGRESQL else "SQLite")
logger.info("Logs to %s", LOG_FILE)

# ==========================
# Database helpers
# ==========================
def get_db():
    if USE_POSTGRESQL:
        return get_postgres_db()
    else:
        return get_sqlite_db()

def get_sqlite_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = sqlite3.connect(SQLITE_DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES, check_same_thread=False)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA journal_mode=WAL;")
            db.execute("PRAGMA foreign_keys=ON;")
        except Exception:
            pass
        g._database = db
    return db

def get_postgres_db():
    """
    Lazily import a Postgres client and return a connection.
    Tries psycopg2 first, then psycopg (psycopg v3). If neither is usable,
    raises a clear RuntimeError with guidance.
    """
    db = getattr(g, "_database", None)
    if db is not None:
        return db

    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not set but get_postgres_db was called.")

    # Try psycopg2 (common, but note: psycopg2-binary may be incompatible with CPython 3.14 builds)
    try:
        import psycopg2
        import psycopg2.extras

        conn = psycopg2.connect(DATABASE_URL)
        # ensure cursors default to returning mappings when possible
        try:
            conn.cursor_factory = psycopg2.extras.RealDictCursor
        except Exception:
            # some psycopg2 builds may not accept setting cursor_factory attribute,
            # but we'll still use RealDictCursor explicitly when creating cursors elsewhere.
            pass

        g._database = conn
        logger.info("Using psycopg2 for PostgreSQL connection")
        return conn

    except Exception as e_psycopg2:
        logger.warning("psycopg2 import/connect failed: %s", e_psycopg2)

    # Try psycopg (psycopg v3)
    try:
        import psycopg
        from psycopg.rows import dict_row

        # psycopg v3 supports row_factory to return dict-like rows
        conn = psycopg.connect(DATABASE_URL, row_factory=dict_row)
        g._database = conn
        logger.info("Using psycopg (psycopg v3) for PostgreSQL connection")
        return conn

    except Exception as e_psycopg:
        logger.warning("psycopg (v3) import/connect failed: %s", e_psycopg)

    # If we reach here, no usable Postgres client is available.
    msg = (
        "No compatible PostgreSQL driver available. The application attempted to use psycopg2 "
        "and psycopg (psycopg v3) but both failed to import/connect. "
        "On Render this commonly happens when Python 3.14 is used with a psycopg2-binary build "
        "that wasn't compiled for that Python ABI (undefined symbol: _PyInterpreterState_Get). "
        "Possible fixes:\n"
        "  * Pin your Python runtime to 3.11 by adding a runtime.txt with 'python-3.11.9' (recommended),\n"
        "  * Or install a driver compatible with your Python version (e.g. 'psycopg' for psycopg v3),\n"
        "  * Or remove DATABASE_URL / use SQLite fallback if you don't actually need Postgres in this environment.\n"
        f"Original psycopg2 error: {e_psycopg2!r}; psycopg error: {e_psycopg!r}"
    )
    logger.error(msg)
    raise RuntimeError(msg)

@app.teardown_appcontext
def close_db(error=None):
    db = getattr(g, "_database", None)
    if db is not None:
        try:
            db.close()
        except Exception:
            pass
        g._database = None

def init_db():
    if USE_POSTGRESQL:
        init_postgres_db()
    else:
        init_sqlite_db()

def init_sqlite_db():
    db = get_db()
    cursor = db.cursor()
    
    # Users table
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            fullName TEXT,
            matricNumber TEXT UNIQUE,
            isApproved INTEGER DEFAULT 0,
            createdAt TEXT
        )
        """
    )
    
    # Attendance table - records persist permanently
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS attendance (
            id TEXT PRIMARY KEY,
            studentId TEXT NOT NULL,
            studentName TEXT,
            matricNumber TEXT,
            courseCode TEXT,
            latitude REAL,
            longitude REAL,
            faceImage TEXT,
            timestamp TEXT,
            date TEXT,
            time TEXT,
            deviceType TEXT,
            UNIQUE(studentId, courseCode, date)
        )
        """
    )
    
    # Reset tokens table
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS reset_tokens (
            token TEXT PRIMARY KEY,
            user_id TEXT,
            expires TEXT
        )
        """
    )
    
    # Session table for server-side sessions (optional, but good for persistence)
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            session_data TEXT,
            expiry TEXT
        )
        """
    )
    
    db.commit()
    logger.info("Initialized SQLite database at %s", SQLITE_DB_PATH)

def init_postgres_db():
    db = get_db()
    cur = db.cursor()

    try:
        # Create users table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL,
                "fullName" TEXT,
                "matricNumber" TEXT UNIQUE,
                "isApproved" INTEGER DEFAULT 0,
                "createdAt" TEXT
            )
        """)

        # Create attendance table with unique constraint - records persist permanently
        cur.execute("""
            CREATE TABLE IF NOT EXISTS attendance (
                id TEXT PRIMARY KEY,
                "studentId" TEXT NOT NULL,
                "studentName" TEXT,
                "matricNumber" TEXT,
                "courseCode" TEXT,
                latitude REAL,
                longitude REAL,
                "faceImage" TEXT,
                timestamp TEXT,
                date TEXT,
                time TEXT,
                "deviceType" TEXT,
                UNIQUE("studentId", "courseCode", date)
            )
        """)

        # Create reset_tokens table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS reset_tokens (
                token TEXT PRIMARY KEY,
                user_id TEXT,
                expires TEXT
            )
        """)
        
        # Create sessions table for server-side sessions
        cur.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                session_data TEXT,
                expiry TEXT
            )
        """)
        
        db.commit()
        logger.info("Initialized PostgreSQL database")
    except Exception as e:
        logger.exception("Error while initializing Postgres DB: %s", e)
        raise

with app.app_context():
    try:
        init_db()

        # Create default admin user if it doesn't exist
        db = get_db()

        # When using psycopg2, to get a dict-like row we need RealDictCursor when creating cursor.
        # We'll create a cursor that returns mapping-like rows if possible.
        def make_cursor_for_db(conn):
            """
            Return a cursor that yields mapping-like rows (dicts) if possible for downstream code.
            """
            # psycopg (v3) connections yield dict-like rows by default if row_factory set.
            try:
                # Try psycopg2 RealDictCursor (psycopg2 may expose extras)
                import psycopg2.extras  # noqa: F401
                return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            except Exception:
                try:
                    # psycopg v3: conn.cursor() returns mapping-like rows if row_factory=dict_row used
                    return conn.cursor()
                except Exception:
                    # fallback generic cursor
                    return conn.cursor()

        cursor = make_cursor_for_db(db)

        if USE_POSTGRESQL:
            cursor.execute("SELECT * FROM users WHERE username = 'admin'")
        else:
            cursor.execute("SELECT * FROM users WHERE username = ?", ('admin',))

        admin = cursor.fetchone()

        if not admin:
            admin_user = {
                "id": str(uuid4()),
                "username": "admin",
                "password": hash_password("admin123"),
                "role": "admin",
                "fullName": "System Administrator",
                "matricNumber": None,
                "isApproved": True,
                "createdAt": now_iso(),
            }

            if USE_POSTGRESQL:
                # Use parameterized insert
                cur = make_cursor_for_db(db)
                cur.execute("""
                    INSERT INTO users (id, username, password, role, "fullName", "matricNumber", "isApproved", "createdAt")
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    admin_user["id"],
                    admin_user["username"],
                    admin_user["password"],
                    admin_user["role"],
                    admin_user["fullName"],
                    admin_user["matricNumber"],
                    admin_user["isApproved"],
                    admin_user["createdAt"],
                ))
            else:
                cursor.execute("""
                    INSERT INTO users (id, username, password, role, fullName, matricNumber, isApproved, createdAt)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    admin_user["id"],
                    admin_user["username"],
                    admin_user["password"],
                    admin_user["role"],
                    admin_user["fullName"],
                    admin_user["matricNumber"],
                    admin_user["isApproved"],
                    admin_user["createdAt"],
                ))

            db.commit()
            logger.info("Created default admin user (username: admin, password: admin123)")

    except Exception as e:
        logger.exception("Failed to initialize DB: %s", e)
        # Reraise so deployment logs show the real failure
        raise

# ==========================
# DB CRUD Helpers
# ==========================
def create_user(user: dict):
    db = get_db()
    cur = db.cursor()

    if USE_POSTGRESQL:
        cur.execute(
            """
            INSERT INTO users (id, username, password, role, "fullName", "matricNumber", "isApproved", "createdAt")
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                user["id"],
                user["username"],
                user["password"],
                user["role"],
                user.get("fullName"),
                user.get("matricNumber"),
                1 if user.get("isApproved") else 0,
                user.get("createdAt", now_iso()),
            ),
        )
    else:
        cur.execute(
            """
            INSERT INTO users (id, username, password, role, fullName, matricNumber, isApproved, createdAt)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user["id"],
                user["username"],
                user["password"],
                user["role"],
                user.get("fullName"),
                user.get("matricNumber"),
                1 if user.get("isApproved") else 0,
                user.get("createdAt", now_iso()),
            ),
        )
    db.commit()

def get_user_by_username_or_matric(identifier):
    db = get_db()
    cur = db.cursor()

    if USE_POSTGRESQL:
        # psycopg2 RealDictCursor or psycopg dict_row will return mapping-like rows
        cur.execute(
            "SELECT * FROM users WHERE username = %s OR \"matricNumber\" = %s LIMIT 1",
            (identifier, identifier),
        )
    else:
        cur.execute(
            "SELECT * FROM users WHERE username = ? OR matricNumber = ? LIMIT 1",
            (identifier, identifier),
        )

    row = cur.fetchone()
    return dict(row) if row else None

def get_user_by_id(user_id):
    db = get_db()
    cur = db.cursor()

    if USE_POSTGRESQL:
        cur.execute("SELECT * FROM users WHERE id = %s LIMIT 1", (user_id,))
    else:
        cur.execute("SELECT * FROM users WHERE id = ? LIMIT 1", (user_id,))

    row = cur.fetchone()
    return dict(row) if row else None

def list_users_safely():
    db = get_db()
    cur = db.cursor()

    if USE_POSTGRESQL:
        cur.execute("SELECT id, username, role, \"fullName\", \"matricNumber\", \"isApproved\", \"createdAt\" FROM users")
    else:
        cur.execute("SELECT id, username, role, fullName, matricNumber, isApproved, createdAt FROM users")

    return [dict(r) for r in cur.fetchall()]

def count_admin_users():
    """Count the number of admin users in the system"""
    db = get_db()
    cur = db.cursor()

    if USE_POSTGRESQL:
        cur.execute("SELECT COUNT(*) as count FROM users WHERE role = 'admin'")
    else:
        cur.execute("SELECT COUNT(*) as count FROM users WHERE role = 'admin'")

    result = cur.fetchone()
    return result['count'] if result else 0

def approve_lecturer_by_id(user_id):
    db = get_db()
    cur = db.cursor()

    if USE_POSTGRESQL:
        cur.execute("UPDATE users SET \"isApproved\" = 1 WHERE id = %s AND role = 'lecturer'", (user_id,))
    else:
        cur.execute("UPDATE users SET isApproved = 1 WHERE id = ? AND role = 'lecturer'", (user_id,))

    db.commit()
    return cur.rowcount > 0

def delete_user_by_id(user_id):
    db = get_db()
    cur = db.cursor()

    if USE_POSTGRESQL:
        cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
    else:
        cur.execute("DELETE FROM users WHERE id = ?", (user_id,))

    db.commit()
    return cur.rowcount > 0

def check_existing_attendance(student_id, course_code, date):
    """Check if attendance already exists for a student in a course on a specific date"""
    db = get_db()
    cur = db.cursor()

    if USE_POSTGRESQL:
        cur.execute(
            "SELECT id FROM attendance WHERE \"studentId\" = %s AND \"courseCode\" = %s AND date = %s LIMIT 1",
            (student_id, course_code, date),
        )
    else:
        cur.execute(
            "SELECT id FROM attendance WHERE studentId = ? AND courseCode = ? AND date = ? LIMIT 1",
            (student_id, course_code, date),
        )

    return cur.fetchone() is not None

def add_attendance_record(record: dict):
    db = get_db()
    cur = db.cursor()

    if USE_POSTGRESQL:
        cur.execute(
            """
            INSERT INTO attendance (id, "studentId", "studentName", "matricNumber", "courseCode",
                latitude, longitude, "faceImage", timestamp, date, time, "deviceType")
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                record["id"],
                record["studentId"],
                record.get("studentName"),
                record.get("matricNumber"),
                record.get("courseCode"),
                record.get("latitude"),
                record.get("longitude"),
                record.get("faceImage"),
                record.get("timestamp"),
                record.get("date"),
                record.get("time"),
                record.get("deviceType"),
            ),
        )
    else:
        cur.execute(
            """
            INSERT INTO attendance (id, studentId, studentName, matricNumber, courseCode,
                latitude, longitude, faceImage, timestamp, date, time, deviceType)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record["id"],
                record["studentId"],
                record.get("studentName"),
                record.get("matricNumber"),
                record.get("courseCode"),
                record.get("latitude"),
                record.get("longitude"),
                record.get("faceImage"),
                record.get("timestamp"),
                record.get("date"),
                record.get("time"),
                record.get("deviceType"),
            ),
        )
    db.commit()

def get_attendance_all():
    db = get_db()
    cur = db.cursor()

    if USE_POSTGRESQL:
        cur.execute("SELECT * FROM attendance ORDER BY timestamp DESC")
    else:
        cur.execute("SELECT * FROM attendance ORDER BY timestamp DESC")

    return [dict(r) for r in cur.fetchall()]

def get_attendance_by_student(student_id):
    db = get_db()
    cur = db.cursor()

    if USE_POSTGRESQL:
        cur.execute("SELECT * FROM attendance WHERE \"studentId\" = %s ORDER BY timestamp DESC", (student_id,))
    else:
        cur.execute("SELECT * FROM attendance WHERE studentId = ? ORDER BY timestamp DESC", (student_id,))

    return [dict(r) for r in cur.fetchall()]

def delete_attendance_by_id(record_id):
    db = get_db()
    cur = db.cursor()

    if USE_POSTGRESQL:
        cur.execute("DELETE FROM attendance WHERE id = %s", (record_id,))
    else:
        cur.execute("DELETE FROM attendance WHERE id = ?", (record_id,))

    db.commit()
    return cur.rowcount > 0

def add_reset_token(token: str, user_id: str, expires_iso: str):
    db = get_db()
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
    db = get_db()
    cur = db.cursor()

    if USE_POSTGRESQL:
        cur.execute("SELECT * FROM reset_tokens WHERE token = %s LIMIT 1", (token,))
    else:
        cur.execute("SELECT * FROM reset_tokens WHERE token = ? LIMIT 1", (token,))

    row = cur.fetchone()
    return dict(row) if row else None

def delete_reset_token(token: str):
    db = get_db()
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
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if "role" not in session or session["role"] not in roles:
                return redirect(url_for("index"))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ==========================
# Routes (views)
# ==========================
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/login")
def login():
    if "user_id" in session:
        # redirect to the correct dashboard
        role = session.get("role")
        if role:
            return redirect(url_for(f"{role}_dashboard"))
    return render_template("login.html")

@app.route("/signup")
def signup():
    if "user_id" in session:
        role = session.get("role")
        if role:
            return redirect(url_for(f"{role}_dashboard"))
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
# API endpoints
# ==========================
@app.route("/api/login", methods=["POST"])
def api_login():
    try:
        data = request.json or {}
        username = data.get("username")
        password = data.get("password")
        remember = bool(data.get("remember", False))

        user = get_user_by_username_or_matric(username)
        if user and verify_password(password, user["password"]):
            if user["role"] == "lecturer" and not user.get("isApproved"):
                return jsonify({"success": False, "message": "Your account is pending approval"}), 403

            # Set session with permanent flag
            session.permanent = True  # Always make sessions permanent
            session.update({
                "user_id": user["id"],
                "username": user["username"],
                "role": user["role"],
                "full_name": user.get("fullName"),
                "matric_number": user.get("matricNumber"),
            })

            # If user requested "remember", extend lifetime further (already permanent, but we can extend)
            if remember:
                session.permanent = True
                # Session already has 30-day lifetime from config

            logger.info("User logged in: %s (role=%s) remember=%s", user["username"], user["role"], remember)
            return jsonify({"success": True, "role": user["role"], "message": "Login successful"})
        else:
            logger.warning("Failed login attempt for username: %s", username)
            return jsonify({"success": False, "message": "Invalid username or password"}), 401
    except Exception as e:
        logger.exception("Error in api_login: %s", e)
        return jsonify({"success": False, "message": "Server error"}), 500

@app.route("/api/signup", methods=["POST"])
def api_signup():
    try:
        data = request.json or {}
        username = data.get("username")
        password = data.get("password")
        role = data.get("role")
        fullName = data.get("fullName")
        matricNumber = data.get("matricNumber")
        remember = bool(data.get("remember", False))

        if not username or not password or not role:
            return jsonify({"success": False, "message": "username, password and role are required"}), 400

        # Check if trying to sign up as admin
        if role == "admin":
            # Count existing admin users
            admin_count = count_admin_users()
            if admin_count >= 1:
                logger.warning("Attempted to create second admin user: %s", username)
                return jsonify({
                    "success": False, 
                    "message": "Admin account already exists. Only one admin user is allowed in the system."
                }), 403

        if get_user_by_username_or_matric(username):
            return jsonify({"success": False, "message": "Username already exists"}), 409

        if role == "student" and matricNumber:
            existing = get_user_by_username_or_matric(matricNumber)
            if existing:
                return jsonify({"success": False, "message": "Matric number already registered"}), 409

        new_user = {
            "id": str(uuid4()),
            "username": username,
            "password": hash_password(password),
            "role": role,
            "fullName": fullName,
            "matricNumber": matricNumber if role == "student" and matricNumber else None,
            "isApproved": False if role == "lecturer" else True,
            "createdAt": now_iso(),
        }

        create_user(new_user)

        # Auto-login for non-lecturers with persistent session
        if role != "lecturer":
            session.permanent = True  # Make session permanent
            session.update({
                "user_id": new_user["id"],
                "username": new_user["username"],
                "role": new_user["role"],
                "full_name": new_user["fullName"],
            })

        logger.info("New user created: %s (role=%s)", username, role)
        return jsonify({
            "success": True,
            "role": role,
            "message": "Account created successfully" + (" (Pending approval)" if role == "lecturer" else "")
        })
    except Exception as e:
        logger.exception("Error in api_signup: %s", e)
        return jsonify({"success": False, "message": "Server error"}), 500

@app.route("/api/logout", methods=["POST"])
def api_logout():
    # Clear session but keep user data in database
    session.clear()
    return jsonify({"success": True})

@app.route("/api/forgot-password", methods=["POST"])
def api_forgot_password():
    try:
        data = request.json or {}
        username = data.get("username")
        user = get_user_by_username_or_matric(username)
        if not user:
            return jsonify({"success": False, "message": "Username not found"}), 404

        token = secrets.token_urlsafe(32)
        expires = (datetime.utcnow() + timedelta(hours=1)).isoformat()
        add_reset_token(token, user["id"], expires)

        logger.info("Reset token created for user %s", username)
        return jsonify({"success": True, "message": "Password reset instructions sent to your email", "demo_token": token})
    except Exception as e:
        logger.exception("Error in forgot-password: %s", e)
        return jsonify({"success": False, "message": "Server error"}), 500

@app.route("/api/reset-password", methods=["POST"])
def api_reset_password():
    try:
        data = request.json or {}
        token = data.get("token")
        new_password = data.get("password")
        if not token or not new_password:
            return jsonify({"success": False, "message": "token and password are required"}), 400

        token_data = get_reset_token(token)
        if token_data and datetime.fromisoformat(token_data["expires"]) > datetime.utcnow():
            user = get_user_by_id(token_data["user_id"])
            if user:
                db = get_db()
                cur = db.cursor()

                if USE_POSTGRESQL:
                    cur.execute("UPDATE users SET password = %s WHERE id = %s", (hash_password(new_password), user["id"]))
                else:
                    cur.execute("UPDATE users SET password = ? WHERE id = ?", (hash_password(new_password), user["id"]))

                db.commit()
                delete_reset_token(token)
                logger.info("Password reset for user id %s", user["id"])
                return jsonify({"success": True, "message": "Password reset successfully"})
        return jsonify({"success": False, "message": "Invalid or expired token"}), 400
    except Exception as e:
        logger.exception("Error in reset-password: %s", e)
        return jsonify({"success": False, "message": "Server error"}), 500

@app.route("/api/submit-attendance", methods=["POST"])
@login_required
@role_required("student")
def api_submit_attendance():
    try:
        data = request.json or {}
        course_code = data.get("courseCode")

        if not course_code:
            return jsonify({"success": False, "message": "Course code is required"}), 400

        today_date = datetime.utcnow().strftime("%Y-%m-%d")

        # Check if student has already submitted attendance for this course today
        if check_existing_attendance(session["user_id"], course_code, today_date):
            logger.warning("Student %s attempted duplicate attendance for course %s on %s",
                          session.get("username"), course_code, today_date)
            return jsonify({
                "success": False,
                "message": "You have already submitted attendance for this course today. Only one submission is allowed per day."
            }), 400

        record = {
            "id": str(uuid4()),
            "studentId": session["user_id"],
            "studentName": session.get("full_name"),
            "matricNumber": data.get("matricNumber"),
            "courseCode": course_code,
            "latitude": data.get("latitude"),
            "longitude": data.get("longitude"),
            "faceImage": data.get("faceImage"),
            "timestamp": now_iso(),
            "date": today_date,
            "time": datetime.utcnow().strftime("%H:%M"),
            "deviceType": data.get("deviceType", "Desktop"),
        }

        try:
            add_attendance_record(record)
            logger.info("Attendance recorded for student %s in course %s",
                       session.get("username"), course_code)
            return jsonify({"success": True, "message": "Attendance submitted successfully"})
        except Exception as e:
            # This handles the case where the UNIQUE constraint catches a duplicate
            logger.warning("Database integrity error - duplicate attendance attempt for student %s in course %s on %s: %s",
                          session.get("username"), course_code, today_date, str(e))
            return jsonify({
                "success": False,
                "message": "You have already submitted attendance for this course today. Only one submission is allowed per day."
            }), 400

    except Exception as e:
        logger.exception("Error in submit-attendance: %s", e)
        return jsonify({"success": False, "message": "Server error"}), 500

@app.route("/api/check-attendance-status", methods=["GET"])
@login_required
@role_required("student")
def api_check_attendance_status():
    """Check if student has already submitted attendance for a specific course today"""
    try:
        course_code = request.args.get("courseCode")
        if not course_code:
            return jsonify({"success": False, "message": "Course code is required"}), 400

        today_date = datetime.utcnow().strftime("%Y-%m-%d")
        has_submitted = check_existing_attendance(session["user_id"], course_code, today_date)

        return jsonify({
            "success": True,
            "hasSubmitted": has_submitted,
            "message": "Already submitted today" if has_submitted else "Can submit attendance"
        })
    except Exception as e:
        logger.exception("Error in check-attendance-status: %s", e)
        return jsonify({"success": False, "message": "Server error"}), 500

@app.route("/api/get-attendance", methods=["GET"])
@login_required
def api_get_attendance():
    try:
        role = session.get("role")
        if role == "student":
            attendance = get_attendance_by_student(session["user_id"])
        elif role in ("lecturer", "admin"):
            attendance = get_attendance_all()
        else:
            attendance = []
        return jsonify({"success": True, "attendance": attendance})
    except Exception as e:
        logger.exception("Error in get-attendance: %s", e)
        return jsonify({"success": False, "message": "Server error"}), 500

@app.route("/api/get-users", methods=["GET"])
@login_required
@role_required("admin")
def api_get_users():
    try:
        users = list_users_safely()
        return jsonify({"success": True, "users": users})
    except Exception as e:
        logger.exception("Error in get-users: %s", e)
        return jsonify({"success": False, "message": "Server error"}), 500

@app.route("/api/approve-lecturer/<user_id>", methods=["POST"])
@login_required
@role_required("admin")
def api_approve_lecturer(user_id):
    try:
        ok = approve_lecturer_by_id(user_id)
        if ok:
            logger.info("Lecturer approved: %s", user_id)
            return jsonify({"success": True, "message": "Lecturer approved successfully"})
        return jsonify({"success": False, "message": "User not found or not a lecturer"}), 404
    except Exception as e:
        logger.exception("Error in approve-lecturer: %s", e)
        return jsonify({"success": False, "message": "Server error"}), 500

@app.route("/api/reject-lecturer/<user_id>", methods=["POST"])
@login_required
@role_required("admin")
def api_reject_lecturer(user_id):
    try:
        deleted = delete_user_by_id(user_id)
        if deleted:
            logger.info("Lecturer rejected/deleted: %s", user_id)
            return jsonify({"success": True, "message": "Lecturer rejected successfully"})
        return jsonify({"success": False, "message": "User not found"}), 404
    except Exception as e:
        logger.exception("Error in reject-lecturer: %s", e)
        return jsonify({"success": False, "message": "Server error"}), 500

@app.route("/api/delete-attendance/<record_id>", methods=["DELETE"])
@login_required
def api_delete_attendance(record_id):
    try:
        if session.get("role") in ["lecturer", "admin"]:
            deleted = delete_attendance_by_id(record_id)
            if deleted:
                logger.info("Attendance deleted: %s by %s", record_id, session.get("username"))
                return jsonify({"success": True, "message": "Record deleted successfully"})
            return jsonify({"success": False, "message": "Record not found"}), 404
        return jsonify({"success": False, "message": "Unauthorized"}), 403
    except Exception as e:
        logger.exception("Error in delete-attendance: %s", e)
        return jsonify({"success": False, "message": "Server error"}), 500

@app.route("/api/current-user", methods=["GET"])
def api_current_user():
    if "user_id" in session:
        user = get_user_by_id(session["user_id"])
        if user:
            return jsonify({
                "success": True,
                "user": {
                    "id": session["user_id"],
                    "username": session.get("username"),
                    "role": session.get("role"),
                    "fullName": session.get("full_name"),
                    "matricNumber": user.get("matricNumber", "Not available"),
                }
            })
    return jsonify({"success": False})

@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({"status": "healthy"}), 200

# ==========================
# Local runner (for dev only)
# ==========================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    logger.info("Running dev server on port %s", port)
    app.run(host="0.0.0.0", port=port, debug=app.debug)