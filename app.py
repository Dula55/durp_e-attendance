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
from werkzeug.middleware.proxy_fix import ProxyFix

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
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_NAME = f"{APP_NAME}_session"

# Logging config
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
LOG_FILE = os.path.join(DATA_DIR, f"{APP_NAME}.log")
LOG_MAX_BYTES = int(os.environ.get("LOG_MAX_BYTES", 5 * 1024 * 1024))  # 5 MB
LOG_BACKUP_COUNT = int(os.environ.get("LOG_BACKUP_COUNT", 5))

# Security settings
PASSWORD_MIN_LENGTH = int(os.environ.get("PASSWORD_MIN_LENGTH", 8))
MAX_LOGIN_ATTEMPTS = int(os.environ.get("MAX_LOGIN_ATTEMPTS", 5))
LOGIN_LOCKOUT_TIME = int(os.environ.get("LOGIN_LOCKOUT_TIME", 15))  # minutes
RATE_LIMIT_ENABLED = os.environ.get("RATE_LIMIT_ENABLED", "True").lower() == "true"
RATE_LIMIT_REQUESTS = int(os.environ.get("RATE_LIMIT_REQUESTS", 100))
RATE_LIMIT_PERIOD = int(os.environ.get("RATE_LIMIT_PERIOD", 60))  # seconds

# Admin restriction settings
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ALLOW_NEW_ADMIN_CREATION = os.environ.get("ALLOW_NEW_ADMIN_CREATION", "False").lower() == "true"

# ==========================
# Flask app
# ==========================
app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = SECRET_KEY
app.debug = os.environ.get("FLASK_DEBUG", "False").lower() == "true"

# Make sessions optionally persistent for "remember me"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=30)
app.config["SESSION_COOKIE_HTTPONLY"] = SESSION_COOKIE_HTTPONLY
app.config["SESSION_COOKIE_SECURE"] = SESSION_COOKIE_SECURE
app.config["SESSION_COOKIE_SAMESITE"] = SESSION_COOKIE_SAMESITE
app.config["SESSION_COOKIE_NAME"] = SESSION_COOKIE_NAME

# Add ProxyFix for proper handling of headers when behind a proxy
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# ==========================
# Rate limiting (simple in-memory)
# ==========================
if RATE_LIMIT_ENABLED:
    from collections import defaultdict
    from time import time
    request_counts = defaultdict(list)

    @app.before_request
    def rate_limit():
        """Simple rate limiting middleware"""
        if request.endpoint and request.endpoint.startswith('api_'):
            client_ip = request.remote_addr
            now = time()
            
            # Clean old requests
            request_counts[client_ip] = [t for t in request_counts[client_ip] if now - t < RATE_LIMIT_PERIOD]
            
            # Check rate limit
            if len(request_counts[client_ip]) >= RATE_LIMIT_REQUESTS:
                logger.warning(f"Rate limit exceeded for IP: {client_ip}")
                return jsonify({"success": False, "message": "Rate limit exceeded. Please try again later."}), 429
            
            request_counts[client_ip].append(now)

# ==========================
# Login attempt tracking (simple in-memory)
# ==========================
login_attempts = defaultdict(list)

def check_login_attempts(username, ip_address):
    """Check if login attempts exceed limit"""
    if not MAX_LOGIN_ATTEMPTS:
        return True
    
    key = f"{username}:{ip_address}"
    now = datetime.utcnow()
    
    # Clean old attempts
    login_attempts[key] = [attempt for attempt in login_attempts[key] 
                          if now - attempt < timedelta(minutes=LOGIN_LOCKOUT_TIME)]
    
    return len(login_attempts[key]) < MAX_LOGIN_ATTEMPTS

def record_failed_login(username, ip_address):
    """Record a failed login attempt"""
    key = f"{username}:{ip_address}"
    login_attempts[key].append(datetime.utcnow())

# ==========================
# Utility functions
# ==========================
def hash_password(password: str) -> str:
    """Return SHA256 hex digest of password (simple hashing)."""
    if len(password) < PASSWORD_MIN_LENGTH:
        raise ValueError(f"Password must be at least {PASSWORD_MIN_LENGTH} characters")
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def verify_password(password: str, hashed: str) -> bool:
    """Verify a password against its SHA256 hash."""
    return hash_password(password) == hashed

def now_iso():
    """Return current UTC time in ISO format."""
    return datetime.utcnow().isoformat()

def validate_email(email):
    """Simple email validation"""
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def sanitize_input(input_str):
    """Basic input sanitization"""
    if input_str is None:
        return None
    # Remove any potentially dangerous characters
    dangerous_chars = ['<', '>', '&', '"', "'", ';', '--', '/*', '*/']
    sanitized = input_str
    for char in dangerous_chars:
        sanitized = sanitized.replace(char, '')
    return sanitized

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
        db = sqlite3.connect(
            SQLITE_DB_PATH, 
            detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES, 
            check_same_thread=False,
            timeout=10  # Add timeout for concurrent access
        )
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA journal_mode=WAL;")
            db.execute("PRAGMA foreign_keys=ON;")
            db.execute("PRAGMA synchronous=NORMAL;")
            db.execute("PRAGMA cache_size=10000;")
            db.execute("PRAGMA temp_store=MEMORY;")
        except Exception as e:
            logger.warning(f"Could not set SQLite PRAGMA: {e}")
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

        conn = psycopg2.connect(
            DATABASE_URL,
            connect_timeout=10,
            keepalives=1,
            keepalives_idle=30,
            keepalives_interval=10,
            keepalives_count=5
        )
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
        conn = psycopg.connect(
            DATABASE_URL, 
            row_factory=dict_row,
            connect_timeout=10,
            keepalives_idle=30,
            keepalives_interval=10,
            keepalives_count=5
        )
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
        except Exception as e:
            logger.error(f"Error closing database connection: {e}")
        g._database = None

def init_db():
    if USE_POSTGRESQL:
        init_postgres_db()
    else:
        init_sqlite_db()

def init_sqlite_db():
    db = get_db()
    cursor = db.cursor()
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
            createdAt TEXT,
            lastLogin TEXT,
            loginAttempts INTEGER DEFAULT 0,
            lockedUntil TEXT,
            email TEXT UNIQUE
        )
        """
    )
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
            ipAddress TEXT,
            userAgent TEXT,
            UNIQUE(studentId, courseCode, date)
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS reset_tokens (
            token TEXT PRIMARY KEY,
            user_id TEXT,
            expires TEXT,
            used INTEGER DEFAULT 0
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS login_attempts (
            id TEXT PRIMARY KEY,
            username TEXT,
            ipAddress TEXT,
            timestamp TEXT,
            successful INTEGER DEFAULT 0
        )
        """
    )
    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
        CREATE INDEX IF NOT EXISTS idx_users_matricNumber ON users(matricNumber);
        CREATE INDEX IF NOT EXISTS idx_attendance_studentId ON attendance(studentId);
        CREATE INDEX IF NOT EXISTS idx_attendance_courseCode ON attendance(courseCode);
        CREATE INDEX IF NOT EXISTS idx_attendance_date ON attendance(date);
        CREATE INDEX IF NOT EXISTS idx_reset_tokens_user_id ON reset_tokens(user_id);
        CREATE INDEX IF NOT EXISTS idx_reset_tokens_expires ON reset_tokens(expires);
        """
    )
    db.commit()
    logger.info("Initialized SQLite database at %s with indexes", SQLITE_DB_PATH)

def init_postgres_db():
    db = get_db()
    cur = db.cursor()

    try:
        # Create users table with additional fields
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL,
                "fullName" TEXT,
                "matricNumber" TEXT UNIQUE,
                "isApproved" INTEGER DEFAULT 0,
                "createdAt" TEXT,
                "lastLogin" TEXT,
                "loginAttempts" INTEGER DEFAULT 0,
                "lockedUntil" TEXT,
                "email" TEXT UNIQUE
            )
        """)

        # Create attendance table with unique constraint and additional fields
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
                "ipAddress" TEXT,
                "userAgent" TEXT,
                UNIQUE("studentId", "courseCode", date)
            )
        """)

        # Create reset_tokens table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS reset_tokens (
                token TEXT PRIMARY KEY,
                user_id TEXT,
                expires TEXT,
                used INTEGER DEFAULT 0
            )
        """)

        # Create login_attempts table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS login_attempts (
                id TEXT PRIMARY KEY,
                username TEXT,
                ipAddress TEXT,
                timestamp TEXT,
                successful INTEGER DEFAULT 0
            )
        """)

        # Create indexes for better performance
        cur.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_users_matricNumber ON users(matricNumber);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_attendance_studentId ON attendance(\"studentId\");")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_attendance_courseCode ON attendance(\"courseCode\");")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_attendance_date ON attendance(date);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_reset_tokens_user_id ON reset_tokens(user_id);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_reset_tokens_expires ON reset_tokens(expires);")

        db.commit()
        logger.info("Initialized PostgreSQL database with indexes")
    except Exception as e:
        logger.exception("Error while initializing Postgres DB: %s", e)
        raise

with app.app_context():
    try:
        init_db()

        # Create default admin user if it doesn't exist AND no admin exists
        db = get_db()

        def make_cursor_for_db(conn):
            """Return a cursor that yields mapping-like rows (dicts) if possible for downstream code."""
            try:
                import psycopg2.extras  # noqa: F401
                return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            except Exception:
                try:
                    return conn.cursor()
                except Exception:
                    return conn.cursor()

        cursor = make_cursor_for_db(db)

        # First check if ANY admin exists
        if USE_POSTGRESQL:
            cursor.execute("SELECT * FROM users WHERE role = 'admin'")
        else:
            cursor.execute("SELECT * FROM users WHERE role = ?", ('admin',))

        existing_admins = cursor.fetchall()
        admin_count = len(existing_admins) if existing_admins else 0

        if admin_count == 0:
            # No admin exists, create default admin
            admin_user = {
                "id": str(uuid4()),
                "username": ADMIN_USERNAME,
                "password": hash_password(os.environ.get("DEFAULT_ADMIN_PASSWORD", "admin123")),
                "role": "admin",
                "fullName": "System Administrator",
                "matricNumber": None,
                "isApproved": 1,
                "createdAt": now_iso(),
                "email": os.environ.get("DEFAULT_ADMIN_EMAIL", "admin@example.com"),
            }

            if USE_POSTGRESQL:
                cur = make_cursor_for_db(db)
                cur.execute("""
                    INSERT INTO users (id, username, password, role, "fullName", "matricNumber", "isApproved", "createdAt", email)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    admin_user["id"],
                    admin_user["username"],
                    admin_user["password"],
                    admin_user["role"],
                    admin_user["fullName"],
                    admin_user["matricNumber"],
                    admin_user["isApproved"],
                    admin_user["createdAt"],
                    admin_user["email"],
                ))
            else:
                cursor.execute("""
                    INSERT INTO users (id, username, password, role, fullName, matricNumber, isApproved, createdAt, email)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    admin_user["id"],
                    admin_user["username"],
                    admin_user["password"],
                    admin_user["role"],
                    admin_user["fullName"],
                    admin_user["matricNumber"],
                    admin_user["isApproved"],
                    admin_user["createdAt"],
                    admin_user["email"],
                ))

            db.commit()
            logger.info("Created default admin user (username: %s)", ADMIN_USERNAME)
            logger.warning("Default admin password should be changed immediately!")
        else:
            logger.info(f"Found {admin_count} existing admin user(s). No new admin created.")

            # If there are multiple admins and ALLOW_NEW_ADMIN_CREATION is False,
            # we should log a warning but not modify anything
            if admin_count > 1 and not ALLOW_NEW_ADMIN_CREATION:
                logger.warning(f"Multiple admin users detected ({admin_count}). Consider consolidating to a single admin.")

    except Exception as e:
        logger.exception("Failed to initialize DB: %s", e)
        # Don't raise in production - let the app try to continue
        if app.debug:
            raise

# ==========================
# DB CRUD Helpers
# ==========================
def create_user(user: dict):
    # Check admin restriction before creating new admin
    if user.get("role") == "admin":
        # Check if admin already exists
        existing_admins = list_users_by_role("admin")
        if len(existing_admins) >= 1 and not ALLOW_NEW_ADMIN_CREATION:
            logger.warning(f"Attempted to create additional admin user '{user.get('username')}' - blocked by admin restriction")
            raise ValueError("Cannot create additional admin user. Only one admin is allowed.")

    db = get_db()
    cur = db.cursor()

    if USE_POSTGRESQL:
        cur.execute(
            """
            INSERT INTO users (id, username, password, role, "fullName", "matricNumber", "isApproved", "createdAt", email)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
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
                user.get("email"),
            ),
        )
    else:
        cur.execute(
            """
            INSERT INTO users (id, username, password, role, fullName, matricNumber, isApproved, createdAt, email)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                user.get("email"),
            ),
        )
    db.commit()
    logger.info(f"Created new user: {user['username']} (role: {user['role']})")

def get_user_by_username_or_matric(identifier):
    db = get_db()
    cur = db.cursor()

    if USE_POSTGRESQL:
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
        cur.execute("SELECT id, username, role, \"fullName\", \"matricNumber\", \"isApproved\", \"createdAt\", email FROM users")
    else:
        cur.execute("SELECT id, username, role, fullName, matricNumber, isApproved, createdAt, email FROM users")

    return [dict(r) for r in cur.fetchall()]

def list_users_by_role(role):
    """List users filtered by role"""
    db = get_db()
    cur = db.cursor()

    if USE_POSTGRESQL:
        cur.execute("SELECT id, username, role, \"fullName\", \"matricNumber\", \"isApproved\", \"createdAt\", email FROM users WHERE role = %s", (role,))
    else:
        cur.execute("SELECT id, username, role, fullName, matricNumber, isApproved, createdAt, email FROM users WHERE role = ?", (role,))

    return [dict(r) for r in cur.fetchall()]

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
    # Check if this is the last admin
    user = get_user_by_id(user_id)
    if user and user.get("role") == "admin":
        remaining_admins = list_users_by_role("admin")
        if len(remaining_admins) <= 1:
            logger.error("Attempted to delete the last admin user - blocked")
            raise ValueError("Cannot delete the last admin user")

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

    # Add additional metadata
    record_with_meta = record.copy()
    record_with_meta["ipAddress"] = request.remote_addr if request else None
    record_with_meta["userAgent"] = request.user_agent.string if request and request.user_agent else None

    if USE_POSTGRESQL:
        cur.execute(
            """
            INSERT INTO attendance (id, "studentId", "studentName", "matricNumber", "courseCode",
                latitude, longitude, "faceImage", timestamp, date, time, "deviceType", "ipAddress", "userAgent")
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                record_with_meta["id"],
                record_with_meta.get("studentId"),
                record_with_meta.get("studentName"),
                record_with_meta.get("matricNumber"),
                record_with_meta.get("courseCode"),
                record_with_meta.get("latitude"),
                record_with_meta.get("longitude"),
                record_with_meta.get("faceImage"),
                record_with_meta.get("timestamp"),
                record_with_meta.get("date"),
                record_with_meta.get("time"),
                record_with_meta.get("deviceType"),
                record_with_meta.get("ipAddress"),
                record_with_meta.get("userAgent"),
            ),
        )
    else:
        cur.execute(
            """
            INSERT INTO attendance (id, studentId, studentName, matricNumber, courseCode,
                latitude, longitude, faceImage, timestamp, date, time, deviceType, ipAddress, userAgent)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record_with_meta["id"],
                record_with_meta.get("studentId"),
                record_with_meta.get("studentName"),
                record_with_meta.get("matricNumber"),
                record_with_meta.get("courseCode"),
                record_with_meta.get("latitude"),
                record_with_meta.get("longitude"),
                record_with_meta.get("faceImage"),
                record_with_meta.get("timestamp"),
                record_with_meta.get("date"),
                record_with_meta.get("time"),
                record_with_meta.get("deviceType"),
                record_with_meta.get("ipAddress"),
                record_with_meta.get("userAgent"),
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

def get_attendance_by_course(course_code, date=None):
    """Get attendance filtered by course and optionally date"""
    db = get_db()
    cur = db.cursor()

    if USE_POSTGRESQL:
        if date:
            cur.execute(
                "SELECT * FROM attendance WHERE \"courseCode\" = %s AND date = %s ORDER BY timestamp DESC",
                (course_code, date)
            )
        else:
            cur.execute("SELECT * FROM attendance WHERE \"courseCode\" = %s ORDER BY timestamp DESC", (course_code,))
    else:
        if date:
            cur.execute(
                "SELECT * FROM attendance WHERE courseCode = ? AND date = ? ORDER BY timestamp DESC",
                (course_code, date)
            )
        else:
            cur.execute("SELECT * FROM attendance WHERE courseCode = ? ORDER BY timestamp DESC", (course_code,))

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
        cur.execute("SELECT * FROM reset_tokens WHERE token = %s AND used = 0 LIMIT 1", (token,))
    else:
        cur.execute("SELECT * FROM reset_tokens WHERE token = ? AND used = 0 LIMIT 1", (token,))

    row = cur.fetchone()
    return dict(row) if row else None

def delete_reset_token(token: str):
    db = get_db()
    cur = db.cursor()

    # Mark as used instead of deleting for audit trail
    if USE_POSTGRESQL:
        cur.execute("UPDATE reset_tokens SET used = 1 WHERE token = %s", (token,))
    else:
        cur.execute("UPDATE reset_tokens SET used = 1 WHERE token = ?", (token,))

    db.commit()

# ==========================
# Auth decorators
# ==========================
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            if request.is_json:
                return jsonify({"success": False, "message": "Authentication required"}), 401
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if "role" not in session or session["role"] not in roles:
                if request.is_json:
                    return jsonify({"success": False, "message": "Insufficient permissions"}), 403
                return redirect(url_for("index"))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def admin_only(f):
    """Special decorator for admin-only routes that enforces single admin policy"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "role" not in session or session["role"] != "admin":
            if request.is_json:
                return jsonify({"success": False, "message": "Admin access required"}), 403
            return redirect(url_for("index"))
        
        # Additional check for admin operations
        if request.method in ['POST', 'PUT', 'DELETE']:
            # For modifying operations, check if this is the only admin
            admins = list_users_by_role("admin")
            if len(admins) == 1:
                # This is the only admin, allow all operations
                pass
            elif len(admins) > 1:
                # Multiple admins detected - log warning but allow operations
                logger.warning(f"Multiple admins detected ({len(admins)}). Consider consolidating.")
            
        return f(*args, **kwargs)
    return decorated_function

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
@admin_only
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
        username = sanitize_input(data.get("username", "").strip())
        password = data.get("password", "")
        remember = bool(data.get("remember", False))
        ip_address = request.remote_addr

        if not username or not password:
            return jsonify({"success": False, "message": "Username and password are required"}), 400

        # Check login attempts
        if not check_login_attempts(username, ip_address):
            logger.warning(f"Too many login attempts for username: {username} from IP: {ip_address}")
            return jsonify({
                "success": False, 
                "message": f"Too many failed attempts. Please try again after {LOGIN_LOCKOUT_TIME} minutes."
            }), 429

        user = get_user_by_username_or_matric(username)
        if user and verify_password(password, user["password"]):
            # Check if account is locked
            if user.get("lockedUntil"):
                locked_until = datetime.fromisoformat(user["lockedUntil"])
                if locked_until > datetime.utcnow():
                    return jsonify({
                        "success": False, 
                        "message": "Account is temporarily locked. Please try again later."
                    }), 403

            if user["role"] == "lecturer" and not user.get("isApproved"):
                record_failed_login(username, ip_address)
                return jsonify({"success": False, "message": "Your account is pending approval"}), 403

            # Set session
            session.update({
                "user_id": user["id"],
                "username": user["username"],
                "role": user["role"],
                "full_name": user.get("fullName"),
                "matric_number": user.get("matricNumber"),
            })

            # If user requested "remember", make session permanent
            session.permanent = remember

            # Log successful login
            logger.info("User logged in: %s (role=%s) from IP: %s", user["username"], user["role"], ip_address)
            
            # Reset login attempts on successful login
            key = f"{username}:{ip_address}"
            if key in login_attempts:
                del login_attempts[key]

            return jsonify({"success": True, "role": user["role"], "message": "Login successful"})
        else:
            record_failed_login(username, ip_address)
            logger.warning("Failed login attempt for username: %s from IP: %s", username, ip_address)
            return jsonify({"success": False, "message": "Invalid username or password"}), 401
    except Exception as e:
        logger.exception("Error in api_login: %s", e)
        return jsonify({"success": False, "message": "Server error"}), 500

@app.route("/api/signup", methods=["POST"])
def api_signup():
    try:
        data = request.json or {}
        username = sanitize_input(data.get("username", "").strip())
        password = data.get("password", "")
        role = data.get("role")
        fullName = sanitize_input(data.get("fullName", "").strip())
        matricNumber = sanitize_input(data.get("matricNumber", "").strip())
        email = sanitize_input(data.get("email", "").strip())
        remember = bool(data.get("remember", False))

        # Validation
        if not username or not password or not role:
            return jsonify({"success": False, "message": "Username, password and role are required"}), 400

        if len(password) < PASSWORD_MIN_LENGTH:
            return jsonify({
                "success": False, 
                "message": f"Password must be at least {PASSWORD_MIN_LENGTH} characters"
            }), 400

        if email and not validate_email(email):
            return jsonify({"success": False, "message": "Invalid email format"}), 400

        if role not in ["student", "lecturer"]:
            return jsonify({"success": False, "message": "Invalid role"}), 400

        # Check for existing user
        existing = get_user_by_username_or_matric(username)
        if existing:
            return jsonify({"success": False, "message": "Username already exists"}), 409

        if role == "student" and matricNumber:
            existing = get_user_by_username_or_matric(matricNumber)
            if existing:
                return jsonify({"success": False, "message": "Matric number already registered"}), 409

        # Check admin restriction for any potential admin creation (though role should be student/lecturer)
        if role == "admin":
            return jsonify({"success": False, "message": "Cannot create admin accounts directly"}), 403

        new_user = {
            "id": str(uuid4()),
            "username": username,
            "password": hash_password(password),
            "role": role,
            "fullName": fullName,
            "matricNumber": matricNumber if role == "student" and matricNumber else None,
            "email": email,
            "isApproved": False if role == "lecturer" else True,
            "createdAt": now_iso(),
        }

        try:
            create_user(new_user)
        except ValueError as e:
            return jsonify({"success": False, "message": str(e)}), 403

        # Auto-login for non-lecturers
        if role != "lecturer":
            session.update({
                "user_id": new_user["id"],
                "username": new_user["username"],
                "role": new_user["role"],
                "full_name": new_user["fullName"],
            })
            session.permanent = remember

        logger.info("New user created: %s (role=%s) from IP: %s", username, role, request.remote_addr)
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
    username = session.get("username")
    session.clear()
    if username:
        logger.info(f"User logged out: {username}")
    return jsonify({"success": True})

@app.route("/api/forgot-password", methods=["POST"])
def api_forgot_password():
    try:
        data = request.json or {}
        username = sanitize_input(data.get("username"))

        if not username:
            return jsonify({"success": False, "message": "Username is required"}), 400

        user = get_user_by_username_or_matric(username)
        if not user:
            # Don't reveal that user doesn't exist for security
            logger.info(f"Password reset requested for non-existent user: {username}")
            return jsonify({"success": True, "message": "If the account exists, reset instructions will be sent"})

        # Check if there's already a valid token
        db = get_db()
        cur = db.cursor()
        if USE_POSTGRESQL:
            cur.execute(
                "SELECT token FROM reset_tokens WHERE user_id = %s AND expires > %s AND used = 0",
                (user["id"], now_iso())
            )
        else:
            cur.execute(
                "SELECT token FROM reset_tokens WHERE user_id = ? AND expires > ? AND used = 0",
                (user["id"], now_iso())
            )
        existing = cur.fetchone()
        if existing:
            # Reuse existing token
            token = existing[0] if isinstance(existing, (tuple, list)) else existing["token"]
        else:
            token = secrets.token_urlsafe(32)
            expires = (datetime.utcnow() + timedelta(hours=1)).isoformat()
            add_reset_token(token, user["id"], expires)

        logger.info("Reset token created for user %s", username)
        
        # In production, send email here
        # For demo, return token
        return jsonify({
            "success": True, 
            "message": "Password reset instructions sent to your email",
            "demo_token": token if app.debug else None
        })
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
            return jsonify({"success": False, "message": "Token and password are required"}), 400

        if len(new_password) < PASSWORD_MIN_LENGTH:
            return jsonify({
                "success": False, 
                "message": f"Password must be at least {PASSWORD_MIN_LENGTH} characters"
            }), 400

        token_data = get_reset_token(token)
        if token_data and datetime.fromisoformat(token_data["expires"]) > datetime.utcnow():
            user = get_user_by_id(token_data["user_id"])
            if user:
                db = get_db()
                cur = db.cursor()

                if USE_POSTGRESQL:
                    cur.execute(
                        "UPDATE users SET password = %s WHERE id = %s", 
                        (hash_password(new_password), user["id"])
                    )
                else:
                    cur.execute(
                        "UPDATE users SET password = ? WHERE id = ?", 
                        (hash_password(new_password), user["id"])
                    )

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
        course_code = sanitize_input(data.get("courseCode", "").upper())

        if not course_code:
            return jsonify({"success": False, "message": "Course code is required"}), 400

        # Validate course code format (example: CS101)
        import re
        if not re.match(r'^[A-Z]{2,4}\d{3,4}$', course_code):
            return jsonify({
                "success": False, 
                "message": "Invalid course code format. Use format like CS101"
            }), 400

        today_date = datetime.utcnow().strftime("%Y-%m-%d")

        # Check if student has already submitted attendance for this course today
        if check_existing_attendance(session["user_id"], course_code, today_date):
            logger.warning("Student %s attempted duplicate attendance for course %s on %s from IP: %s",
                          session.get("username"), course_code, today_date, request.remote_addr)
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
            "time": datetime.utcnow().strftime("%H:%M:%S"),
            "deviceType": data.get("deviceType", "Desktop"),
        }

        try:
            add_attendance_record(record)
            logger.info("Attendance recorded for student %s in course %s from IP: %s",
                       session.get("username"), course_code, request.remote_addr)
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
        course_code = sanitize_input(request.args.get("courseCode", "").upper())
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
        course_filter = request.args.get("course")
        date_filter = request.args.get("date")

        if role == "student":
            attendance = get_attendance_by_student(session["user_id"])
        elif role in ("lecturer", "admin"):
            if course_filter:
                attendance = get_attendance_by_course(course_filter, date_filter)
            else:
                attendance = get_attendance_all()
        else:
            attendance = []

        return jsonify({"success": True, "attendance": attendance})
    except Exception as e:
        logger.exception("Error in get-attendance: %s", e)
        return jsonify({"success": False, "message": "Server error"}), 500

@app.route("/api/get-attendance-stats", methods=["GET"])
@login_required
@role_required("admin", "lecturer")
def api_get_attendance_stats():
    """Get attendance statistics"""
    try:
        db = get_db()
        cur = db.cursor()

        if USE_POSTGRESQL:
            # Total attendance records
            cur.execute("SELECT COUNT(*) as total FROM attendance")
            total = dict(cur.fetchone())["total"]

            # Attendance by course
            cur.execute("""
                SELECT "courseCode", COUNT(*) as count 
                FROM attendance 
                GROUP BY "courseCode" 
                ORDER BY count DESC
            """)
            by_course = [dict(r) for r in cur.fetchall()]

            # Attendance by date (last 7 days)
            cur.execute("""
                SELECT date, COUNT(*) as count 
                FROM attendance 
                WHERE date >= date('now', '-7 days')
                GROUP BY date 
                ORDER BY date
            """)
            by_date = [dict(r) for r in cur.fetchall()]

            # Unique students
            cur.execute('SELECT COUNT(DISTINCT "studentId") as unique_students FROM attendance')
            unique_students = dict(cur.fetchone())["unique_students"]
        else:
            cur.execute("SELECT COUNT(*) as total FROM attendance")
            total = cur.fetchone()["total"]

            cur.execute("""
                SELECT courseCode, COUNT(*) as count 
                FROM attendance 
                GROUP BY courseCode 
                ORDER BY count DESC
            """)
            by_course = [dict(r) for r in cur.fetchall()]

            cur.execute("""
                SELECT date, COUNT(*) as count 
                FROM attendance 
                WHERE date >= date('now', '-7 days')
                GROUP BY date 
                ORDER BY date
            """)
            by_date = [dict(r) for r in cur.fetchall()]

            cur.execute('SELECT COUNT(DISTINCT studentId) as unique_students FROM attendance')
            unique_students = cur.fetchone()["unique_students"]

        return jsonify({
            "success": True,
            "stats": {
                "total": total,
                "unique_students": unique_students,
                "by_course": by_course,
                "by_date": by_date
            }
        })
    except Exception as e:
        logger.exception("Error in get-attendance-stats: %s", e)
        return jsonify({"success": False, "message": "Server error"}), 500

@app.route("/api/get-users", methods=["GET"])
@login_required
@role_required("admin")
def api_get_users():
    try:
        users = list_users_safely()
        # Don't return password hashes
        for user in users:
            if "password" in user:
                del user["password"]
        return jsonify({"success": True, "users": users})
    except Exception as e:
        logger.exception("Error in get-users: %s", e)
        return jsonify({"success": False, "message": "Server error"}), 500

@app.route("/api/approve-lecturer/<user_id>", methods=["POST"])
@login_required
@admin_only
def api_approve_lecturer(user_id):
    try:
        ok = approve_lecturer_by_id(user_id)
        if ok:
            logger.info("Lecturer approved: %s by admin %s", user_id, session.get("username"))
            return jsonify({"success": True, "message": "Lecturer approved successfully"})
        return jsonify({"success": False, "message": "User not found or not a lecturer"}), 404
    except Exception as e:
        logger.exception("Error in approve-lecturer: %s", e)
        return jsonify({"success": False, "message": "Server error"}), 500

@app.route("/api/reject-lecturer/<user_id>", methods=["POST"])
@login_required
@admin_only
def api_reject_lecturer(user_id):
    try:
        deleted = delete_user_by_id(user_id)
        if deleted:
            logger.info("Lecturer rejected/deleted: %s by admin %s", user_id, session.get("username"))
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
            # Don't return sensitive data
            return jsonify({
                "success": True,
                "user": {
                    "id": session["user_id"],
                    "username": session.get("username"),
                    "role": session.get("role"),
                    "fullName": session.get("full_name"),
                    "matricNumber": user.get("matricNumber", "Not available"),
                    "email": user.get("email"),
                    "isApproved": user.get("isApproved", False) if user.get("role") == "lecturer" else True,
                }
            })
    return jsonify({"success": False})

@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint for monitoring"""
    health_status = {
        "status": "healthy",
        "timestamp": now_iso(),
        "database": "connected",
        "version": "1.0.0"
    }
    
    # Check database connection
    try:
        db = get_db()
        cur = db.cursor()
        if USE_POSTGRESQL:
            cur.execute("SELECT 1")
        else:
            cur.execute("SELECT 1")
        cur.fetchone()
    except Exception as e:
        health_status["status"] = "degraded"
        health_status["database"] = f"error: {str(e)}"
        logger.error(f"Health check failed: {e}")
        return jsonify(health_status), 503
    
    return jsonify(health_status), 200

@app.route("/metrics", methods=["GET"])
@login_required
@admin_only
def metrics():
    """Basic metrics endpoint for monitoring"""
    try:
        db = get_db()
        cur = db.cursor()

        metrics_data = {
            "timestamp": now_iso(),
            "users": {},
            "attendance": {},
            "system": {}
        }

        # User counts by role
        if USE_POSTGRESQL:
            cur.execute("SELECT role, COUNT(*) as count FROM users GROUP BY role")
        else:
            cur.execute("SELECT role, COUNT(*) as count FROM users GROUP BY role")
        
        for row in cur.fetchall():
            metrics_data["users"][dict(row)["role"]] = dict(row)["count"]

        # Attendance counts
        if USE_POSTGRESQL:
            cur.execute("SELECT COUNT(*) as total FROM attendance")
            metrics_data["attendance"]["total"] = dict(cur.fetchone())["total"]
            
            cur.execute("SELECT COUNT(DISTINCT date) as days FROM attendance")
            metrics_data["attendance"]["days"] = dict(cur.fetchone())["days"]
        else:
            cur.execute("SELECT COUNT(*) as total FROM attendance")
            metrics_data["attendance"]["total"] = cur.fetchone()["total"]
            
            cur.execute("SELECT COUNT(DISTINCT date) as days FROM attendance")
            metrics_data["attendance"]["days"] = cur.fetchone()["days"]

        # System metrics
        import psutil
        metrics_data["system"]["cpu_percent"] = psutil.cpu_percent(interval=1)
        metrics_data["system"]["memory_percent"] = psutil.virtual_memory().percent
        metrics_data["system"]["disk_usage_percent"] = psutil.disk_usage('/').percent

        return jsonify({"success": True, "metrics": metrics_data})
    except Exception as e:
        logger.exception("Error in metrics: %s", e)
        return jsonify({"success": False, "message": "Server error"}), 500

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    if request.is_json:
        return jsonify({"success": False, "message": "Resource not found"}), 404
    return render_template("404.html"), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}")
    if request.is_json:
        return jsonify({"success": False, "message": "Internal server error"}), 500
    return render_template("500.html"), 500

@app.errorhandler(429)
def ratelimit_error(error):
    return jsonify({"success": False, "message": "Rate limit exceeded. Please try again later."}), 429

# ==========================
# Local runner (for dev only)
# ==========================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    logger.info("Running development server on port %s", port)
    logger.warning("This is a development server. Do not use in production!")
    
    # In production, use a proper WSGI server like gunicorn
    if os.environ.get("USE_PRODUCTION_SERVER", "False").lower() == "true":
        logger.error("Running in production mode with Flask's development server is not recommended!")
    
    app.run(host="0.0.0.0", port=port, debug=app.debug)