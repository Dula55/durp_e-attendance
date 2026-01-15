import os
import secrets
import json
import base64
from datetime import datetime, timedelta
from flask import (
    Flask, render_template, request, jsonify, session as flask_session,
    redirect, url_for, flash
)
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)

# -----------------------------------------------------------------------------
# App & configuration
# -----------------------------------------------------------------------------
app = Flask(__name__)

# Use environment variables where possible (safer for production)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL', 'sqlite:///attendance.db'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'connect_args': {'check_same_thread': False}
}

# -----------------------------------------------------------------------------
# Extensions
# -----------------------------------------------------------------------------
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# -----------------------------------------------------------------------------
# Models - Simplified to avoid migration issues
# -----------------------------------------------------------------------------
class User(UserMixin, db.Model):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'student', 'lecturer', 'admin'
    full_name = db.Column(db.String(100), nullable=False)
    matric_number = db.Column(db.String(50), unique=True, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    is_approved = db.Column(db.Boolean, default=False)  # For lecturer approval
    approved_by = db.Column(db.String(100), nullable=True)  # Store admin name instead of ID
    approved_at = db.Column(db.DateTime, nullable=True)


class LecturerPIN(db.Model):
    __tablename__ = 'lecturer_pin'

    id = db.Column(db.Integer, primary_key=True)
    pin = db.Column(db.String(6), unique=True, nullable=False)
    lecturer_name = db.Column(db.String(100), nullable=False)
    generated_by = db.Column(db.String(100), nullable=False)
    generated_at = db.Column(db.DateTime, default=datetime.utcnow)
    expiry_date = db.Column(db.DateTime, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    usage_count = db.Column(db.Integer, default=0)
    last_used = db.Column(db.DateTime, nullable=True)


class AttendanceRecord(db.Model):
    __tablename__ = 'attendance_record'

    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, nullable=False)
    student_name = db.Column(db.String(100), nullable=False)
    matric_number = db.Column(db.String(50), nullable=False)
    course_code = db.Column(db.String(20), nullable=False)
    date = db.Column(db.Date, nullable=False)
    time = db.Column(db.Time, nullable=False)
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)
    face_image_path = db.Column(db.String(200), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    device_info = db.Column(db.Text, nullable=True)


class Course(db.Model):
    __tablename__ = 'course'

    id = db.Column(db.Integer, primary_key=True)
    course_code = db.Column(db.String(20), unique=True, nullable=False)
    course_name = db.Column(db.String(100), nullable=False)
    lecturer_id = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Session(db.Model):
    __tablename__ = 'session'

    id = db.Column(db.Integer, primary_key=True)
    session_code = db.Column(db.String(10), unique=True, nullable=False)
    course_id = db.Column(db.Integer, nullable=False)
    lecturer_id = db.Column(db.Integer, nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    attendance_count = db.Column(db.Integer, default=0)


# -----------------------------------------------------------------------------
# Database initialization
# -----------------------------------------------------------------------------
def init_database():
    """Initialize database with all tables"""
    with app.app_context():
        # Create all tables
        db.create_all()
        
        # Check if admin exists, if not create one
        if not User.query.filter_by(role='admin').first():
            admin_password = bcrypt.generate_password_hash('Admin@123').decode('utf-8')
            admin = User(
                username='admin',
                password=admin_password,
                role='admin',
                full_name='System Administrator',
                is_approved=True
            )
            db.session.add(admin)
            db.session.commit()
            print("Default admin created: username='admin', password='Admin@123'")
        
        print("Database initialized successfully")


# -----------------------------------------------------------------------------
# User loader for Flask-Login
# -----------------------------------------------------------------------------
@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except Exception:
        return None


# -----------------------------------------------------------------------------
# Routes: Authentication / User management
# -----------------------------------------------------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        # Redirect to respective dashboard based on role
        if current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif current_user.role == 'lecturer':
            # Check if lecturer is approved
            if not current_user.is_approved:
                flash('Your lecturer account is pending approval by an administrator.', 'warning')
                return redirect(url_for('home'))
            return redirect(url_for('lecturer_dashboard'))
        elif current_user.role == 'student':
            return redirect(url_for('student_dashboard'))
        return redirect(url_for('home'))

    if request.method == 'POST':
        login_method = request.form.get('login_method', 'credentials')

        if login_method == 'credentials':
            username = request.form.get('username')
            password = request.form.get('password')
            remember = request.form.get('remember') == 'on'

            # Allow login by username or matric number
            user = User.query.filter(
                (User.username == username) |
                (User.matric_number == username)
            ).first()

            if user and bcrypt.check_password_hash(user.password, password):
                # Check if lecturer is approved
                if user.role == 'lecturer' and not user.is_approved:
                    flash('Your lecturer account is pending approval by an administrator.', 'warning')
                    return redirect(url_for('home'))
                
                login_user(user, remember=remember)
                flash('Login successful!', 'success')
                
                # Redirect to respective dashboard
                if user.role == 'admin':
                    return redirect(url_for('admin_dashboard'))
                elif user.role == 'lecturer':
                    return redirect(url_for('lecturer_dashboard'))
                elif user.role == 'student':
                    return redirect(url_for('student_dashboard'))
                else:
                    return redirect(url_for('home'))
            else:
                flash('Invalid username or password', 'error')

        elif login_method == 'pin':
            pin = request.form.get('pin')
            pin_record = LecturerPIN.query.filter_by(pin=pin, is_active=True).first()

            if pin_record and pin_record.expiry_date > datetime.utcnow():
                # Create lecturer session access (temporary)
                flask_session['lecturer_pin_access'] = True
                flask_session['lecturer_name'] = pin_record.lecturer_name
                flask_session['pin_id'] = pin_record.id

                # Update PIN usage
                pin_record.usage_count += 1
                pin_record.last_used = datetime.utcnow()
                db.session.commit()

                flash(f'Welcome, {pin_record.lecturer_name}!', 'success')
                return redirect(url_for('lecturer_dashboard'))
            else:
                flash('Invalid or expired PIN', 'error')

    return render_template('login.html', current_year=datetime.now().year)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        # Redirect to respective dashboard based on role
        if current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif current_user.role == 'lecturer':
            return redirect(url_for('lecturer_dashboard'))
        elif current_user.role == 'student':
            return redirect(url_for('student_dashboard'))
        return redirect(url_for('home'))

    if request.method == 'POST':
        role = request.form.get('role')
        full_name = request.form.get('full_name')
        username = request.form.get('username')
        password = request.form.get('password')
        matric_number = request.form.get('matric_number')

        # Validate uniqueness
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists', 'error')
            return render_template('signup.html', current_year=datetime.now().year)

        if role == 'student' and matric_number:
            existing_matric = User.query.filter_by(matric_number=matric_number).first()
            if existing_matric:
                flash('Matric number already registered', 'error')
                return render_template('signup.html', current_year=datetime.now().year)

        if role == 'admin':
            existing_admin = User.query.filter_by(role='admin').first()
            if existing_admin:
                flash('Only one administrator account is allowed. Please contact the system administrator.', 'error')
                return render_template('signup.html', current_year=datetime.now().year)

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Determine approval status based on role
        is_approved = False
        if role == 'student':
            # Students are auto-approved
            is_approved = True
        elif role == 'lecturer':
            # Lecturers require admin approval
            is_approved = False
        elif role == 'admin':
            # Admin accounts are auto-approved
            is_approved = True

        user = User(
            username=username,
            password=hashed_password,
            role=role,
            full_name=full_name,
            matric_number=matric_number if role == 'student' else None,
            is_approved=is_approved
        )

        try:
            db.session.add(user)
            db.session.commit()
            
            if role == 'lecturer':
                flash('Lecturer account created successfully! Please wait for administrator approval before logging in.', 'success')
                return redirect(url_for('login'))
            else:
                login_user(user)
                flash('Account created successfully!', 'success')
                
                # Redirect to respective dashboard
                if user.role == 'admin':
                    return redirect(url_for('admin_dashboard'))
                elif user.role == 'lecturer':
                    return redirect(url_for('lecturer_dashboard'))
                elif user.role == 'student':
                    return redirect(url_for('student_dashboard'))
                else:
                    return redirect(url_for('home'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating account: {str(e)}', 'error')

    return render_template('signup.html', current_year=datetime.now().year)


@app.route('/reset', methods=['GET', 'POST'])
def reset():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif current_user.role == 'lecturer':
            return redirect(url_for('lecturer_dashboard'))
        elif current_user.role == 'student':
            return redirect(url_for('student_dashboard'))
        return redirect(url_for('home'))

    if request.method == 'POST':
        identifier = request.form.get('identifier')
        user_type = request.form.get('user_type', 'student')

        user = User.query.filter(
            (User.username == identifier) |
            (User.matric_number == identifier),
            User.role == user_type
        ).first()

        if user:
            flash('Password reset instructions have been sent to your provided contact.', 'success')
        else:
            flash('No account found with the provided information.', 'error')

    return render_template('reset.html', current_year=datetime.now().year)


@app.route('/logout')
@login_required
def logout():
    # Clear any lecturer PIN session
    flask_session.pop('lecturer_pin_access', None)
    flask_session.pop('lecturer_name', None)
    flask_session.pop('pin_id', None)

    logout_user()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('index'))


# -----------------------------------------------------------------------------
# Pages
# -----------------------------------------------------------------------------
@app.route('/')
def index():
    """Entry point with splash screen"""
    return render_template('index.html')


@app.route("/home")
def home():
    """Main landing page - accessible to all users"""
    return render_template("home.html", current_year=datetime.now().year)


# -----------------------------------------------------------------------------
# Lecturer PIN API and admin PIN management
# -----------------------------------------------------------------------------
@app.route('/lecturer/verify-pin', methods=['POST'])
def verify_pin():
    data = request.get_json(force=True)
    pin = data.get('pin')

    pin_record = LecturerPIN.query.filter_by(pin=pin, is_active=True).first()

    if not pin_record:
        return jsonify({'success': False, 'message': 'Invalid PIN'})

    if pin_record.expiry_date < datetime.utcnow():
        return jsonify({'success': False, 'message': 'PIN has expired'})

    pin_record.usage_count += 1
    pin_record.last_used = datetime.utcnow()
    db.session.commit()

    return jsonify({
        'success': True,
        'message': 'Access granted',
        'pin': {
            'lecturer_name': pin_record.lecturer_name,
            'expiry': pin_record.expiry_date.isoformat()
        }
    })


@app.route('/admin/generate-pin', methods=['POST'])
@login_required
def generate_pin():
    if current_user.role != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'})

    data = request.get_json(force=True)
    lecturer_name = data.get('lecturer_name')
    expiry_days = int(data.get('expiry_days', 7))
    auto_generate = data.get('auto_generate', True)
    custom_pin = data.get('custom_pin', '')

    if auto_generate:
        while True:
            pin = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
            if not LecturerPIN.query.filter_by(pin=pin).first():
                break
    else:
        pin = custom_pin
        if len(pin) != 6 or not pin.isdigit():
            return jsonify({'success': False, 'message': 'PIN must be 6 digits'})
        if LecturerPIN.query.filter_by(pin=pin).first():
            return jsonify({'success': False, 'message': 'PIN already exists'})

    expiry_date = datetime.utcnow() + timedelta(days=expiry_days)
    pin_record = LecturerPIN(
        pin=pin,
        lecturer_name=lecturer_name,
        generated_by=current_user.full_name,
        expiry_date=expiry_date
    )

    try:
        db.session.add(pin_record)
        db.session.commit()
        return jsonify({
            'success': True,
            'message': 'PIN generated successfully',
            'pin': {
                'pin': pin,
                'lecturer_name': lecturer_name,
                'expiry_date': expiry_date.isoformat()
            }
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Error generating PIN: {e}'})


@app.route('/admin/pins')
@login_required
def get_pins():
    if current_user.role != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'})

    pins = LecturerPIN.query.all()
    pins_data = []
    for pin in pins:
        pins_data.append({
            'id': pin.id,
            'pin': pin.pin,
            'lecturer_name': pin.lecturer_name,
            'generated_by': pin.generated_by,
            'generated_at': pin.generated_at.isoformat(),
            'expiry_date': pin.expiry_date.isoformat(),
            'is_active': pin.is_active,
            'usage_count': pin.usage_count,
            'last_used': pin.last_used.isoformat() if pin.last_used else None
        })

    return jsonify({'success': True, 'pins': pins_data})


# -----------------------------------------------------------------------------
# Attendance endpoints
# -----------------------------------------------------------------------------
@app.route('/attendance/submit', methods=['POST'])
@login_required
def submit_attendance():
    if current_user.role != 'student':
        return jsonify({'success': False, 'message': 'Unauthorized'})

    data = request.get_json(force=True)
    course_code = data.get('course_code')
    latitude = data.get('latitude')
    longitude = data.get('longitude')
    face_image_data = data.get('face_image')  # Base64 encoded image

    # Validate course code
    if not course_code:
        return jsonify({'success': False, 'message': 'Course code is required'})

    face_image_path = None
    if face_image_data:
        if ',' in face_image_data:
            face_image_data = face_image_data.split(',')[1]

        os.makedirs('static/face_images', exist_ok=True)
        filename = f"face_{current_user.matric_number}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.jpg"
        face_image_path = f"static/face_images/{filename}"

        with open(face_image_path, 'wb') as f:
            f.write(base64.b64decode(face_image_data))

    attendance = AttendanceRecord(
        student_id=current_user.id,
        student_name=current_user.full_name,
        matric_number=current_user.matric_number,
        course_code=course_code,
        date=datetime.utcnow().date(),
        time=datetime.utcnow().time(),
        latitude=latitude,
        longitude=longitude,
        face_image_path=face_image_path,
        device_info=json.dumps({
            'user_agent': request.user_agent.string,
            'platform': request.user_agent.platform
        })
    )

    try:
        db.session.add(attendance)
        db.session.commit()
        return jsonify({
            'success': True,
            'message': 'Attendance submitted successfully',
            'attendance': {
                'id': attendance.id,
                'date': attendance.date.isoformat(),
                'time': attendance.time.strftime('%H:%M:%S'),
                'course': attendance.course_code
            }
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Error submitting attendance: {e}'})


@app.route('/attendance/records')
@login_required
def get_attendance_records():
    if current_user.role not in ['admin', 'lecturer']:
        return jsonify({'success': False, 'message': 'Unauthorized'})

    records = AttendanceRecord.query.order_by(AttendanceRecord.timestamp.desc()).all()
    records_data = []
    for record in records:
        records_data.append({
            'id': record.id,
            'student_name': record.student_name,
            'matric_number': record.matric_number,
            'course_code': record.course_code,
            'date': record.date.isoformat(),
            'time': record.time.strftime('%H:%M:%S'),
            'latitude': record.latitude,
            'longitude': record.longitude,
            'face_image_path': record.face_image_path,
            'timestamp': record.timestamp.isoformat()
        })

    return jsonify({'success': True, 'records': records_data})


# -----------------------------------------------------------------------------
# Standalone Dashboards for roles - These are the permanent dashboard routes
# -----------------------------------------------------------------------------
@app.route('/dashboard')
@login_required
def dashboard():
    """Universal dashboard route that redirects to role-specific dashboard"""
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif current_user.role == 'lecturer':
        # Check if lecturer is approved
        if not current_user.is_approved:
            flash('Your lecturer account is pending approval by an administrator.', 'warning')
            return redirect(url_for('home'))
        return redirect(url_for('lecturer_dashboard'))
    elif current_user.role == 'student':
        return redirect(url_for('student_dashboard'))
    else:
        return redirect(url_for('home'))


@app.route('/student/dashboard')
@login_required
def student_dashboard():
    if current_user.role != 'student':
        flash('Access denied. Student area only.', 'error')
        return redirect(url_for('home'))

    # Get student's attendance records
    records = AttendanceRecord.query.filter_by(student_id=current_user.id) \
        .order_by(AttendanceRecord.timestamp.desc()).limit(10).all()

    # Calculate statistics
    all_records = AttendanceRecord.query.filter_by(student_id=current_user.id).all()
    today = datetime.utcnow().date()
    today_records = [r for r in all_records if r.date == today]
    total_courses = len(set([r.course_code for r in all_records]))

    stats = {
        'total_attendance': len(all_records),
        'present_today': len(today_records),
        'total_courses': total_courses
    }

    return render_template('student_dashboard.html',
                           current_user=current_user,
                           records=records,
                           stats=stats,
                           current_year=datetime.now().year)


@app.route('/lecturer/dashboard')
@login_required
def lecturer_dashboard():
    # Check if user is a lecturer or has PIN access
    if current_user.role != 'lecturer':
        pin_access = flask_session.get('lecturer_pin_access', False)
        if not pin_access:
            flash('Access denied. Lecturer area only.', 'error')
            return redirect(url_for('home'))
    else:
        # Check if lecturer is approved
        if not current_user.is_approved:
            flash('Your lecturer account is pending approval by an administrator.', 'warning')
            return redirect(url_for('home'))

    # Get attendance records (all records for now - can filter by lecturer's courses later)
    records = AttendanceRecord.query.order_by(AttendanceRecord.timestamp.desc()).limit(50).all()
    today = datetime.utcnow().date()
    today_records = [r for r in records if r.date == today]

    # Get total students count
    total_students = User.query.filter_by(role='student').count()

    # Get active sessions for the lecturer
    active_sessions = []
    if current_user.role == 'lecturer':
        # Get lecturer's active sessions
        lecturer_sessions = Session.query.filter_by(
            lecturer_id=current_user.id, 
            is_active=True
        ).all()
        for session in lecturer_sessions:
            course = Course.query.get(session.course_id)
            active_sessions.append({
                'course_name': course.course_name if course else f"Course {session.course_id}",
                'code': session.session_code,
                'started_at': session.start_time,
                'attendance_count': session.attendance_count
            })
    else:
        # For PIN access, show demo sessions
        active_sessions = [
            {
                'course_name': 'URP 101 - Introduction',
                'code': 'URP101A',
                'started_at': datetime.utcnow() - timedelta(hours=2),
                'attendance_count': 25
            },
            {
                'course_name': 'URP 202 - Regional Planning',
                'code': 'URP202B',
                'started_at': datetime.utcnow() - timedelta(hours=1),
                'attendance_count': 20
            }
        ]

    stats = {
        'total_students': total_students,
        'present_today': len(today_records),
        'absent_today': total_students - len(today_records),
        'total_records': AttendanceRecord.query.count(),
        'active_sessions': len(active_sessions)
    }

    # Get unique course codes for filtering
    course_codes = db.session.query(AttendanceRecord.course_code).distinct().all()
    courses = [{'code': code[0]} for code in course_codes if code[0]]

    # If PIN access, use session name, otherwise use current_user
    if flask_session.get('lecturer_pin_access'):
        flask_session['lecturer_name'] = flask_session.get('lecturer_name', 'Guest Lecturer')

    return render_template('lecturer_dashboard.html',
                           current_user=current_user,
                           stats=stats,
                           records=records,
                           courses=courses,
                           active_sessions=active_sessions,
                           current_year=datetime.now().year)


@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('Access denied. Admin area only.', 'error')
        return redirect(url_for('home'))

    # Calculate statistics
    total_admins = User.query.filter_by(role='admin').count()
    total_students = User.query.filter_by(role='student').count()
    total_lecturers = User.query.filter_by(role='lecturer').count()
    pending_lecturers = User.query.filter_by(role='lecturer', is_approved=False).count()
    total_records = AttendanceRecord.query.count()
    total_pins = LecturerPIN.query.filter_by(is_active=True).count()

    today = datetime.utcnow().date()
    pins_today = LecturerPIN.query.filter(
        LecturerPIN.last_used >= datetime.combine(today, datetime.min.time())
    ).count()

    today_records = AttendanceRecord.query.filter(
        AttendanceRecord.date == today
    ).count()

    stats = {
        'total_admins': total_admins,
        'total_students': total_students,
        'total_lecturers': total_lecturers,
        'pending_lecturers': pending_lecturers,
        'total_users': total_admins + total_students + total_lecturers,
        'total_records': total_records,
        'total_pins': total_pins,
        'pin_usage_today': pins_today,
        'todays_records': today_records
    }

    # Get recent PINs
    recent_pins = LecturerPIN.query.order_by(LecturerPIN.generated_at.desc()).limit(5).all()

    # Get pending lecturer approvals
    pending_approvals = User.query.filter_by(
        role='lecturer', 
        is_approved=False
    ).order_by(User.created_at.desc()).all()

    # Check for system alerts (expiring PINs)
    system_alerts = []
    expiring_pins = LecturerPIN.query.filter(
        LecturerPIN.expiry_date <= datetime.utcnow() + timedelta(days=2),
        LecturerPIN.is_active == True
    ).count()

    if expiring_pins > 0:
        system_alerts.append({
            'type': 'warning',
            'title': f'{expiring_pins} PINs Expiring Soon',
            'message': 'Expire in next 2 days',
            'icon': 'warning'
        })

    if pending_lecturers > 0:
        system_alerts.append({
            'type': 'warning',
            'title': f'{pending_lecturers} Lecturer(s) Awaiting Approval',
            'message': 'Review pending lecturer registrations',
            'icon': 'person_add'
        })

    system_alerts.append({
        'type': 'success',
        'title': 'System Normal',
        'message': 'All systems operational',
        'icon': 'check_circle'
    })

    return render_template('admin_dashboard.html',
                           current_user=current_user,
                           stats=stats,
                           recent_pins=recent_pins,
                           pending_approvals=pending_approvals,
                           system_alerts=system_alerts,
                           current_year=datetime.now().year)


# NEW: Approve lecturer endpoint
@app.route('/admin/approve-lecturer/<int:user_id>', methods=['POST'])
@login_required
def approve_lecturer(user_id):
    if current_user.role != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'})

    user = User.query.get(user_id)
    if not user or user.role != 'lecturer':
        return jsonify({'success': False, 'message': 'Lecturer not found'})

    user.is_approved = True
    user.approved_by = current_user.full_name  # Store admin name instead of ID
    user.approved_at = datetime.utcnow()

    try:
        db.session.commit()
        return jsonify({'success': True, 'message': 'Lecturer approved successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Error approving lecturer: {e}'})


# NEW: Reject lecturer endpoint
@app.route('/admin/reject-lecturer/<int:user_id>', methods=['POST'])
@login_required
def reject_lecturer(user_id):
    if current_user.role != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'})

    user = User.query.get(user_id)
    if not user or user.role != 'lecturer':
        return jsonify({'success': False, 'message': 'Lecturer not found'})

    try:
        db.session.delete(user)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Lecturer registration rejected and removed'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Error rejecting lecturer: {e}'})


# -----------------------------------------------------------------------------
# Simple API endpoints
# -----------------------------------------------------------------------------
@app.route('/api/stats')
@login_required
def get_stats():
    if current_user.role == 'student':
        records = AttendanceRecord.query.filter_by(student_id=current_user.id).all()
        return jsonify({
            'total_attendance': len(records),
            'last_attendance': records[0].timestamp.isoformat() if records else None
        })
    elif current_user.role == 'lecturer':
        today = datetime.utcnow().date()
        records = AttendanceRecord.query.all()
        today_records = [r for r in records if r.date == today]
        total_students = User.query.filter_by(role='student').count()

        return jsonify({
            'total_students': total_students,
            'present_today': len(today_records),
            'absent_today': total_students - len(today_records),
            'total_records': len(records)
        })
    elif current_user.role == 'admin':
        total_admins = User.query.filter_by(role='admin').count()
        total_records = AttendanceRecord.query.count()
        total_pins = LecturerPIN.query.filter_by(is_active=True).count()
        pending_lecturers = User.query.filter_by(role='lecturer', is_approved=False).count()

        today = datetime.utcnow().date()
        pins_today = LecturerPIN.query.filter(
            LecturerPIN.last_used >= datetime.combine(today, datetime.min.time())
        ).count()

        return jsonify({
            'total_admins': total_admins,
            'total_records': total_records,
            'total_pins': total_pins,
            'pin_usage_today': pins_today,
            'pending_lecturers': pending_lecturers
        })

    return jsonify({'success': False})


# -----------------------------------------------------------------------------
# Course Management
# -----------------------------------------------------------------------------
@app.route('/api/courses')
@login_required
def get_courses():
    courses = Course.query.all()
    courses_data = []
    for course in courses:
        courses_data.append({
            'id': course.id,
            'course_code': course.course_code,
            'course_name': course.course_name,
            'lecturer_id': course.lecturer_id
        })
    return jsonify({'success': True, 'courses': courses_data})


# -----------------------------------------------------------------------------
# Session Management
# -----------------------------------------------------------------------------
@app.route('/api/sessions/active')
@login_required
def get_active_sessions():
    if current_user.role not in ['lecturer', 'admin']:
        return jsonify({'success': False, 'message': 'Unauthorized'})

    active_sessions = Session.query.filter_by(is_active=True).all()
    sessions_data = []
    for session in active_sessions:
        course = Course.query.get(session.course_id)
        lecturer = User.query.get(session.lecturer_id)
        sessions_data.append({
            'id': session.id,
            'session_code': session.session_code,
            'course_code': course.course_code if course else 'Unknown',
            'course_name': course.course_name if course else 'Unknown',
            'lecturer_name': lecturer.full_name if lecturer else 'Unknown',
            'start_time': session.start_time.isoformat(),
            'attendance_count': session.attendance_count
        })
    return jsonify({'success': True, 'sessions': sessions_data})


# -----------------------------------------------------------------------------
# Health Check
# -----------------------------------------------------------------------------
@app.route('/health')
def health_check():
    try:
        # Test database connection
        User.query.first()
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'database': 'connected'
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'timestamp': datetime.utcnow().isoformat(),
            'database': 'disconnected',
            'error': str(e)
        }), 500


# -----------------------------------------------------------------------------
# Session heartbeat to keep sessions alive
# -----------------------------------------------------------------------------
@app.route('/session/heartbeat', methods=['POST'])
@login_required
def session_heartbeat():
    """Keep user session alive with AJAX calls"""
    return jsonify({'success': True, 'timestamp': datetime.utcnow().isoformat()})


# -----------------------------------------------------------------------------
# Database reset command (for development)
# -----------------------------------------------------------------------------
@app.cli.command('reset-db')
def reset_db():
    """Reset the database (development only)"""
    with app.app_context():
        # Drop all tables
        db.drop_all()
        # Create all tables
        db.create_all()
        
        # Create default admin
        admin_password = bcrypt.generate_password_hash('Admin@123').decode('utf-8')
        admin = User(
            username='admin',
            password=admin_password,
            role='admin',
            full_name='System Administrator',
            is_approved=True
        )
        db.session.add(admin)
        db.session.commit()
        
        print("Database reset complete!")
        print("Default admin created:")
        print("  Username: admin")
        print("  Password: Admin@123")


# -----------------------------------------------------------------------------
# Database initialization on startup
# -----------------------------------------------------------------------------
@app.before_request
def initialize_database():
    """Initialize database on first request if needed"""
    try:
        # Try to query the database to see if tables exist
        User.query.first()
    except Exception:
        # If tables don't exist, create them
        with app.app_context():
            db.create_all()
            
            # Check if admin exists, if not create one
            if not User.query.filter_by(role='admin').first():
                admin_password = bcrypt.generate_password_hash('Admin@123').decode('utf-8')
                admin = User(
                    username='admin',
                    password=admin_password,
                    role='admin',
                    full_name='System Administrator',
                    is_approved=True
                )
                db.session.add(admin)
                db.session.commit()
                print("Database initialized with default admin")


# -----------------------------------------------------------------------------
# Entry point
# -----------------------------------------------------------------------------
if __name__ == '__main__':
    # For local development only; in production use a WSGI server and set FLASK_APP env var.
    app.run(debug=True, host='0.0.0.0', port=5000)