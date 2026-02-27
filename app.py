from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from functools import wraps
import json
import hashlib
import secrets
from datetime import datetime, timedelta
import os

app = Flask(__name__)
# Use environment variable for secret key in production
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
# Disable debug mode in production
app.debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'

# File paths for data storage - make configurable via environment variables
DATA_DIR = os.environ.get('DATA_DIR', '.')
USERS_FILE = os.path.join(DATA_DIR, 'users.json')
ATTENDANCE_FILE = os.path.join(DATA_DIR, 'attendance.json')
RESET_TOKENS_FILE = os.path.join(DATA_DIR, 'reset_tokens.json')

# Initialize JSON files if they don't exist
def init_json_files():
    # Ensure data directory exists
    if DATA_DIR != '.' and not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR, exist_ok=True)
    
    for file_path in [USERS_FILE, ATTENDANCE_FILE, RESET_TOKENS_FILE]:
        if not os.path.exists(file_path):
            with open(file_path, 'w') as f:
                json.dump([], f)

init_json_files()

# Helper functions for JSON operations
def read_json(file_path):
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def write_json(file_path, data):
    with open(file_path, 'w') as f:
        json.dump(data, f, indent=2)

# Password hashing
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password, hashed):
    return hash_password(password) == hashed

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Role-based access decorator
def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'role' not in session or session['role'] not in roles:
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login():
    if 'user_id' in session:
        return redirect(url_for(f"{session['role']}_dashboard"))
    return render_template('login.html')

@app.route('/signup')
def signup():
    if 'user_id' in session:
        return redirect(url_for(f"{session['role']}_dashboard"))
    return render_template('signup.html')

@app.route('/forgot-password')
def forgot_password():
    return render_template('forgot_password.html')

@app.route('/admin-dashboard')
@login_required
@role_required('admin')
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.route('/lecturer-dashboard')
@login_required
@role_required('lecturer')
def lecturer_dashboard():
    return render_template('lecturer_dashboard.html')

@app.route('/student-dashboard')
@login_required
@role_required('student')
def student_dashboard():
    return render_template('student_dashboard.html')

# API Routes
@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    users = read_json(USERS_FILE)
    user = next((u for u in users if u['username'] == username or u.get('matricNumber') == username), None)
    
    if user and verify_password(password, user['password']):
        if user['role'] == 'lecturer' and not user.get('isApproved', False):
            return jsonify({'success': False, 'message': 'Your account is pending approval'})
        
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['role'] = user['role']
        session['full_name'] = user['fullName']
        session['matric_number'] = user.get('matricNumber')
        
        return jsonify({
            'success': True,
            'role': user['role'],
            'message': 'Login successful'
        })
    
    return jsonify({'success': False, 'message': 'Invalid username or password'})

@app.route('/api/signup', methods=['POST'])
def api_signup():
    data = request.json
    users = read_json(USERS_FILE)
    
    # Check if username exists
    if any(u['username'] == data['username'] for u in users):
        return jsonify({'success': False, 'message': 'Username already exists'})
    
    # Check if matric number exists for students
    if data['role'] == 'student' and any(u.get('matricNumber') == data['matricNumber'] for u in users):
        return jsonify({'success': False, 'message': 'Matric number already registered'})
    
    new_user = {
        'id': str(datetime.now().timestamp()),
        'username': data['username'],
        'password': hash_password(data['password']),
        'role': data['role'],
        'fullName': data['fullName'],
        'matricNumber': data.get('matricNumber') if data['role'] == 'student' else None,
        'isApproved': data['role'] != 'lecturer',
        'createdAt': datetime.now().isoformat()
    }
    
    users.append(new_user)
    write_json(USERS_FILE, users)
    
    # Auto login for non-lecturer users
    if data['role'] != 'lecturer':
        session['user_id'] = new_user['id']
        session['username'] = new_user['username']
        session['role'] = new_user['role']
        session['full_name'] = new_user['fullName']
    
    return jsonify({
        'success': True,
        'role': data['role'],
        'message': 'Account created successfully' + (' (Pending approval)' if data['role'] == 'lecturer' else '')
    })

@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({'success': True})

@app.route('/api/forgot-password', methods=['POST'])
def api_forgot_password():
    data = request.json
    username = data.get('username')
    
    users = read_json(USERS_FILE)
    user = next((u for u in users if u['username'] == username or u.get('matricNumber') == username), None)
    
    if user:
        token = secrets.token_urlsafe(32)
        reset_tokens = read_json(RESET_TOKENS_FILE)
        
        reset_tokens.append({
            'user_id': user['id'],
            'token': token,
            'expires': (datetime.now() + timedelta(hours=1)).isoformat()
        })
        
        write_json(RESET_TOKENS_FILE, reset_tokens)
        
        return jsonify({
            'success': True,
            'message': 'Password reset instructions sent to your email',
            'demo_token': token
        })
    
    return jsonify({'success': False, 'message': 'Username not found'})

@app.route('/api/reset-password', methods=['POST'])
def api_reset_password():
    data = request.json
    token = data.get('token')
    new_password = data.get('password')
    
    reset_tokens = read_json(RESET_TOKENS_FILE)
    token_data = next((t for t in reset_tokens if t['token'] == token), None)
    
    if token_data and datetime.fromisoformat(token_data['expires']) > datetime.now():
        users = read_json(USERS_FILE)
        user = next((u for u in users if u['id'] == token_data['user_id']), None)
        
        if user:
            user['password'] = hash_password(new_password)
            write_json(USERS_FILE, users)
            
            reset_tokens = [t for t in reset_tokens if t['token'] != token]
            write_json(RESET_TOKENS_FILE, reset_tokens)
            
            return jsonify({'success': True, 'message': 'Password reset successfully'})
    
    return jsonify({'success': False, 'message': 'Invalid or expired token'})

@app.route('/api/submit-attendance', methods=['POST'])
@login_required
@role_required('student')
def api_submit_attendance():
    data = request.json
    attendance = read_json(ATTENDANCE_FILE)
    
    record = {
        'id': str(datetime.now().timestamp()),
        'studentId': session['user_id'],
        'studentName': session['full_name'],
        'matricNumber': data.get('matricNumber'),
        'courseCode': data.get('courseCode'),
        'latitude': data.get('latitude'),
        'longitude': data.get('longitude'),
        'faceImage': data.get('faceImage'),
        'timestamp': datetime.now().isoformat(),
        'date': datetime.now().strftime('%Y-%m-%d'),
        'time': datetime.now().strftime('%H:%M'),
        'deviceType': data.get('deviceType', 'Desktop')
    }
    
    attendance.append(record)
    write_json(ATTENDANCE_FILE, attendance)
    
    return jsonify({'success': True, 'message': 'Attendance submitted successfully'})

@app.route('/api/get-attendance', methods=['GET'])
@login_required
def api_get_attendance():
    role = session['role']
    attendance = read_json(ATTENDANCE_FILE)
    
    if role == 'student':
        attendance = [a for a in attendance if a['studentId'] == session['user_id']]
    elif role == 'lecturer':
        pass
    
    return jsonify({'success': True, 'attendance': attendance})

@app.route('/api/get-users', methods=['GET'])
@login_required
@role_required('admin')
def api_get_users():
    users = read_json(USERS_FILE)
    for user in users:
        user.pop('password', None)
    return jsonify({'success': True, 'users': users})

@app.route('/api/approve-lecturer/<user_id>', methods=['POST'])
@login_required
@role_required('admin')
def api_approve_lecturer(user_id):
    users = read_json(USERS_FILE)
    user = next((u for u in users if u['id'] == user_id), None)
    
    if user and user['role'] == 'lecturer':
        user['isApproved'] = True
        write_json(USERS_FILE, users)
        return jsonify({'success': True, 'message': 'Lecturer approved successfully'})
    
    return jsonify({'success': False, 'message': 'User not found'})

@app.route('/api/reject-lecturer/<user_id>', methods=['POST'])
@login_required
@role_required('admin')
def api_reject_lecturer(user_id):
    users = read_json(USERS_FILE)
    users = [u for u in users if u['id'] != user_id]
    write_json(USERS_FILE, users)
    return jsonify({'success': True, 'message': 'Lecturer rejected successfully'})

@app.route('/api/delete-attendance/<record_id>', methods=['DELETE'])
@login_required
def api_delete_attendance(record_id):
    attendance = read_json(ATTENDANCE_FILE)
    
    if session['role'] in ['lecturer', 'admin']:
        attendance = [a for a in attendance if a['id'] != record_id]
        write_json(ATTENDANCE_FILE, attendance)
        return jsonify({'success': True, 'message': 'Record deleted successfully'})
    
    return jsonify({'success': False, 'message': 'Unauthorized'})

@app.route('/api/current-user', methods=['GET'])
def api_current_user():
    if 'user_id' in session:
        users = read_json(USERS_FILE)
        user = next((u for u in users if u['id'] == session['user_id']), None)
        
        if user:
            return jsonify({
                'success': True,
                'user': {
                    'id': session['user_id'],
                    'username': session['username'],
                    'role': session['role'],
                    'fullName': session['full_name'],
                    'matricNumber': user.get('matricNumber', 'Not available')
                }
            })
    
    return jsonify({'success': False})

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for Docker"""
    return jsonify({'status': 'healthy'}), 200

@app.route('/health')
def health():
    return {"status": "healthy"}

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)