from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone 
import sqlite3
import random
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this'

# Database setup
def init_db():
    conn = sqlite3.connect('zta_users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE, email TEXT, 
                  password_hash TEXT, mfa_secret TEXT, role TEXT, created_at TIMESTAMP)''')
    
    # Add default admin user
    c.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
    if c.fetchone()[0] == 0:
        mfa_secret = str(random.randint(100000, 999999))
        password_hash = generate_password_hash('admin123')
        c.execute("INSERT INTO users (username, email, password_hash, mfa_secret, role, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                 ('admin', 'admin@zta.system', password_hash, mfa_secret, 'admin', datetime.now(timezone.utc)))
    
    conn.commit()
    conn.close()

init_db()

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id, username, role='user'): 
        self.id = id
        self.username = username
        self.role = role 

# Improved MFA system
class MFASystem:
    @staticmethod
    def generate_mfa_code():
        return str(random.randint(100000, 999999))
    
    @staticmethod
    def validate_mfa_code(user_code, stored_code):
        return user_code == stored_code

mfa_system = MFASystem()

# Context-aware security checks
def perform_context_checks(request):
    checks = {}
    
    # Time context
    current_hour = datetime.now().hour
    checks['time_ok'] = (9 <= current_hour <= 20)
    checks['current_time'] = datetime.now().strftime('%H:%M')
    
    # Device context
    checks['user_agent'] = request.headers.get('User-Agent', 'Unknown')
    checks['ip_address'] = request.remote_addr
    
    # Location context (simplified)
    checks['local_access'] = request.remote_addr in ['127.0.0.1', '::1']
    
    return checks

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('zta_users.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user_data = c.fetchone()
    conn.close()
    if user_data:
        return User(user_data[0], user_data[1])
    return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form.get('role', 'user')  # Get role from form, default to 'user'
        
        print(f"DEBUG: Registration form data - username: {username}, role: {role}")  # Debug line
        
        # Context check during registration
        context = perform_context_checks(request)
        print(f" NEW USER REGISTRATION: {username} as {role} from {context['ip_address']}")
        
        conn = sqlite3.connect('zta_users.db')
        c = conn.cursor()
        
        try:
            # Generate MFA secret for new user
            mfa_secret = str(random.randint(100000, 999999))
            password_hash = generate_password_hash(password)  # Hash the password!
            
            c.execute("INSERT INTO users (username, email, password_hash, mfa_secret, role, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                     (username, email, password_hash, mfa_secret, role, datetime.now()))
            conn.commit()
            
            flash(f' Registration successful! Your MFA code is: {mfa_secret} | Role: {role}')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash(' Username already exists!')
        finally:
            conn.close()
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']  # This is plain text from form
        mfa_code = request.form.get('mfa_code', '')
        
        # Enhanced context awareness
        context = perform_context_checks(request)
        print(f"ZTA Context-Aware Login: {username} from {context['ip_address']}")
        
        conn = sqlite3.connect('zta_users.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user_data = c.fetchone()
        conn.close()
        
        # FIX: Use password hashing verification
        if user_data and check_password_hash(user_data[3], password):  # This line is critical!
            if mfa_code == user_data[4]:
                # Check context policies
                if not context['time_ok']:
                    flash(' Security Alert: Login outside business hours!')
                if not context['local_access']:
                    flash(' Security Alert: Remote access detected!')
                
                user = User(user_data[0], user_data[1], user_data[5])
                login_user(user)
                flash(f' Login successful! Role: {user.role}')
                return redirect(url_for('dashboard'))
            else:
                flash(' Invalid MFA code!')
        else:
            flash(' Invalid credentials!')
            print(f"DEBUG: Login failed for {username}")  # Debug line
    
    return render_template('login.html')

# Admin required decorator
def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin():
            flash(' Administrator access required!')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Admin dashboard route
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    conn = sqlite3.connect('zta_users.db')
    c = conn.cursor()
    c.execute("SELECT id, username, email, role, created_at FROM users")
    all_users = c.fetchall()
    conn.close()
    
    context = perform_context_checks(request)
    return render_template('admin_dashboard.html', users=all_users, context=context)


@app.route('/dashboard')
@login_required
def dashboard():
    context = perform_context_checks(request)  # FIXED: Get context and pass to template
    return render_template('dashboard.html', context=context)

@app.route('/api/data')
@login_required
def api_data():
    context = perform_context_checks(request)
    
    # Enhanced context-aware policies
    if not context['time_ok']:
        return jsonify({'error': 'ZTA Policy: Access outside business hours denied'}), 403
    if not context['local_access']:
        return jsonify({'error': 'ZTA Policy: Remote API access denied'}), 403
    
    return jsonify({
        'message': 'Protected data access granted!',
        'user': current_user.username,
        'access_context': context,
        'zta_policies_passed': True
    })

@app.route('/logout')
def logout():
    logout_user()
    flash(' Session terminated securely')
    return redirect(url_for('index'))

@app.route('/debug-routes')
def debug_routes():
    routes = []
    for rule in app.url_map.iter_rules():
        routes.append({
            'endpoint': rule.endpoint,
            'methods': list(rule.methods),
            'path': str(rule)
        })
    return jsonify(routes)

if __name__ == '__main__':
    app.run(debug=True)