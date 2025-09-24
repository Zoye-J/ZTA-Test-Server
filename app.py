from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
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
    
    c.execute("SELECT username, role, mfa_secret FROM users WHERE username = 'admin'")
    existing_admin = c.fetchone()
    
    if existing_admin:
        print(f" Admin user exists: {existing_admin[0]} with role: {existing_admin[1]}")
        print(f" Admin MFA Code: {existing_admin[2]}")  
    
        if existing_admin[1] != 'admin':
            c.execute("UPDATE users SET role = 'admin' WHERE username = 'admin'")
            
    else:
        print(" Creating default admin user...")
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
        self.role = role if role is not None else 'user' 
    def is_admin(self): 
        return self.role == 'admin'

# Improved MFA system
class MFASystem:
    @staticmethod
    def generate_mfa_code():
        return str(random.randint(100000, 999999))
    
    @staticmethod
    def validate_mfa_code(user_code, stored_code):
        return user_code == stored_code

mfa_system = MFASystem()

# Context-aware
def perform_context_checks(request):
    checks = {}
    
    # Time context
    current_hour = datetime.now().hour
    checks['time_ok'] = (9 <= current_hour <= 23)
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
        user = User(user_data[0], user_data[1], user_data[5])
        return user
    else:
        print(" No user found in database")
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
        role = request.form.get('role', 'user') 
        
        print(f"DEBUG: Registration form data - username: {username}, role: {role}")  
        
        # Context check during registration
        context = perform_context_checks(request)
        print(f" NEW USER REGISTRATION: {username} as {role} from {context['ip_address']}")
        
        conn = sqlite3.connect('zta_users.db')
        c = conn.cursor()
        
        try:
            # Generate MFA secret for new user
            mfa_secret = str(random.randint(100000, 999999))
            password_hash = generate_password_hash(password) 
            
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
        password = request.form['password']
        mfa_code = request.form.get('mfa_code', '')
        context = perform_context_checks(request)
        print(f" LOGIN ATTEMPT: {username} from {context['ip_address']} at {datetime.now().strftime('%H:%M:%S')}")
   
        
        conn = sqlite3.connect('zta_users.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user_data = c.fetchone()
        conn.close()
        
        if user_data:
            print(f" USER DATA: ID={user_data[0]}, Role={user_data[5]}")
        
        if user_data and check_password_hash(user_data[3], password):
            if mfa_code == user_data[4]:
                user = User(user_data[0], user_data[1], user_data[5])
                
                login_user(user)
                flash(f' Login successful! Role: {user.role}')
                return redirect(url_for('dashboard'))
            else:
                flash(' Invalid MFA code!')
        else:
            flash(' Invalid credentials!')
    
    return render_template('login.html')


def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin():
            flash(' Administrator access required!')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def get_browser_name(user_agent):
    user_agent = user_agent.lower()
    
    if 'edg/' in user_agent or 'edge/' in user_agent:
        return 'Microsoft Edge'
    elif 'chrome/' in user_agent and 'edg/' not in user_agent:
        return 'Google Chrome'
    elif 'firefox/' in user_agent or 'fxios/' in user_agent:
        return 'Mozilla Firefox'
    elif 'safari/' in user_agent and 'chrome/' not in user_agent:
        return 'Safari'
    elif 'opera/' in user_agent or 'opr/' in user_agent:
        return 'Opera'
    elif 'trident/' in user_agent or 'msie' in user_agent:
        return 'Internet Explorer'
    else:
        return 'Unknown Browser'
    
@app.route('/dashboard')
@login_required
def dashboard():
    context = perform_context_checks(request)
    browser_name = get_browser_name(context['user_agent'])
    print(f" DASHBOARD: {current_user.username} | {datetime.now().strftime('%H:%M:%S')} | {context['ip_address']} | {browser_name}")
    if current_user.is_admin():
        return render_template('dashboard_admin.html', context=context)
    else:
        return render_template('dashboard_user.html', context=context)


@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    context = perform_context_checks(request)
    browser_name = get_browser_name(context['user_agent'])
    print(f"ADMIN DASHBOARD: {current_user.username} | {datetime.now().strftime('%H:%M:%S')} | {context['ip_address']} | {browser_name}")
    conn = sqlite3.connect('zta_users.db')
    c = conn.cursor()
    c.execute("SELECT id, username, email, role, created_at FROM users")
    all_users = c.fetchall()
    conn.close()
    
    return render_template('admin_dashboard.html', users=all_users, context=context)


@app.route('/api/data')
@login_required
def api_data():
    context = perform_context_checks(request)
    browser_name = get_browser_name(context['user_agent'])
    print(f" API: {current_user.username} | {datetime.now().strftime('%H:%M:%S')} | {context['ip_address']} | {browser_name}")
    
    
    if not context['time_ok']:
        return jsonify({'error': 'ZTA Policy: Access outside business hours denied'}), 403
    if not context['local_access']:
        return jsonify({'error': 'ZTA Policy: Remote API access denied'}), 403
    
    return jsonify({
        'message': 'Protected data access granted!',
    })

@app.route('/logout')
def logout():
    logout_user()
    flash(' Session terminated securely')
    return redirect(url_for('index'))

@app.route('/clear-session')
def clear_session():
    logout_user()
    session.clear()
    flash(' Session completely cleared. Please login fresh.')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)