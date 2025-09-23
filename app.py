from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime  # Import datetime for time-based policies

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin):
    def __init__(self, id):
        self.id = id

users = {'admin': {'password': 'password'}}

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Device fingerprint logging
        user_agent = request.headers.get('User-Agent')
        ip_address = request.remote_addr
        print(f"ZTA Device Check - Login attempt from: {ip_address}, Device: {user_agent}")
        
        if username in users and users[username]['password'] == password:
            #MFA
            mfa_code = request.form.get('mfa_code', '')
            if mfa_code == '123456': 
                user = User(username)
                login_user(user)
                flash('Logged in successfully with MFA!')
                return redirect(url_for('dashboard'))
            else:
                flash('MFA code required. Use 123456 for demo.')
        else:
            flash('Invalid credentials!')
    
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/api/data')
@login_required
def api_data():
    # Time-based access
    current_hour = datetime.now().hour
    if not (9 <= current_hour <= 17): 
        return jsonify({'error': 'ZTA Policy Violation: Access outside business hours (9AM-5PM) denied'}), 403
    
    return jsonify({
        'message': 'This is protected data!', 
        'user': current_user.id,
        'access_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'policy_enforced': 'Time-based access control active'
    })

if __name__ == '__main__':
    app.run(debug=True)