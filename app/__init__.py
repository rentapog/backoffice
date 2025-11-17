

from flask import Flask, render_template, request, redirect, url_for, session, flash
import os
from dotenv import load_dotenv
from app.claude import claude_bp



load_dotenv()
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your_secret_key_here')
app.register_blueprint(claude_bp)

@app.route('/')
def index():
    return render_template('index.html')


# Admin login route
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Simple check, replace with real authentication
        if username == 'admin' and password == 'admin':
            session['user'] = username
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid credentials')
    return render_template('login.html')

# Admin logout route
@app.route('/admin/logout')
def admin_logout():
    session.pop('user', None)
    return redirect(url_for('admin_login'))

# Admin dashboard route
@app.route('/admin/dashboard')
def admin_dashboard():
    if 'user' not in session:
        return redirect(url_for('admin_login'))
    return render_template('dashboard.html', response=None)

if __name__ == '__main__':
    app.run(debug=True)
