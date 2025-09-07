from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from functools import wraps
from pymongo import MongoClient
from bson import ObjectId
import os
from dotenv import load_dotenv
from datetime import datetime

# Load environment variables
load_dotenv()
from pymongo.mongo_client import MongoClient
from bson import ObjectId
from dotenv import load_dotenv
import os

load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

# Initialize extensions
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User class must be defined before database connection
class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.username = user_data['username']
        self.role = user_data.get('role', 'user')

    def is_admin(self):
        return self.role == 'admin'

@login_manager.user_loader
def load_user(user_id):
    user_data = db.users.find_one({'_id': ObjectId(user_id)})
    return User(user_data) if user_data else None

# MongoDB connection
try:
    client = MongoClient(os.getenv('MONGO_URI'))
    db = client['todo_db']
    # Test the connection
    client.admin.command('ping')
    print("Successfully connected to MongoDB!")
except Exception as e:
    print(f"Error connecting to MongoDB: {e}")
    raise

class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.username = user_data['username']
        self.role = user_data.get('role', 'user')

    def is_admin(self):
        return self.role == 'admin'

@login_manager.user_loader
def load_user(user_id):
    user_data = db.users.find_one({'_id': ObjectId(user_id)})
    return User(user_data) if user_data else None

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role', 'user')

        # Basic validation
        if not username or not password:
            flash('Username and password are required')
            return redirect(url_for('signup'))

        # Check if username exists
        if db.users.find_one({'username': username}):
            flash('Username already exists')
            return redirect(url_for('signup'))

        # First user gets admin role
        if db.users.count_documents({}) == 0:
            role = 'admin'

        # Hash password and create user
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        db.users.insert_one({
            'username': username,
            'password': hashed_password,
            'role': role
        })

        flash('Account created successfully! Please login.')
        return redirect(url_for('login'))

    # For GET request
    is_first_user = db.users.count_documents({}) == 0
    return render_template('signup.html', is_first_user=is_first_user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user_data = db.users.find_one({'username': username})
        if user_data and bcrypt.check_password_hash(user_data['password'], password):
            user = User(user_data)
            login_user(user)
            return redirect(url_for('todo'))
        
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@app.route('/todo')
@login_required
def todo():
    tasks = db.tasks.find({'user_id': current_user.id})
    return render_template('todo.html', tasks=tasks)

@app.route('/add_task', methods=['POST'])
@login_required
def add_task():
    task = request.form['task']
    db.tasks.insert_one({
        'task': task,
        'user_id': current_user.id
    })
    return redirect(url_for('todo'))

@app.route('/delete_task/<task_id>')
@login_required
def delete_task(task_id):
    db.tasks.delete_one({'_id': ObjectId(task_id), 'user_id': current_user.id})
    return redirect(url_for('todo'))

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin():
            flash('You need to be an admin to access this page.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    users = list(db.users.find())
    tasks = list(db.tasks.find())
    return render_template('admin_dashboard.html', users=users, tasks=tasks)

@app.route('/admin/create_option', methods=['POST'])
@login_required
@admin_required
def create_option():
    option_name = request.form['option_name']
    option_value = request.form['option_value']
    db.options.insert_one({
        'name': option_name,
        'value': option_value,
        'created_by': current_user.id
    })
    flash('New option created successfully')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_user/<user_id>', methods=['POST'])
@login_required
@admin_required
def admin_delete_user(user_id):
    if user_id != current_user.id:
        db.users.delete_one({'_id': ObjectId(user_id)})
        db.tasks.delete_many({'user_id': user_id})
        flash('User and their tasks deleted successfully')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_task/<task_id>', methods=['POST'])
@login_required
@admin_required
def admin_delete_task(task_id):
    db.tasks.delete_one({'_id': ObjectId(task_id)})
    flash('Task deleted successfully')
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    # Default port is 5000 if PORT env var is not set
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
