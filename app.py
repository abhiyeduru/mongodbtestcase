from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from pymongo.mongo_client import MongoClient
from bson import ObjectId
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# MongoDB connection
try:
    client = MongoClient(os.getenv('MONGO_URI'))
    # Send a ping to confirm a successful connection
    client.admin.command('ping')
    print("Pinged your deployment. You successfully connected to MongoDB!")
    db = client['todo_db']
except Exception as e:
    print(f"Error connecting to MongoDB: {e}")
    raise

class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.username = user_data['username']

@login_manager.user_loader
def load_user(user_id):
    user_data = db.users.find_one({'_id': ObjectId(user_id)})
    return User(user_data) if user_data else None

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if db.users.find_one({'username': username}):
            flash('Username already exists')
            return redirect(url_for('signup'))
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user_id = db.users.insert_one({
            'username': username,
            'password': hashed_password
        }).inserted_id
        
        return redirect(url_for('login'))
    return render_template('signup.html')

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

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)

if __name__ == '__main__':
    app.run(debug=True)
