from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_socketio import SocketIO, join_room, leave_room, send
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_wtf import CSRFProtect
import rsa
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import os
import re

app = Flask(__name__)
csrf = CSRFProtect(app)

app.secret_key = os.urandom(24)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
socketio = SocketIO(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# AES Key
public_key, private_key = rsa.newkeys(2048)
aes_key = hashlib.sha256(b'secret_aes_key').digest()

# DB - User
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    is_active = db.Column(db.Boolean, default=False)

# Helper functions for AES encrypt & decrypt
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def encrypt_aes(key, data):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
    return cipher.iv + ct_bytes

def decrypt_aes(key, data):
    iv = data[:16]
    ct = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')

@app.route('/')
@login_required
def index():
    return render_template('index.html', username=current_user.username)

# Log in
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        print(f"Attempting login for user: {username}")

        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            print(f"Login successful for user: {username}")
            login_user(user)
            user.is_active = True
            db.session.commit()

            session['username'] = username
            session.modified = True

            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        
        flash('Invalid username or password', 'danger')
    return render_template('login.html')

# Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Unique username check
        user_username_exists = User.query.filter_by(username=username).first()
        if user_username_exists:
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))
        
        # Unique email check
        user_email_exists = User.query.filter_by(email=email).first()
        if user_email_exists:
            flash('Email already in use', 'danger')
            return redirect(url_for('register'))
        
        # Email format validation
        email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        if not re.match(email_regex, email):
            flash('Invalid email address', 'danger')
            return redirect(url_for('register'))
        
        # Identical passwords check
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('register'))
        
        # Check for strong password
        password_regex = r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$'
        if not re.match(password_regex, password):
            flash('Password must be at least 8 characters long and include a number and a special character', 'danger')
            return redirect(url_for('register'))
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! You can now log in.', 'success')

        return redirect(url_for('login'))
    return render_template('register.html')

# Log out
@app.route('/logout')
@login_required
def logout():
    if 'username' in session:
        username = session['username']
        user = User.query.filter_by(username=username).first()
        if user:
            user.is_active = False
            db.session.commit()
    system_message = f"{username} has left the room."
    send({'msg': system_message, 'username': 'System', 'type': 'system'}, room='chatroom')
    logout_user()
    active_users = get_active_users()
    socketio.emit('activeUsers', active_users, room='chatroom')
    return redirect(url_for('login'))

# Joining the chat room
@socketio.on('join')
def handle_join(data=None):
    if 'username' in session:
        username = session['username']
    else:
        username = current_user.username
        session['username'] = username
    join_room('chatroom')
    system_message = f"{username} has entered the room."
    send({'msg': system_message, 'username': 'System', 'type': 'system'}, room='chatroom')
    active_users = get_active_users()
    socketio.emit('activeUsers', active_users, room='chatroom')

# Receiving messages from user, and delivering it to the rest
@socketio.on('message')
def handle_message(data):
    print(f"Received message: {data['msg']} from {session['username']}")
    encrypted_message = encrypt_aes(aes_key, data['msg'])
    print(f"Encrypted message: {encrypted_message.hex()}")
    send({'msg': encrypted_message.hex(), 'username': session['username']}, room='chatroom')

# User leaves the chat
@socketio.on('disconnect')
def handle_disconnect():
    if 'username' in session:
        username = session['username']
        user = User.query.filter_by(username=username).first()
        if user:
            user.is_active = False
            db.session.commit()
    system_message = f"{username} has left the room."
    send({'msg': system_message, 'username': 'System', 'type': 'system'}, room='chatroom')
    active_users = get_active_users()
    socketio.emit('activeUsers', active_users, room='chatroom')

# Check for active users in DB (is_active == 1)
def get_active_users():
    return [user.username for user in User.query.filter_by(is_active=True).all()]

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, debug=True)