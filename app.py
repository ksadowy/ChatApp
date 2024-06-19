from flask import Flask, render_template, request, redirect, url_for, session
from flask_socketio import SocketIO, join_room, leave_room, send
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import rsa
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib

app = Flask(__name__)
app.secret_key = 'secret!'
socketio = SocketIO(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# RSA key generation
public_key, private_key = rsa.newkeys(2048)
aes_key = hashlib.sha256(b'secret_aes_key').digest()  # AES key

# Simulated user database
users = {}

class User(UserMixin):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password

@login_manager.user_loader
def load_user(user_id):
    return users.get(user_id)

# Helper functions for AES encryption and decryption
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

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        for user in users.values():
            if user.username == username and user.password == password:
                login_user(user)
                return redirect(url_for('index'))
        return "Invalid username or password"
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user_id = str(len(users) + 1)
        users[user_id] = User(user_id, username, password)
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@socketio.on('join')
def handle_join(data=None):
    if data:
        session['username'] = data['username']
    join_room('chatroom')
    send({'msg': f"{current_user.username} has entered the room."}, room='chatroom')

@socketio.on('message')
def handle_message(data):
    print("Received message:", data['msg'])
    encrypted_message = encrypt_aes(aes_key, data['msg'])
    print("Encrypted message:", encrypted_message.hex())
    send({'msg': encrypted_message.hex(), 'username': current_user.username}, room='chatroom')

@socketio.on('disconnect')
def handle_disconnect():
    send({'msg': f"{current_user.username} has left the room."}, room='chatroom')

if __name__ == '__main__':
    socketio.run(app, debug=True)