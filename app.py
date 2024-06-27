from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_socketio import SocketIO, join_room, leave_room, send
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_wtf import CSRFProtect
from pyDH import DiffieHellman
import rsa
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import os
import re
import datetime

app = Flask(__name__)
csrf = CSRFProtect(app)

# Generowanie losowego sekretnego klucza do zabezpieczenia sesji aplikacji
app.config['SECRET_KEY'] = os.urandom(24)

# Konfiguracja bazy danych SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(minutes=30)

# Inicjalizacja obiektów
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
socketio = SocketIO(app, manage_session=True)

# Inicjalizacja oraz podpięcie menadżera logowania do aplikacji
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Inicjalizacja metody Diffie Hellmana do wymiany kluczy
dh = DiffieHellman()
server_public_key = dh.gen_public_key() # Generowanie klucza publicznego
server_private_key = dh.get_private_key() # Generowanie klucza prywatnego
shared_secrets = {} # Słownik do przechowywania wspólnych sekretów

# Generowanie pary kluczy RSA
public_key, private_key = rsa.newkeys(2048)

# Generowanie klucza AES za pomocą SHA256
aes_key = hashlib.sha256(b'secret_aes_key').digest()

# Model użytkownika w bazie danych
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    is_active = db.Column(db.Boolean, default=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Funkcja do szyfrowania danych za pomocą AES
def encrypt_aes(key, data):
    """
    Tworzenie nowego obiektu w trybie CBC:
    Każdy blok jest szyfrowany z użyciem wyniku poprzedniego.
    Dzięki temu, nawet przy wysyłaniu tych samych wiadomości, ich szyfrowane wersje wyglądają inaczej.
    Przez to, że każda część jest powiązana z poprzednią, znacznie trudniej jest złamać szyfr.
    """
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size)) # Szyfrowanie danych z paddingiem
    return cipher.iv + ct_bytes # Zwracanie wektora inicjalizacyjnego razem z zaszyfrowanymi danymi

# Funkcja do deszyfrowania danych za pomocą AES
def decrypt_aes(key, data):
    iv = data[:16] # Pobieranie wektora inicjalizacyjnego
    ct = data[16:] # Pobieranie zaszyfrowanych danych
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size) # Deszyfrowanie danych z usunięciem paddingu
    return pt.decode('utf-8') # Zwracanie odszyfrowanych danych jako string

# Endpoint do pobierania klucza publicznego RSA
@app.route('/get_public_key', methods=['GET'])
def get_public_key():
    return jsonify({'public_key': public_key.save_pkcs1().decode()}) # Zwracanie klucza publicznego w postaci JSON

# Endpoint do ustawiania zaszyfrowanego klucza AES
@app.route('/set_encrypted_aes_key', methods=['POST'])
def set_encrypted_aes_key():
    client_public_key = int(request.json['client_public_key']) # Pobieranie klucza publicznego klienta
    dh_server = DiffieHellman(private_key=server_private_key) # Inicjalizacja metody Diffie Hellmana z kluczem prywatnym serwera
    shared_secret = dh_server.gen_shared_key(client_public_key) # Generowanie wspólnego sekretu
    aes_key = hashlib.sha256(shared_secret.encode()).digest() # Generowanie klucza AES z hasha wspólnego sekretu
    session['aes_key'] = aes_key # Przechowywanie klucza AES w sesji
    return 'Key received', 200


@app.route('/')
@login_required
def index():
    return render_template('index.html', username=current_user.username)

# Funkcja odpowiedzialna za logowanie użytkownika
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        print(f"Attempting login for user: {username}")

        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            print(f"Login successful for user: {username}")
            login_user(user, remember=True)
            user.is_active = True
            db.session.commit()

            session['username'] = username
            session.permanent = True

            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        
        flash('Invalid username or password', 'danger')
    return render_template('login.html')

# Funkcja odpowiedzialna za rejestrację nowych użytkowników
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Sprawdzenie, czy użytkownik o podanej nazwie już istnieje
        user_username_exists = User.query.filter_by(username=username).first()
        if user_username_exists:
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))
        
        # Sprawdzenie, czy użytkownik o podanym mailu już istnieje
        user_email_exists = User.query.filter_by(email=email).first()
        if user_email_exists:
            flash('Email already in use', 'danger')
            return redirect(url_for('register'))
        
        # Walidacja formatu e-maila
        email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        if not re.match(email_regex, email):
            flash('Invalid email address', 'danger')
            return redirect(url_for('register'))
        
        # Sprawdzenie zgodności hasła
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('register'))
        
        # Walidacja hasła (min, 8 znaków, cyfra oraz znak specjalny)
        password_regex = r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$'
        if not re.match(password_regex, password):
            flash('Password must be at least 8 characters long and include a number and a special character', 'danger')
            return redirect(url_for('register'))
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8') # Hashowanie hasła
        new_user = User(username=username, email=email, password=hashed_password) # Tworzenie nowego użytkownika w bazie danych
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! You can now log in.', 'success')

        return redirect(url_for('login'))
    return render_template('register.html')

# Wylogowanie użytkownika
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
    session.pop('username', None)
    active_users = get_active_users()
    socketio.emit('activeUsers', active_users, room='chatroom')
    return redirect(url_for('login'))

# Obsługa dołączania do pokoju czatu
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

# Obsługa odbierania wiadomości od użytkownika
@socketio.on('message')
def handle_message(data):
    print(f"Received message: {data['msg']} from {session['username']}")
    encrypted_message = encrypt_aes(aes_key, data['msg']) # Szyfrowanie wiadomości za pomocą AES
    print(f"Encrypted message: {encrypted_message.hex()}") # Wyświetlanie zaszyfrowanej wiadomości w formacie heksadecymalnym
    timestamp = datetime.datetime.now().strftime('%H:%M')
    send({'msg': encrypted_message.hex(), 'username': session['username'], 'timestamp': timestamp}, room='chatroom')

# Obsługa 
@socketio.on('disconnect')
def handle_disconnect():
    if 'username' in session:
        username = session['username']
        user = User.query.filter_by(username=username).first()
        if user:
            user.is_active = False
            db.session.commit()
    system_message = f"{username} has left the room."
    print(f'{username} has left the room')
    send({'msg': system_message, 'username': 'System', 'type': 'system'}, room='chatroom')
    active_users = get_active_users()
    socketio.emit('activeUsers', active_users, room='chatroom')

# Funkcja do pobierania listy aktywnych użytkowników
def get_active_users():
    return [user.username for user in User.query.filter_by(is_active=True).all()]

if __name__ == '__main__':
    with app.app_context():
        db.create_all() # Tworzenie tabel w bazie danych, jeśli nie istnieją
    socketio.run(app, debug=True)