# server.py

from flask import Flask, request, jsonify
import jwt
from datetime import datetime, timedelta, timezone
import base64
import sqlite3
import threading
import os
import uuid
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Initialize Flask app
app = Flask(__name__)

# Rate Limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[]
)

# Database file name
DB_FILE = 'totally_not_my_privateKeys.db'

# Encryption key from environment variable
ENCRYPTION_KEY = os.environ.get('NOT_MY_KEY')
if ENCRYPTION_KEY is None:
    raise ValueError(
        "Encryption key not found in environment variable 'NOT_MY_KEY'"
        )

# Table schemas
CREATE_TABLE_SQL = '''
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)
'''

CREATE_USERS_TABLE_SQL = '''
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    email TEXT UNIQUE,
    date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
)
'''

CREATE_AUTH_LOGS_TABLE_SQL = '''
CREATE TABLE IF NOT EXISTS auth_logs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_ip TEXT NOT NULL,
    request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER,
    FOREIGN KEY(user_id) REFERENCES users(id)
)
'''

# Key rotation settings
KEY_ROTATION_THRESHOLD = 600
KEY_RETENTION_PERIOD = 7

# Stopping event for threads
stop_event = threading.Event()


# Function to generate RSA key pair
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    return private_key


# Function to encode integers using base64url
def base64url_encode(value):
    bytes_value = int_to_bytes(value)
    encoded = base64.urlsafe_b64encode(bytes_value)
    return encoded.decode('utf-8').rstrip('=')


# Function to convert integer to bytes
def int_to_bytes(value):
    byte_length = (value.bit_length() + 7) // 8
    return value.to_bytes(byte_length, 'big')


# Initialize database
def init_db(db_file=None):
    if db_file is None:
        db_file = app.config.get('DB_FILE', DB_FILE)
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute(CREATE_TABLE_SQL)
    cursor.execute(CREATE_USERS_TABLE_SQL)
    cursor.execute(CREATE_AUTH_LOGS_TABLE_SQL)
    conn.commit()
    conn.close()


# Save key to database
def save_key_to_db(private_key_pem, exp, db_file=None):
    if db_file is None:
        db_file = app.config.get('DB_FILE', DB_FILE)
    # Encrypt the private key
    fernet = Fernet(ENCRYPTION_KEY)
    encrypted_key = fernet.encrypt(private_key_pem.encode('utf-8'))
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO keys (key, exp) VALUES (?, ?)',
        (encrypted_key, int(exp.timestamp()))
    )
    conn.commit()
    kid = cursor.lastrowid
    conn.close()
    return kid


# Load keys from database
def load_keys_from_db(include_expired=False, db_file=None):
    if db_file is None:
        db_file = app.config.get('DB_FILE', DB_FILE)
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    current_timestamp = int(datetime.now(timezone.utc).timestamp())
    if include_expired:
        cursor.execute('SELECT kid, key, exp FROM keys')
    else:
        cursor.execute('SELECT kid, key, exp FROM keys WHERE exp > ?',
                       (current_timestamp,))
    rows = cursor.fetchall()
    conn.close()
    keys = []
    for row in rows:
        kid, encrypted_key, exp_timestamp = row
        # Decrypt the private key
        fernet = Fernet(ENCRYPTION_KEY)
        try:
            decrypted_key_pem = fernet.decrypt(encrypted_key)
        except InvalidToken:
            continue  # Skip keys that cannot be decrypted
        private_key = serialization.load_pem_private_key(
            decrypted_key_pem,
            password=None
        )
        exp = datetime.fromtimestamp(exp_timestamp, tz=timezone.utc)
        keys.append({
            'kid': kid,
            'private_key': private_key,
            'expires_at': exp
        })
    return keys


# Generate and store a new key
def generate_and_store_key(expiration_time, db_file=None):
    if db_file is None:
        db_file = app.config.get('DB_FILE', DB_FILE)
    private_key = generate_rsa_key_pair()
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    kid = save_key_to_db(private_key_pem, expiration_time, db_file=db_file)
    return kid


# Cleanup expired keys from the database
def cleanup_expired_keys(db_file=None):
    if db_file is None:
        db_file = app.config.get('DB_FILE', DB_FILE)
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    retention_period = (
        datetime.now(timezone.utc) - timedelta(days=KEY_RETENTION_PERIOD)
    )
    retention_timestamp = int(retention_period.timestamp())
    cursor.execute('DELETE FROM keys WHERE exp < ?', (retention_timestamp,))
    conn.commit()
    conn.close()


# Check and rotate keys if necessary
def check_and_rotate_keys():
    if not stop_event.is_set():
        timer = threading.Timer(60, check_and_rotate_keys)
        timer.daemon = True
        timer.start()
    current_time = datetime.now(timezone.utc)
    keys_data = load_keys_from_db(include_expired=False)
    needs_new_key = True
    for key_data in keys_data:
        time_remaining = (key_data['expires_at']
                          - current_time).total_seconds()
        if time_remaining > KEY_ROTATION_THRESHOLD:
            needs_new_key = False
            break
    if needs_new_key:
        # Generate a new key
        new_expiration = current_time + timedelta(hours=1)
        generate_and_store_key(new_expiration)
    # Clean up old expired keys
    cleanup_expired_keys()


# Initialize database and set up keys
def setup_keys():
    init_db()
    current_time = datetime.now(timezone.utc)
    # Load keys to check if the database is empty
    db_file = app.config.get('DB_FILE', DB_FILE)
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM keys')
    key_count = cursor.fetchone()[0]
    conn.close()

    if key_count == 0:
        # Generate initial unexpired key
        unexpired_expiration = current_time + timedelta(hours=1)
        generate_and_store_key(unexpired_expiration)
        # Generate initial expired key
        expired_expiration = current_time - timedelta(hours=1)
        generate_and_store_key(expired_expiration)
    # Start the key rotation checker only if not disabled
    if not app.config.get('DISABLE_KEY_ROTATION', False):
        check_and_rotate_keys()


# JWKS endpoint to serve public keys in JWKS format
@app.route('/.well-known/jwks.json')
def jwks():
    keys_data = load_keys_from_db(include_expired=False)
    jwks_keys = []
    for key_data in keys_data:
        kid = key_data['kid']
        private_key = key_data['private_key']
        public_key = private_key.public_key()
        public_numbers = public_key.public_numbers()
        e = public_numbers.e
        n = public_numbers.n
        jwk = {
            'kty': 'RSA',
            'use': 'sig',
            'kid': str(kid),
            'n': base64url_encode(n),
            'e': base64url_encode(e),
        }
        jwks_keys.append(jwk)
    return jsonify({'keys': jwks_keys})


# User Registration Endpoint
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or 'username' not in data or 'email' not in data:
        return jsonify({'error': 'Invalid input'}), 400

    username = data['username']
    email = data['email']

    # Generate a secure password using UUIDv4
    password = str(uuid.uuid4())

    # Hash the password using Argon2
    ph = PasswordHasher(
        time_cost=3,
        memory_cost=64 * 1024,
        parallelism=2,
        hash_len=32,
        salt_len=16
    )
    password_hash = ph.hash(password)

    # Store user details in the database
    db_file = app.config.get('DB_FILE', DB_FILE)
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    try:
        cursor.execute(
            'INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)',
            (username, password_hash, email)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'error': 'Username or email already exists'}), 400
    conn.close()

    # Return the password to the user
    return jsonify({'password': password}), 201


# Authentication Endpoint with Rate Limiting
@app.route('/auth', methods=['POST'])
@limiter.limit("10 per second")
def auth():
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'error': 'Invalid credentials'}), 401

    username = data['username']
    password = data['password']
    expired = 'expired' in request.args
    current_time = datetime.now(timezone.utc)

    # Retrieve user from database
    db_file = app.config.get('DB_FILE', DB_FILE)
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute(
        'SELECT id, password_hash FROM users WHERE username = ?',
        (username,)
    )
    result = cursor.fetchone()
    conn.close()

    if result is None:
        return jsonify({'error': 'Invalid credentials'}), 401

    user_id, password_hash = result

    # Verify password
    ph = PasswordHasher()
    try:
        ph.verify(password_hash, password)
    except VerifyMismatchError:
        return jsonify({'error': 'Invalid credentials'}), 401

    if expired:
        keys_data = load_keys_from_db(include_expired=True)
        expired_keys = [key for key in keys_data if key['expires_at']
                        <= current_time]
        if not expired_keys:
            return jsonify({'error': 'No expired keys available'}), 400
        key_data = max(expired_keys, key=lambda k: k['expires_at'])
        exp = current_time - timedelta(hours=1)
    else:
        keys_data = load_keys_from_db(include_expired=False)
        if not keys_data:
            return jsonify({'error': 'No valid keys available'}), 400
        key_data = max(keys_data, key=lambda k: k['expires_at'])
        exp = current_time + timedelta(minutes=30)

    kid = key_data['kid']
    private_key = key_data['private_key']

    payload = {
        'sub': username,
        'iat': int(current_time.timestamp()),
        'exp': int(exp.timestamp()),
    }

    headers = {
        'kid': str(kid)
    }

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    token = jwt.encode(
        payload,
        private_key_pem,
        algorithm='RS256',
        headers=headers
    )

    # Log the authentication request
    request_ip = request.remote_addr
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)',
        (request_ip, user_id)
    )
    conn.commit()
    conn.close()

    return jsonify({'token': token})


# Run the Flask app on port 8080
if __name__ == '__main__':
    setup_keys()
    try:
        app.run(host='0.0.0.0', port=8080)
    except KeyboardInterrupt:
        print("Stopping server...")
        stop_event.set()
