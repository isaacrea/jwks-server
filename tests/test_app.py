# tests/test_app.py

import pytest
from server import app, generate_and_store_key, KEY_ROTATION_THRESHOLD, ENCRYPTION_KEY
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
import base64
import datetime
import sqlite3
from unittest.mock import patch
from freezegun import freeze_time
import os
from cryptography.fernet import Fernet
import uuid
from argon2 import PasswordHasher
import threading


# Fixture to provide a test client
@pytest.fixture
def client():
    # Set the encryption key for testing
    os.environ['NOT_MY_KEY'] = Fernet.generate_key().decode()
    app.testing = True
    app.config['DB_FILE'] = 'test_database.db'  # Use a separate test DB
    app.config['DISABLE_KEY_ROTATION'] = True  # Disable key rotation
    app.config['RATELIMIT_ENABLED'] = False  # Disable rate limiting during most tests
    # Ensure a fresh database for each test
    with app.app_context():
        init_test_db()
    with app.test_client() as client:
        yield client
    # Clean up after tests
    if os.path.exists('test_database.db'):
        os.remove('test_database.db')
    # Clean up environment variable
    del os.environ['NOT_MY_KEY']


# Helper function to initialize the test database
def init_test_db():
    from server import init_db, generate_and_store_key
    init_db(app.config['DB_FILE'])
    # Generate initial keys
    current_time = datetime.datetime.now(datetime.timezone.utc)
    # Unexpired key
    unexpired_expiration = current_time + datetime.timedelta(hours=1)
    generate_and_store_key(unexpired_expiration, db_file=app.config['DB_FILE'])
    # Expired key
    expired_expiration = current_time - datetime.timedelta(hours=1)
    generate_and_store_key(expired_expiration, db_file=app.config['DB_FILE'])


def test_init_db(client):
    # Remove the test database if it exists
    if os.path.exists(app.config['DB_FILE']):
        os.remove(app.config['DB_FILE'])

    # Call init_db()
    from server import init_db

    init_db(app.config['DB_FILE'])

    # Check that the database and tables exist
    assert os.path.exists(app.config['DB_FILE'])

    conn = sqlite3.connect(app.config['DB_FILE'])
    cursor = conn.cursor()
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='keys'"
    )
    keys_table_exists = cursor.fetchone()
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='users'"
    )
    users_table_exists = cursor.fetchone()
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='auth_logs'"
    )
    auth_logs_table_exists = cursor.fetchone()
    conn.close()

    assert keys_table_exists is not None  # The 'keys' table should exist
    assert users_table_exists is not None  # The 'users' table should exist
    assert auth_logs_table_exists is not None  # The 'auth_logs' table should exist

    # Clean up
    if os.path.exists(app.config['DB_FILE']):
        os.remove(app.config['DB_FILE'])


def test_setup_keys(client):
    # Remove the test database if it exists
    if os.path.exists(app.config['DB_FILE']):
        os.remove(app.config['DB_FILE'])

    # Call setup_keys()
    from server import setup_keys, load_keys_from_db

    app.config['DISABLE_KEY_ROTATION'] = True
    setup_keys()

    # Verify that initial keys are created
    with app.app_context():
        keys_data = load_keys_from_db(include_expired=True, db_file=app.config['DB_FILE'])
        assert len(keys_data) >= 2  # Should have at least two keys

        # Check for unexpired and expired keys
        current_time = datetime.datetime.now(datetime.timezone.utc)
        unexpired_keys = [
            key for key in keys_data if key['expires_at'] > current_time
        ]
        expired_keys = [
            key for key in keys_data if key['expires_at'] <= current_time
        ]

        assert len(unexpired_keys) >= 1  # At least one unexpired key
        assert len(expired_keys) >= 1    # At least one expired key

    # Clean up
    if os.path.exists(app.config['DB_FILE']):
        os.remove(app.config['DB_FILE'])


def test_jwks_endpoint(client):
    response = client.get('/.well-known/jwks.json')
    assert response.status_code == 200
    data = response.get_json()
    assert 'keys' in data
    assert len(data['keys']) > 0  # Should have at least one unexpired key


def test_auth_endpoint_unexpired(client, register_user):
    response = client.post('/auth', json={'username': 'testuser', 'password': register_user['password']})
    assert response.status_code == 200
    data = response.get_json()
    assert 'token' in data
    token = data['token']
    assert token is not None
    # Validate the token
    validate_jwt(token, client, 'testuser')


def test_auth_endpoint_expired(client, register_user):
    response = client.post('/auth?expired', json={'username': 'testuser', 'password': register_user['password']})
    assert response.status_code == 200
    data = response.get_json()
    assert 'token' in data
    token = data['token']
    assert token is not None
    # Validate the token and expect an InvalidTokenError
    with pytest.raises(jwt.InvalidTokenError):
        validate_jwt(token, client, 'testuser')


def test_auth_no_unexpired_keys(client, register_user):
    # Expire all keys
    with app.app_context():
        conn = sqlite3.connect(app.config['DB_FILE'])
        cursor = conn.cursor()
        current_timestamp = int(datetime.datetime.now(
            datetime.timezone.utc).timestamp())
        cursor.execute('UPDATE keys SET exp = ?', (current_timestamp - 3600,))
        conn.commit()
        conn.close()

    # Try to get an unexpired token
    response = client.post('/auth', json={'username': 'testuser', 'password': register_user['password']})
    assert response.status_code == 400
    data = response.get_json()
    assert 'error' in data
    assert data['error'] == 'No valid keys available'


def test_auth_no_expired_keys(client, register_user):
    # Remove all expired keys
    with app.app_context():
        conn = sqlite3.connect(app.config['DB_FILE'])
        cursor = conn.cursor()
        current_timestamp = int(datetime.datetime.now(
            datetime.timezone.utc).timestamp())
        cursor.execute('DELETE FROM keys WHERE exp <= ?', (current_timestamp,))
        conn.commit()
        conn.close()

    # Try to get an expired token
    response = client.post('/auth?expired', json={'username': 'testuser', 'password': register_user['password']})
    assert response.status_code == 400
    data = response.get_json()
    assert 'error' in data
    assert data['error'] == 'No expired keys available'


def test_jwks_no_keys(client):
    # Disable key rotation during this test
    with patch('server.check_and_rotate_keys'):
        # Remove all keys
        with app.app_context():
            conn = sqlite3.connect(app.config['DB_FILE'])
            cursor = conn.cursor()
            cursor.execute('DELETE FROM keys')
            conn.commit()
            conn.close()

        # Fetch JWKS
        response = client.get('/.well-known/jwks.json')
        assert response.status_code == 200
        data = response.get_json()
        assert 'keys' in data
        assert len(data['keys']) == 0  # No keys should be present


def test_auth_invalid_method(client):
    # Send a GET request instead of POST
    response = client.get('/auth')
    assert response.status_code == 405  # Method Not Allowed


def test_auth_invalid_parameters(client, register_user):
    # Send an invalid query parameter
    response = client.post('/auth?invalid_param', json={'username': 'testuser', 'password': register_user['password']})
    assert response.status_code == 200
    data = response.get_json()
    assert 'token' in data  # Should ignore invalid parameters


def test_key_rotation_logic(client):
    from server import check_and_rotate_keys
    current_time = datetime.datetime.now(datetime.timezone.utc)
    with freeze_time(current_time):
        # Expire all keys
        with app.app_context():
            conn = sqlite3.connect(app.config['DB_FILE'])
            cursor = conn.cursor()
            expiring_timestamp = int((current_time - datetime.timedelta(
                seconds=1)).timestamp())
            cursor.execute('UPDATE keys SET exp = ?', (expiring_timestamp,))
            conn.commit()
            conn.close()

        # Run the key rotation function
        check_and_rotate_keys()

        # Check that a new key was generated
        with app.app_context():
            conn = sqlite3.connect(app.config['DB_FILE'])
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM keys WHERE exp > ?',
                           (expiring_timestamp,))
            new_keys_count = cursor.fetchone()[0]
            conn.close()
            assert new_keys_count >= 1


def test_register_endpoint(client):
    # Test successful registration
    response = client.post('/register', json={'username': 'newuser', 'email': 'newuser@example.com'})
    assert response.status_code == 201
    data = response.get_json()
    assert 'password' in data
    password = data['password']
    assert password is not None

    # Verify user is stored in the database
    conn = sqlite3.connect(app.config['DB_FILE'])
    cursor = conn.cursor()
    cursor.execute('SELECT username, password_hash, email FROM users WHERE username = ?', ('newuser',))
    result = cursor.fetchone()
    conn.close()
    assert result is not None
    stored_username, stored_password_hash, stored_email = result
    assert stored_username == 'newuser'
    assert stored_email == 'newuser@example.com'
    # Verify password is hashed
    ph = PasswordHasher()
    try:
        ph.verify(stored_password_hash, password)
    except:
        pytest.fail("Password hash does not match")


def test_register_existing_username(client):
    # Register a user
    client.post('/register', json={'username': 'existinguser', 'email': 'user1@example.com'})
    # Try to register with the same username
    response = client.post('/register', json={'username': 'existinguser', 'email': 'user2@example.com'})
    assert response.status_code == 400
    data = response.get_json()
    assert 'error' in data
    assert data['error'] == 'Username or email already exists'


def test_register_invalid_input(client):
    # Missing username
    response = client.post('/register', json={'email': 'user@example.com'})
    assert response.status_code == 400
    # Missing email
    response = client.post('/register', json={'username': 'user'})
    assert response.status_code == 400
    # Invalid JSON
    response = client.post('/register', data='invalid json', content_type='application/json')
    assert response.status_code == 400


def test_auth_logging(client, register_user):
    # Clear auth_logs table
    with app.app_context():
        conn = sqlite3.connect(app.config['DB_FILE'])
        cursor = conn.cursor()
        cursor.execute('DELETE FROM auth_logs')
        conn.commit()
        conn.close()

    # Perform authentication
    response = client.post('/auth', json={'username': 'testuser', 'password': register_user['password']})
    assert response.status_code == 200

    # Verify that the authentication request was logged
    with app.app_context():
        conn = sqlite3.connect(app.config['DB_FILE'])
        cursor = conn.cursor()
        cursor.execute('SELECT request_ip, user_id FROM auth_logs')
        logs = cursor.fetchall()
        conn.close()
        assert len(logs) == 1
        request_ip, user_id = logs[0]
        assert request_ip == '127.0.0.1'  # Adjust if needed
        assert user_id == register_user['user_id']


def validate_jwt(token, client, expected_sub):
    unverified_headers = jwt.get_unverified_header(token)
    kid = unverified_headers['kid']

    # Fetch JWKS
    jwks_response = client.get('/.well-known/jwks.json')
    jwks = jwks_response.get_json()

    # Find the key with matching kid
    key = next((k for k in jwks['keys'] if k['kid'] == str(kid)), None)
    if key is None:
        raise jwt.InvalidTokenError("Public key not found in JWKS")

    # Decode 'n' and 'e' from Base64URL
    def base64url_decode(input_str):
        rem = len(input_str) % 4
        if rem > 0:
            input_str += '=' * (4 - rem)
        return base64.urlsafe_b64decode(input_str)

    n = int.from_bytes(base64url_decode(key['n']), 'big')
    e = int.from_bytes(base64url_decode(key['e']), 'big')
    public_numbers = rsa.RSAPublicNumbers(e, n)
    public_key = public_numbers.public_key()

    # Verify the token
    payload = jwt.decode(token, public_key, algorithms=['RS256'])
    assert payload['sub'] == expected_sub


# Fixture to register a test user
@pytest.fixture
def register_user(client):
    # Register a new user
    response = client.post('/register', json={'username': 'testuser', 'email': 'testuser@example.com'})
    assert response.status_code == 201
    data = response.get_json()
    password = data['password']
    # Get user ID from database
    conn = sqlite3.connect(app.config['DB_FILE'])
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM users WHERE username = ?', ('testuser',))
    user_id = cursor.fetchone()[0]
    conn.close()
    return {'username': 'testuser', 'password': password, 'user_id': user_id}
