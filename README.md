# JWKS Server v3
This project implements a JSON Web Key Set (JWKS) server with enhanced security features. It provides endpoints for key distribution, user registration, authentication, and includes mechanisms for key rotation, AES encryption, authentication logging, and rate limiting.
## Testing
- Test suite covers over 80%
- **Gradebot test for rate limiting did not throw requests fast enough to trigger my rate limiter**
  - Wrote separate test `test_rate_limit.py`
  - Server successfully returns `HTTP 429 Too Many Requests` 
## Features
- AES Encryption of Private Keys
  - Private keys stored in the database are encrypted using AES encryption with the Fernet module from the `cryptography` library.
  - The encryption key is provided via an environment variable `NOT_MY_KEY`, ensuring it is not hardcoded or exposed in the codebase.
- User Registration
  - Users can register via the `POST /register` endpoint by providing a `username` and `email`.
  - A secure password is generated using UUIDv4 and returned to the user in JSON format.
  - Passwords are hashed using Argon2 with recommended security settings before being stored in the database.
- Authentication Logging
  - Successful authentication requests to the `POST /auth` endpoint are logged in the `auth_logs` table.
  - The log includes the request IP address, timestamp, and user ID.
- Rate Limiting
  - A rate limiter is implemented for the `POST /auth` endpoint using `flask-limiter`.
  - Limits requests to 10 requests per second to prevent abuse and brute-force attacks.
  - Excess requests receive a `429 Too Many Requests` response.
  - Only successful authentication attempts are logged.
- Key Rotation
  - RSA key pairs are rotated periodically to enhance security.
  - Keys are stored with an expiration timestamp and are cleaned up after a retention period.
- JWT Issuance
  - The server issues JSON Web Tokens (JWTs) signed with RSA private keys.
  - Tokens include standard claims and are signed using RS256 algorithm.

