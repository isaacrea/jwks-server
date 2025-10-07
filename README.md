# JWKS Server
A learning/portfolio project that implements a JSON Web Key Set (JWKS) server with:
- Rotating RSA signing keys (private keys encrypted at rest)
- Public key distribution via /.well-known/jwks.json
- User registration with Argon2 password hashing
- JWT issuance (RS256) with kid headers
- Basic authentication logging
- Rate limiting on /auth
> **Not for production. This project is for demonstration and learning only.**

## Table of Contents
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [API](#api)
- [How It Works](#how-it-works)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Notes](#notes)
- [License](#license)

## Quick Start
### 1. Clone and set up Python
   ```bash
   git clone https://github.com/isaacrea/jwks-server.git
   cd jwks-server
   python -m venv .venv
   # Windows: .venv\Scripts\activate
   source .venv/bin/activate
   pip install -r requirements.txt
   ```
### 2. Configure environment
   Generate a Fernet key (urlsafe base64):
   ```bash
   python - <<'PY'
   from cryptography.fernet import Fernet
   print(Fernet.generate_key().decrypt())
   PY
   ```
  Create `.env`:
  ```ini
  # .env
  NOT_MY_KEY=<paste-generated-fernet-key>
  FLASK_ENV=development
  PORT=8080
  ```
  _(You can also export these as environment variables instead of using a `.env` file.)_
### 3. Run
  ```bash
  python server.py
  # Server starts on http://localhost:8080
  ```

## Configuration
Variable | Required | Description
--- | :---: | --- |
`NOT_MY_KEY` | YES | Fernet key for encrypting priviate keys at rest (urlsafe base64).
`PORT` | NO | Port to bind (default `8080`).
`FLASK_ENV` | NO | `development` or `production` (affects Flask debug behavior).

#### .env.example
 ```ini
  NOT_MY_KEY=g744zYz6qjlsAfSEbbIeuFURXmGrWHG3ZEzl_XxhHHw=
  FLASK_ENV=development
  PORT=8080
  ```

## API
### `GET /.well-known/jwks.json`
Returns public keys (unexpired) for verifying tokens.
```bash
curl -s http://localhost:8080/.well-known/jwks.json | jq
```
Example response:
```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "1",
      "n": "<base64url-modulus>",
      "e": "AQAB"
    }
  ]
}
```
---
### `POST /register`
Registers a user by `usernamne` and `email`. Returns a randomly generated password (UUIDv4) once.
#### Request
```json
  { "username": "alice", "email": "alice@example.com" }
```
#### Response
```json
  { "password": "b706dcb7-1c90-4a36-9a70-..." }
```
> Passwords are Argon2-hashed server-side before storage.
---
### `POST /auth[?expired]`
Authenticates a user and returns a signed JWT (RS256).
If `?expired` is present, issues a token that is already expired using the most recently expired key (for testing verifiers).
#### Request
```json
  { "username": "alice", "password": "<uuid-from-register>" }
```
#### Success (200)
```json
  { "token": "<JWT>" }
```
**Rate limiting:** 10 requests/second per client IP. Excess returns **429 Too Many Requests**.

