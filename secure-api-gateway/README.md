# Secure API Gateway

A production-quality Python FastAPI application demonstrating authentication, authorization, rate limiting, and security best practices.

## Quick Start

```bash
cd secure-api-gateway
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Swagger docs: [http://localhost:8000/docs](http://localhost:8000/docs)

## Architecture

```
app/
├── main.py              # FastAPI app factory, middleware registration, route inclusion
├── auth.py              # JWT creation/validation, password hashing, RBAC dependencies
├── security.py          # Security headers, JWT extraction, request logging middleware
├── rate_limiter.py      # Sliding-window rate limiter with pluggable backend
├── models.py            # Pydantic models for request/response validation
├── routes/
│   ├── auth_routes.py       # /login, /refresh, /me
│   ├── protected_routes.py  # /data (any user), /admin (admin only)
│   └── simulation_routes.py # /simulate-attack
└── utils/
    ├── logging.py       # Structured JSON logger for security events
    └── sanitize.py      # Input sanitization helpers
```

## Demo Users

| Username | Password   | Role  |
|----------|------------|-------|
| admin    | admin123!  | admin |
| alice    | user1234   | user  |

## API Endpoints

| Method | Path              | Auth Required | Role     | Description                    |
|--------|-------------------|---------------|----------|--------------------------------|
| POST   | `/login`          | No            | -        | Get JWT token                  |
| POST   | `/refresh`        | No            | -        | Refresh an existing token      |
| GET    | `/me`             | Yes           | Any      | Current user info              |
| GET    | `/data`           | Yes           | Any      | Access protected data          |
| POST   | `/data`           | Yes           | Any      | Submit validated data          |
| GET    | `/admin`          | Yes           | admin    | Admin-only endpoint            |
| POST   | `/simulate-attack`| No            | -        | Run attack simulations         |
| GET    | `/health`         | No            | -        | Health check                   |
| GET    | `/docs`           | No            | -        | Swagger UI                     |

## Example curl Commands

### Login
```bash
# Get a JWT token
curl -s -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123!"}' | python3 -m json.tool

# Store the token
TOKEN=$(curl -s -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123!"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
```

### Access Protected Resources
```bash
# Get data (any authenticated user)
curl -s http://localhost:8000/data \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

# Admin-only endpoint
curl -s http://localhost:8000/admin \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

# Submit data with validation
curl -s -X POST http://localhost:8000/data \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "test_item", "value": "some data"}' | python3 -m json.tool
```

### Test Security Controls
```bash
# Invalid token
curl -s http://localhost:8000/data \
  -H "Authorization: Bearer invalid.token.here" | python3 -m json.tool

# Rate limiting (run in quick succession)
for i in $(seq 1 8); do
  echo "Request $i:"
  curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/health
  echo
done

# Malformed input (XSS attempt)
curl -s -X POST http://localhost:8000/data \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "<script>alert(1)</script>", "value": "xss"}' | python3 -m json.tool

# Role violation (login as alice, try /admin)
ALICE_TOKEN=$(curl -s -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "user1234"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

curl -s http://localhost:8000/admin \
  -H "Authorization: Bearer $ALICE_TOKEN" | python3 -m json.tool
```

### Attack Simulation
```bash
# Simulate invalid token attacks
curl -s -X POST http://localhost:8000/simulate-attack \
  -H "Content-Type: application/json" \
  -d '{"attack_type": "invalid_token"}' | python3 -m json.tool

# Simulate rate limiting
curl -s -X POST http://localhost:8000/simulate-attack \
  -H "Content-Type: application/json" \
  -d '{"attack_type": "excessive_requests"}' | python3 -m json.tool

# Simulate malformed input
curl -s -X POST http://localhost:8000/simulate-attack \
  -H "Content-Type: application/json" \
  -d '{"attack_type": "malformed_input"}' | python3 -m json.tool
```

## Security Decisions & Tradeoffs

### Authentication
- **bcrypt** for password hashing: adaptive cost factor makes brute-force impractical. Tradeoff: ~100ms per hash vs. nanoseconds for SHA-256, but security is worth the latency on login.
- **HS256 JWT**: symmetric signing is simpler for a single-service gateway. For microservices, switch to **RS256** so services can verify tokens without sharing the secret.
- **Short-lived tokens (30 min)**: limits blast radius if a token leaks. Tradeoff: users must refresh more often.

### Authorization
- **Roles embedded in JWT**: no DB lookup per request. Tradeoff: role changes don't take effect until the token is re-issued.
- **Generic error on login failure**: prevents username enumeration at the cost of slightly less helpful error messages.

### Rate Limiting
- **Sliding window algorithm**: more accurate than fixed windows (no burst at window boundaries). Tradeoff: slightly more memory per key.
- **In-memory store**: zero dependencies, but not shared across workers/processes. For production multi-instance deployments, plug in Redis.
- **Role-based limits**: admins get 20 req/10s, users get 5. Configurable per role.

### Input Validation
- **Pydantic v2 strict models**: type coercion + length limits reject garbage before it reaches business logic.
- **Script tag rejection**: defense-in-depth against stored XSS, even though an API typically doesn't render HTML.

### Logging
- **Structured JSON**: machine-parseable, ready for ELK/Splunk/SIEM ingestion.
- **Security events logged**: failed logins, invalid JWTs, rate limit violations, authorization denials.

### Headers
- Full suite of security headers (HSTS, CSP, X-Frame-Options, etc.) applied to every response, even though this is an API -- defense-in-depth.
