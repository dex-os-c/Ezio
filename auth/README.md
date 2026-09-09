# Auth Module

JWT authentication and token blacklist for Ezio API.

## Components

- `token_blacklist.py` — Redis-backed token revocation for logout and account disable

## Usage

```python
from auth.token_blacklist import revoke_token, is_token_revoked
from api.auth import get_current_user, CurrentUser
```

## Configuration

Set `REDIS_URL` in `.env` to enable the token blacklist:

```
REDIS_URL=redis://localhost:6379/0
```

## Behaviour on Redis availability (deliberate design decision)

This is an intentional tradeoff, not an accident of the implementation:

- **`REDIS_URL` not set** — the blacklist is disabled by design. There is no
  revocation infrastructure; tokens remain valid until their natural 8-hour
  expiry. `is_token_revoked()` returns `False`. This is documented fail-open
  for operators who choose not to run Redis.

- **`REDIS_URL` set but Redis unreachable** — revocation was explicitly opted
  in, so it is treated as a required control and the API **fails closed**:
  `is_token_revoked()` raises `BlacklistUnavailableError` and
  `get_current_user` rejects the request with `503 Service Unavailable` plus
  an operator-facing warning log, rather than silently accepting a
  possibly-revoked token. Enforcement resumes automatically (per-request
  retry) once Redis is reachable again — no restart needed.

**Rationale:** Ezio is a single-operator self-hosted tool with 8-hour
(not short-lived) tokens. Silently honouring revoked tokens during a Redis
outage would make logout / session invalidation unreliable exactly when it
matters, and an attacker could induce an outage to bypass revocation. An
operator who prefers availability over revocation can unset `REDIS_URL` to
return to the fail-open-by-design mode above.