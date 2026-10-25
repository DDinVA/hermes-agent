"""Copilot credential recovery for auxiliary calls.

Copilot answers a server-revoked exchanged IDE JWT with a bare ``403 forbidden`` (#135645),
not the ``401 IDE token expired`` the generic auth ladder keys on, and the revoked JWT stays
cached (memory and disk) until its stored ``expires_at`` lapses hours later.
"""

from typing import Optional


def _is_copilot_revoked_jwt(exc: Exception, provider: Optional[str]) -> bool:
    """Copilot 403: refreshable, unlike other providers' 403s, so it earns the same one-shot
    re-exchange as a 401. ``provider`` is the already-normalized auth-refresh provider."""
    return provider == "copilot" and getattr(exc, "status_code", None) == 403


def _refresh_copilot_credentials() -> bool:
    from hermes_cli.copilot_auth import evict_cached_exchanged_token, exchange_copilot_token, resolve_copilot_token

    raw_token, _source = resolve_copilot_token()
    if not str(raw_token or "").strip():
        return False
    # Evict memory AND disk: popping only the in-process cache let the exchange's disk
    # fast-path hand back the same revoked JWT.
    evict_cached_exchanged_token(raw_token)
    exchange_copilot_token(raw_token)
    return True
