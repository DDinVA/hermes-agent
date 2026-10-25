"""Copilot 403 "forbidden" from a server-revoked exchanged JWT triggers one re-exchange (#135645)."""

from unittest.mock import MagicMock, patch

from agent import auxiliary_client as aux
from agent.turn_recovery import _refresh_credentials_after_401
from agent.turn_retry_state import TurnRetryState


def _agent(*, copilot: bool, refresh_ok: bool = True):
    agent = MagicMock()
    agent.api_mode = "chat_completions"
    agent.provider = "copilot" if copilot else "openrouter"
    agent._is_copilot_provider.return_value = copilot
    agent._try_refresh_copilot_client_credentials.return_value = refresh_ok
    return agent


def test_copilot_403_reexchanges_once():
    agent, retry = _agent(copilot=True), TurnRetryState()
    assert _refresh_credentials_after_401(agent, Exception("forbidden"), retry, 403) is True
    agent._try_refresh_copilot_client_credentials.assert_called_once()
    assert retry.copilot_auth_retry_attempted is True
    # A second 403 in the same attempt must not loop: the guard is spent.
    assert _refresh_credentials_after_401(agent, Exception("forbidden"), retry, 403) is False
    agent._try_refresh_copilot_client_credentials.assert_called_once()


def test_copilot_403_failed_refresh_returns_false():
    agent = _agent(copilot=True, refresh_ok=False)
    assert _refresh_credentials_after_401(agent, Exception("forbidden"), TurnRetryState(), 403) is False


def test_copilot_401_still_refreshes():
    agent = _agent(copilot=True)
    assert _refresh_credentials_after_401(agent, Exception("401"), TurnRetryState(), 401) is True
    agent._try_refresh_copilot_client_credentials.assert_called_once()


def test_non_copilot_403_untouched():
    agent = _agent(copilot=False)
    assert _refresh_credentials_after_401(agent, Exception("forbidden"), TurnRetryState(), 403) is False
    agent._try_refresh_copilot_client_credentials.assert_not_called()


class _StatusError(Exception):
    def __init__(self, status_code: int):
        super().__init__(f"Error code: {status_code} - forbidden")
        self.status_code = status_code


def test_aux_revoked_jwt_predicate_is_copilot_403_only():
    e403 = _StatusError(403)
    assert aux._is_copilot_revoked_jwt(e403, "copilot") is True
    assert aux._is_copilot_revoked_jwt(e403, "openrouter") is False
    assert aux._is_copilot_revoked_jwt(_StatusError(401), "copilot") is False


def test_aux_copilot_refresh_evicts_disk_and_memory():
    with patch("hermes_cli.copilot_auth.resolve_copilot_token", return_value=("ghu_x", "env")), \
         patch("hermes_cli.copilot_auth.evict_cached_exchanged_token") as evict, \
         patch("hermes_cli.copilot_auth.exchange_copilot_token") as exchange:
        assert aux._refresh_copilot_credentials() is True
    evict.assert_called_once_with("ghu_x")
    exchange.assert_called_once_with("ghu_x")
