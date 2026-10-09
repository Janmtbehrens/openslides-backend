from typing import Any

import jwt
from argon2 import PasswordHasher

from ...shared.env import Environment
from ...shared.exceptions import AuthenticationException
from ...shared.interfaces.logging import LoggingModule
from ..shared.authenticated_service import AuthenticatedService
from .interface import AuthenticationService


class IDPPayload:
    def __init__(self, claims: dict):
        self.sub = claims.get("sub", "")  # User ID
        self.sid = claims.get("sid", "")  # Session ID
        self.os_id = claims.get("os_id", "")  # OS User ID


class AuthenticationOIDC(AuthenticationService, AuthenticatedService):
    """
    OIDC authentication service
    """

    password_hasher = PasswordHasher()
    ANONYMOUS_USER = 0
    blocked_session_ids = []

    client_id_path = "/zitadel/bootstrap/client-id"
    _idp_client_id = ""

    def __init__(self, env: Environment, logging: LoggingModule) -> None:
        self.logger = logging.getLogger(__name__)
        self.env = env
        self.issuer_url = self.env.IDP_URL_EXTERNAL

    def _get_client_id(self) -> str:
        if self._idp_client_id != "":
            return self._idp_client_id

        # Fetch key from client id file
        try:
            with open(self.client_id_path) as file:
                self._idp_client_id = file.read().replace("\n", "")
                return self._idp_client_id
        except Exception as e:
            raise AuthenticationException(f"Error reading client id file: {e}")

    def authenticate(self) -> tuple[int, str | None]:
        self.logger.debug("Authentication request received")

        # Fetch JWT
        header_value = self.access_token
        if not header_value.startswith("Bearer: "):
            raise AuthenticationException("Authorization does not contain 'Bearer:'")

        # Convert JWT to Payload
        token_string = header_value[len("Bearer: ") :]
        payload = IDPPayload(self._extract_claims(token_string))

        if not payload.sub or not payload.os_id:
            return (0, "")

        if self.is_session_id_blocked(payload.sid):
            self.logger.warning(f"Session ID {payload.sid} is blocked by blocklist")
            return (0, "")

        return (int(payload.os_id), header_value)

    def backchannel_logout(self, encoded_logout_token: str) -> str:
        # Extract Logout Token
        self.logger.debug("Backchannel logout triggered")

        # Extract session ID
        try:
            session_id = self._fetch_session_id(encoded_logout_token)

            # Block session ID
            self.block_session_id(session_id)
        except Exception as e:
            raise AuthenticationException(f"Fetching session ID from logout token: {e}")

        return session_id

    def _fetch_session_id(self, logout_token: str) -> str:
        claims = self._extract_claims(logout_token)

        # Required per OIDC backchannel logout: events must include the backchannel logout event
        backchannel_event_key = "http://schemas.openid.net/event/backchannel-logout"
        events = claims.get("events")
        if not isinstance(events, dict) or backchannel_event_key not in events:
            raise AuthenticationException(
                "Token is not a valid backchannel logout token (missing events)"
            )

        # Validate issuer
        if claims.get("iss") != self.issuer_url:
            raise AuthenticationException(
                f"Invalid issuer: got {claims.get('iss')}, want {self.issuer_url}"
            )

        # Extract session ID
        if not claims.get("sid"):
            raise AuthenticationException("Logout token does not contain session ID")
        elif not isinstance(claims.get("sid"), str):
            raise AuthenticationException("Logout token has no valid session ID")

        return claims["sid"]

    def _extract_claims(self, token: str) -> dict[str, Any]:
        try:
            claims = jwt.decode(
                token,
                algorithms=["RS256"],
                audience=self._get_client_id(),
                options={"verify_aud": True, "verify_signature": False},
            )
        except jwt.exceptions.DecodeError as e:
            raise AuthenticationException(f"Decoding JWT token: {e}")
        except jwt.exceptions.InvalidAudienceError as e:
            raise AuthenticationException(f"Audience check on JWT token: {e}")

        return claims

    def hash(self, to_hash: str) -> str:
        return self.password_hasher.hash(to_hash)

    def is_equal(self, to_hash: str, to_compare: str) -> bool:
        return to_hash == to_compare

    def is_anonymous(self, user_id: int) -> bool:
        return user_id == self.ANONYMOUS_USER

    def block_session_id(self, session_id: str) -> None:
        self.blocked_session_ids.append(session_id)

    def is_session_id_blocked(self, session_id: str) -> bool:
        return session_id in self.blocked_session_ids

    def clear_all_sessions(self) -> None:
        self.auth_handler.clear_all_sessions(self.access_token)

    def clear_sessions_by_user_id(self, user_id: int) -> None:
        self.auth_handler.clear_sessions_by_user_id(user_id)
