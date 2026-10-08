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
        self.preferred_username = claims.get("preferred_username", "")  # User Name
        self.azp = claims.get("azp", "")  # Client name
        self.exp = claims.get("exp", 0)  # Expirery Date
        self.iss = claims.get("iss", "")  # Issuer URL


class AuthenticationOIDC(AuthenticationService, AuthenticatedService):
    """
    OIDC authentication service
    """

    passwordHasher = PasswordHasher()
    ANONYMOUS_USER = 0
    blocked_session_ids = []

    def __init__(self, env: Environment, logging: LoggingModule) -> None:
        self.logger = logging.getLogger(__name__)
        self.env = env
        self.issuer_url = self.env.IDP_URL_EXTERNAL
        self.headers = {"Content-Type": "application/json"}

    def authenticate(self) -> tuple[int, str | None]:
        self.logger.debug(
            f"Start request to authentication service with the following data: access_token: {self.access_token}"
        )

        # Fetch JWT
        header_value = self.access_token
        if not header_value.startswith("Bearer: "):
            raise AuthenticationException(
                f"Authorization does not contain 'Bearer:', instead {self.access_token}"
            )

        # Convert JWT to Payload
        payload = self._extract_payload(header_value[len("Bearer: ") :])

        if not payload or not payload.sub or not payload.os_id:
            return (0, "")

        if self.is_session_id_blocked(payload.sid):
            self.logger.warning(f"Session ID {payload.sid} is blocked by blocklist")
            return (0, "")

        return (int(payload.os_id), header_value)

    def backchannel_logout(self, encoded_logout_token: str) -> str:
        # Extract Logout Token
        self.logger.debug(f"Backchannel logout triggered")

        # Extract session ID
        try:
            session_id = self._fetch_session_id(encoded_logout_token)

            # Block session ID
            self.block_session_id(session_id)
        except Exception as e:
            raise AuthenticationException(f"Fetching session ID from logout token: {e}")

        return session_id

    def _extract_payload(self, token_string: str) -> IDPPayload:
        claims = self._extract_claims(token_string)

        payload = IDPPayload(claims)

        return payload

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
        if "sid" not in claims or not claims.get("sid"):
            raise AuthenticationException(
                f"Logout token does not contain session ID \n {claims}"
            )

        return claims["sid"]

    def _extract_claims(self, token: str) -> dict[str, Any]:
        try:
            claims = jwt.decode(
                token,
                algorithms=["RS256"],
                options={"verify_aud": False, "verify_signature": False},
            )
        except jwt.exceptions.DecodeError as e:
            raise AuthenticationException(f"Decoding JWT token: {e}")

        return claims

    def hash(self, toHash: str) -> str:
        return self.passwordHasher.hash(toHash)

    def is_equal(self, toHash: str, toCompare: str) -> bool:
        return toHash == toCompare

    def is_anonymous(self, user_id: int) -> bool:
        return user_id == self.ANONYMOUS_USER

    def block_session_id(self, session_id: str):
        self.blocked_session_ids.append(session_id)
        return

    def is_session_id_blocked(self, session_id: str) -> bool:
        return session_id in self.blocked_session_ids

    def clear_all_sessions(self) -> None:
        self.auth_handler.clear_all_sessions(self.access_token)

    def clear_sessions_by_user_id(self, user_id: int) -> None:
        self.auth_handler.clear_sessions_by_user_id(user_id)
