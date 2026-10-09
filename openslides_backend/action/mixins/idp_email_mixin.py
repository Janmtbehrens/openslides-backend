import logging
import os

import requests
from requests import Response

from openslides_backend.shared.exceptions import ActionException

from ..action import Action

logger = logging.getLogger(__name__)


class IDPEmailMixin(Action):
    """
    Provides a mixin for an external Identity Provider concerning email settings
    """

    admin_token_path = "/zitadel/bootstrap/admin.pat"

    external_host = os.getenv("IDP_EXTERNAL_HOST", "localhost:8800")

    idp_route = os.getenv("IDP_URL_INTERNAL", "http://zitadel-api:8080")

    idp_message_route = f"{idp_route}/management/v1/text/message/"
    idp_email_route = f"{idp_route}/admin/v1/email/"

    _idp_admin_access_token = ""
    _idp_email_provider_id = ""

    def _get_admin_key(self) -> str:
        if self._idp_admin_access_token != "":
            return self._idp_admin_access_token

        # Fetch key from admin file
        try:
            with open(self.admin_token_path) as file:
                self._idp_admin_access_token = file.read().replace("\n", "")
                return self._idp_admin_access_token
        except Exception as e:
            raise ActionException(f"Error reading admin pat file: {e}")

    def _get_email_provider(self) -> str:
        if self._idp_email_provider_id != "":
            return self._idp_email_provider_id

        try:
            # Fetch email provider ID from IDP
            response = requests.get(
                self.idp_email_route,
                headers={
                    "Authorization": f"Bearer {self._get_admin_key()}",
                    "Host": f"{self.external_host}",
                },
            )

            if response.status_code != 200:
                self.idp_error(response)

            json_response = response.json()

            if "config" not in json_response or "id" not in json_response["config"]:
                raise ActionException(
                    f"Error fetching email provider id: No id config.id in response: {json_response}"
                )

            return json_response["config"]["id"]
        except Exception as e:
            raise ActionException(f"Error fetching email provider id: {e}")

    def set_email_sender(self, sender: str) -> None:
        try:
            # Change email sender
            response = requests.put(
                self.idp_email_route + "smtp/" + self._get_email_provider(),
                json={"senderAddress": f"{sender}"},
                headers={
                    "Authorization": f"Bearer {self._get_admin_key()}",
                    "Host": f"{self.external_host}",
                },
            )

            if response.status_code != 200:
                self.idp_error(response)
        except Exception as e:
            raise ActionException(f"Error changing email sender: {e}")

    def set_email_reply_address(self, reply_address: str) -> None:
        try:
            # Change email reply address
            response = requests.put(
                self.idp_email_route + "smtp/" + self._get_email_provider(),
                json={"replyToAddress": f"{reply_address}"},
                headers={
                    "Authorization": f"Bearer {self._get_admin_key()}",
                    "Host": f"{self.external_host}",
                },
            )

            if response.status_code != 200:
                self.idp_error(response)
        except Exception as e:
            raise ActionException(f"Error changing email reply address: {e}")

    def set_email_subject(self, subject: str, language: str) -> None:
        if not language:
            language = "de"

        try:
            # Change email subject
            response = requests.put(
                self.idp_message_route + "invite_user/" + language + "/",
                json={"subject": f"{subject}"},
                headers={
                    "Authorization": f"Bearer {self._get_admin_key()}",
                    "Host": f"{self.external_host}",
                },
            )

            if response.status_code != 200:
                self.idp_error(response)
        except Exception as e:
            raise ActionException(f"Error changing email subject user: {e}")

    def set_email_body(self, body: str) -> None:
        try:
            # Change email body
            response = requests.put(
                self.idp_message_route + "invite_user/" + language + "/",
                json={"text": f"{body}"},
                headers={
                    "Authorization": f"Bearer {self._get_admin_key()}",
                    "Host": f"{self.external_host}",
                },
            )

            if response.status_code != 200:
                self.idp_error(response)
        except Exception as e:
            raise ActionException(f"Error changing email body: {e}")

    # Throws a generic error to the client while logging the real issue
    def idp_error(self, from_response: Response) -> None:
        self.logger.error(f"{from_response.status_code} - {from_response.text}")
        raise ActionException(
            "An IDP error occurred. Please contact your administrator"
        )
