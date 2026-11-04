""" Copyright start
  Copyright (C) 2008 - 2026 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import time
from typing import Any, Optional

import requests
from connectors.core.connector import ConnectorError, get_logger

from .constants import API_BASE_PATH, CONNECTOR_NAME, ERROR_MESSAGES, REGION_URLS, TOKEN_URL
from .models import ConnectorConfig

logger = get_logger(CONNECTOR_NAME)

# Tokens are cached per (api_id, client_id, region) across operations. FortiCloud
# throttles repeated password grants with an invalid_grant lockout that applies to
# every client_id on the account and self-clears only after 15-30 minutes, so a
# per-call login would take the whole account down under playbook load.
_TOKEN_CACHE: dict[tuple[Optional[str], str, str], dict[str, Any]] = {}
_TOKEN_EXPIRY_BUFFER = 300


class MakeRestApiCall:

    def __init__(self, config: dict[str, Any]) -> None:
        cfg = ConnectorConfig.model_validate(config)
        region = cfg.region
        server_url = cfg.server_url
        if server_url:
            # An explicit Server URL overrides the region picker, so that a new
            # regional host can be used before this connector ships support for it.
            if not server_url.startswith(("http://", "https://")):
                server_url = "https://{0}".format(server_url)
            base = server_url
        elif region == "Custom":
            raise ConnectorError(
                "'Server URL' is required when 'Region' is Custom: enter the "
                "FortiGate Cloud API host, for example "
                "https://api.fortigate.forticloud.com"
            )
        else:
            base = REGION_URLS.get(region, "")
            if not base:
                raise ConnectorError(
                    "Unknown region '{0}'. Expected one of: {1}".format(
                        region, ", ".join(list(REGION_URLS) + ["Custom"])
                    )
                )
        self.server_url = base + API_BASE_PATH
        self.api_id = cfg.api_id
        self.password = cfg.password.get_secret_value() if cfg.password else None
        self.client_id = cfg.client_id
        self.verify_ssl = cfg.verify_ssl
        self.authenticated = False
        self.headers: dict[str, str] = {}
        self.login()

    def _cache_key(self) -> tuple[Optional[str], str, str]:
        return (self.api_id, self.client_id, self.server_url)

    def _post_token(self, data: dict[str, Any]) -> dict[str, Any]:
        """POST one grant to the FortiCloud IAM token endpoint; return the
        validated response body (access_token presence is verified here)."""
        try:
            response = requests.post(
                TOKEN_URL,
                json=data,
                headers={"Content-Type": "application/json"},
                verify=self.verify_ssl,
                timeout=60,
            )
        except requests.exceptions.SSLError as err:
            raise ConnectorError(ERROR_MESSAGES["ssl_error"]) from err
        except requests.exceptions.ConnectionError as err:
            raise ConnectorError(ERROR_MESSAGES["time_out"]) from err

        try:
            body: dict[str, Any] = response.json()
        except ValueError:
            raise ConnectorError(
                "Unexpected non-JSON response from the FortiCloud IAM token "
                "endpoint: HTTP {0} {1}".format(response.status_code, response.text[:200])
            )

        if not response.ok or body.get("status") != "success":
            if body.get("error") == "invalid_grant":
                raise ConnectorError(
                    "FortiCloud IAM rejected the credentials with 'invalid_grant'. "
                    "Repeated failed authentication locks out every client_id on the "
                    "account for 15-30 minutes. Verify the API ID and password before "
                    "retrying. Details: {0}".format(body)
                )
            raise ConnectorError("Failed to acquire token: {0}".format(body))

        if not body.get("access_token"):
            raise ConnectorError(
                "Token endpoint returned success without an access_token: {0}".format(body)
            )
        return body

    def login(self) -> None:
        key = self._cache_key()
        cached = _TOKEN_CACHE.get(key)
        if cached and cached["expires_at"] - _TOKEN_EXPIRY_BUFFER > time.time():
            self.headers = {"Authorization": "Bearer {0}".format(cached["access_token"])}
            self.authenticated = True
            return

        # The IAM endpoint issues a refresh_token alongside every grant. A
        # refresh grant carries no account password, so renewing with it avoids
        # the invalid_grant lockout that repeated password grants can trigger.
        # A failed refresh (expired or revoked) falls back to the password
        # grant, which remains the only path on the first login of a process.
        refresh_token = (cached or {}).get("refresh_token")
        body = None
        if refresh_token:
            try:
                body = self._post_token({
                    "client_id": self.client_id,
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                })
            except ConnectorError as err:
                logger.warning(
                    "The refresh_token grant was rejected ({0}); falling back to "
                    "a password grant".format(str(err)[:160])
                )
        if body is None:
            body = self._post_token({
                "username": self.api_id,
                "password": self.password,
                "client_id": self.client_id,
                "grant_type": "password",
            })

        _TOKEN_CACHE[key] = {
            "access_token": body["access_token"],
            # A refresh response may rotate the refresh token; keep the old one
            # as a fallback when it does not.
            "refresh_token": body.get("refresh_token") or refresh_token,
            "expires_at": time.time() + body.get("expires_in", 3600),
        }
        self.headers = {"Authorization": "Bearer {0}".format(body["access_token"])}
        self.authenticated = True

    def make_request(
        self,
        endpoint: str = "",
        params: Optional[dict[str, Any]] = None,
        method: str = "GET",
        headers: Optional[dict[str, str]] = None,
        json_data: Any = None,
        data: Optional[str] = None,
        ok_statuses: Optional[tuple[int, ...]] = None,
    ) -> Any:
        """Issue one FortiGate Cloud API call.

        headers: per-call header overrides merged over the authenticated
        defaults, so a caller can change Content-Type without losing the
        Authorization header.

        json_data: JSON-encoded body (Content-Type: application/json).
        data: pre-encoded body sent verbatim; combined with a form-urlencoded
        Content-Type override this reproduces the request shape the FortiGate
        v2 connector proved live for the Quarantine Monitor ban endpoints
        (JSON body, form content-type).

        ok_statuses: optional tuple of additional HTTP status codes to treat as
        success (returning the parsed body) instead of raising ConnectorError.
        Orchestration operations use this to probe for a resource with a clean
        404 answer instead of parsing exception text.
        """
        url = self.server_url + endpoint
        request_headers = {"Content-Type": "application/json"}
        request_headers.update(self.headers)
        request_headers.update(headers or {})
        try:
            response = requests.request(
                method=method,
                url=url,
                headers=request_headers,
                json=json_data,
                data=data,
                params=params,
                verify=self.verify_ssl,
                timeout=60,
            )
            if response.ok or (ok_statuses and response.status_code in ok_statuses):
                if "json" in response.headers.get("Content-Type", ""):
                    return response.json()
                return response.text
            try:
                detail = response.json()
            except ValueError:
                detail = response.text
            logger.error("Error: %s", detail)
            if response.status_code == 401:
                # The cached token was rejected (revoked or rotated out from
                # under this process); drop it so the next call re-authenticates
                # instead of retrying the same dead token for the rest of the
                # process lifetime.
                _TOKEN_CACHE.pop(self._cache_key(), None)
            raise ConnectorError(
                "{0}. Details: {1}".format(
                    ERROR_MESSAGES.get(response.status_code, "HTTP {0}".format(response.status_code)),
                    detail,
                )
            )
        except requests.exceptions.SSLError as err:
            raise ConnectorError(ERROR_MESSAGES["ssl_error"]) from err
        except requests.exceptions.ConnectionError as err:
            raise ConnectorError(ERROR_MESSAGES["time_out"]) from err
