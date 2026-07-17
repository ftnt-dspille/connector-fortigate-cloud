""" Copyright start
  Copyright (C) 2008 - 2026 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import time
from typing import Any

import requests
from connectors.core.connector import ConnectorError, get_logger

from .constants import API_BASE_PATH, CONNECTOR_NAME, ERROR_MESSAGES, REGION_URLS, TOKEN_URL

logger = get_logger(CONNECTOR_NAME)

# Tokens are cached per (api_id, client_id, region) across operations. FortiCloud
# throttles repeated password grants with an invalid_grant lockout that applies to
# every client_id on the account and self-clears only after 15-30 minutes, so a
# per-call login would take the whole account down under playbook load.
_TOKEN_CACHE: dict[tuple[str, str, str], dict[str, Any]] = {}
_TOKEN_EXPIRY_BUFFER = 300


class MakeRestApiCall:

    def __init__(self, config):
        region = config.get("region") or "Global"
        server_url = (config.get("server_url") or "").strip().strip("/")
        if server_url:
            # An explicit Server URL overrides the region picker, so that a new
            # regional host can be used before this connector ships support for it.
            if not server_url.startswith(("http://", "https://")):
                server_url = "https://{0}".format(server_url)
            base = server_url
        else:
            base = REGION_URLS.get(region)
            if not base:
                raise ConnectorError(
                    "Unknown region '{0}'. Expected one of: {1}".format(
                        region, ", ".join(REGION_URLS)
                    )
                )
        self.server_url = base + API_BASE_PATH
        self.api_id = config.get("api_id")
        self.password = config.get("password")
        self.client_id = config.get("client_id") or "fortigatecloud"
        self.verify_ssl = config.get("verify_ssl", True)
        self.authenticated = False
        self.headers = {}
        self.login()

    def _cache_key(self):
        return (self.api_id, self.client_id, self.server_url)

    def login(self):
        key = self._cache_key()
        cached = _TOKEN_CACHE.get(key)
        if cached and cached["expires_at"] - _TOKEN_EXPIRY_BUFFER > time.time():
            self.headers = {"Authorization": "Bearer {0}".format(cached["access_token"])}
            self.authenticated = True
            return

        data = {
            "username": self.api_id,
            "password": self.password,
            "client_id": self.client_id,
            "grant_type": "password",
        }
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
            body = response.json()
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

        token = body.get("access_token")
        if not token:
            raise ConnectorError("Token endpoint returned success without an access_token: {0}".format(body))

        _TOKEN_CACHE[key] = {
            "access_token": token,
            "expires_at": time.time() + body.get("expires_in", 3600),
        }
        self.headers = {"Authorization": "Bearer {0}".format(token)}
        self.authenticated = True

    def make_request(self, endpoint="", params=None, method="GET", headers=None, json_data=None):
        url = self.server_url + endpoint
        request_headers = {"Content-Type": "application/json"}
        request_headers.update(headers or self.headers)
        try:
            response = requests.request(
                method=method,
                url=url,
                headers=request_headers,
                json=json_data,
                params=params,
                verify=self.verify_ssl,
                timeout=60,
            )
            if response.ok:
                if "json" in response.headers.get("Content-Type", ""):
                    return response.json()
                return response.text
            try:
                detail = response.json()
            except ValueError:
                detail = response.text
            logger.error("Error: %s", detail)
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
