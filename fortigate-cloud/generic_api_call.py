""" Copyright start
  Copyright (C) 2008 - 2026 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from connectors.core.connector import ConnectorError

from .make_rest_api_call import MakeRestApiCall


def generic_api_call(config: dict, params: dict) -> dict:
    method = (params.get("method") or "GET").upper()
    endpoint = params.get("endpoint")
    if not endpoint:
        raise ConnectorError("'endpoint' is a required parameter, for example: /devices")
    if not endpoint.startswith("/"):
        endpoint = "/" + endpoint
    payload = params.get("payload") or None

    fgc = MakeRestApiCall(config=config)
    return fgc.make_request(endpoint=endpoint, method=method, json_data=payload)
