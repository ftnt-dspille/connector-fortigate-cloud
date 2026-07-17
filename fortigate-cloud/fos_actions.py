""" Copyright start
  Copyright (C) 2008 - 2026 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import json

from connectors.core.connector import ConnectorError

from .make_rest_api_call import MakeRestApiCall


def _parse_query_parameters(value):
    if not value:
        return {}
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except ValueError:
            raise ConnectorError(
                "'query_parameters' must be a JSON object or a key/value dictionary; got: {0}".format(value)
            )
        if not isinstance(parsed, dict):
            raise ConnectorError(
                "'query_parameters' must be a JSON object, not a {0}".format(type(parsed).__name__)
            )
        return parsed
    raise ConnectorError("'query_parameters' must be a JSON object or a key/value dictionary")


def fos_api_call(config: dict, params: dict) -> dict:
    """Proxy any FortiOS API call to a managed FortiGate through FortiGate Cloud.

    Requires the FortiGate to be deployed to FortiGate Cloud with configuration
    management enabled and its management tunnel online. Only GET is available on
    free FortiGate Cloud accounts; POST, PUT and DELETE require a paid FortiGate.
    """
    sn = params.get("sn")
    if not sn or not str(sn).strip():
        raise ConnectorError("'sn' is a required parameter")
    sn = str(sn).strip()

    method = (params.get("method") or "GET").upper()
    if method not in ("GET", "POST", "PUT", "DELETE"):
        raise ConnectorError("'method' must be one of GET, POST, PUT or DELETE; got '{0}'".format(method))

    fos_path = params.get("fos_api_path")
    if not fos_path or not str(fos_path).strip():
        raise ConnectorError(
            "'fos_api_path' is a required parameter, for example: api/v2/monitor/license/status"
        )
    fos_path = str(fos_path).strip().lstrip("/")

    query = _parse_query_parameters(params.get("query_parameters"))
    payload = params.get("payload") or None
    if isinstance(payload, str):
        payload = payload.strip()
        if payload:
            try:
                payload = json.loads(payload)
            except ValueError:
                raise ConnectorError("'payload' must be valid JSON")
        else:
            payload = None

    fgc = MakeRestApiCall(config=config)
    return fgc.make_request(
        endpoint="/fgt/{0}/{1}".format(sn, fos_path),
        method=method,
        params=query,
        json_data=payload,
    )
