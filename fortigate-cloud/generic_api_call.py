""" Copyright start
  Copyright (C) 2008 - 2026 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from typing import Any

from .make_rest_api_call import MakeRestApiCall
from .models import GenericApiCallParams, parse_params


def generic_api_call(config: dict[str, Any], params: dict[str, Any]) -> Any:
    p = parse_params(GenericApiCallParams, params)
    fgc = MakeRestApiCall(config=config)
    return fgc.make_request(endpoint=p.endpoint, method=p.method, json_data=p.payload)
