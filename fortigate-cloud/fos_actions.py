""" Copyright start
  Copyright (C) 2008 - 2026 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from typing import Any

from .make_rest_api_call import MakeRestApiCall
from .models import FosApiCallParams, parse_params


def fos_api_call(config: dict[str, Any], params: dict[str, Any]) -> Any:
    """Proxy any FortiOS API call to a managed FortiGate through FortiGate Cloud.

    Requires the FortiGate to be deployed to FortiGate Cloud with configuration
    management enabled and its management tunnel online. Only GET is available on
    free FortiGate Cloud accounts; POST, PUT and DELETE require a paid FortiGate.
    """
    p = parse_params(FosApiCallParams, params)
    fgc = MakeRestApiCall(config=config)
    return fgc.make_request(
        endpoint="/fgt/{0}/{1}".format(p.sn, p.fos_api_path),
        method=p.method,
        params=p.query_parameters,
        json_data=p.payload,
    )
