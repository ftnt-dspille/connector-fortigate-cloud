""" Copyright start
  Copyright (C) 2008 - 2026 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from connectors.core.connector import ConnectorError, get_logger

from .constants import CONNECTOR_NAME
from .device_actions import (
    add_device,
    add_report_schedule,
    delete_report_schedule,
    get_auto_backup_setting,
    get_device,
    get_devices,
    get_report_schedule,
    get_report_schedules,
    update_auto_backup_setting,
    update_device_management,
)
from .fos_actions import fos_api_call
from .generic_api_call import generic_api_call
from .make_rest_api_call import MakeRestApiCall

logger = get_logger(CONNECTOR_NAME)


def _check_health(config: dict) -> bool:
    """Verify the config can actually reach the FortiGate Cloud device API.

    A successful IAM token grant is not sufficient evidence of health: the token
    endpoint issues a token for any valid FortiCloud identity, but FortiGate Cloud
    rejects it with 401 invalid_client unless that IAM user also holds Admin
    permissions for FortiGate Cloud. Probing /devices is what distinguishes a
    working config from one that can log in but do nothing.
    """
    fgc = MakeRestApiCall(config=config)
    if not fgc.authenticated:
        raise ConnectorError("Failed to authenticate with FortiCloud IAM")
    fgc.make_request(endpoint="/devices", method="GET", params={"limit": 1, "offset": 0})
    return True


operations = {
    "get_devices": get_devices,
    "get_device": get_device,
    "add_device": add_device,
    "update_device_management": update_device_management,
    "get_report_schedules": get_report_schedules,
    "get_report_schedule": get_report_schedule,
    "add_report_schedule": add_report_schedule,
    "delete_report_schedule": delete_report_schedule,
    "get_auto_backup_setting": get_auto_backup_setting,
    "update_auto_backup_setting": update_auto_backup_setting,
    "fos_api_call": fos_api_call,
    "generic_api_call": generic_api_call,
}
