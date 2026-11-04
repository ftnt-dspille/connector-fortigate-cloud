""" Copyright start
  Copyright (C) 2008 - 2026 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from typing import Any, Callable

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
    list_firmware_upgrades,
    update_auto_backup_setting,
    update_device_management,
)
from .fgt_proxy_actions import (
    block_ip,
    create_firewall_address,
    delete_firewall_address,
    get_fgt_system_status,
    list_banned_ips,
    list_firewall_addresses,
    list_firewall_policies,
    quarantine_ip,
    unblock_ip,
    unquarantine_ip,
)
from .fos_actions import fos_api_call
from .generic_api_call import generic_api_call
from .make_rest_api_call import MakeRestApiCall
from .script_actions import (
    create_script,
    delete_script,
    get_script_task_output,
    list_script_tasks,
    list_scripts,
    run_script,
)

logger = get_logger(CONNECTOR_NAME)


def _check_health(config: dict[str, Any]) -> bool:
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


Operation = Callable[[dict[str, Any], dict[str, Any]], Any]

operations: dict[str, Operation] = {
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
    "get_fgt_system_status": get_fgt_system_status,
    "list_firewall_addresses": list_firewall_addresses,
    "list_firewall_policies": list_firewall_policies,
    "create_firewall_address": create_firewall_address,
    "delete_firewall_address": delete_firewall_address,
    "block_ip": block_ip,
    "unblock_ip": unblock_ip,
    "quarantine_ip": quarantine_ip,
    "unquarantine_ip": unquarantine_ip,
    "list_banned_ips": list_banned_ips,
    "list_scripts": list_scripts,
    "create_script": create_script,
    "delete_script": delete_script,
    "run_script": run_script,
    "list_script_tasks": list_script_tasks,
    "get_script_task_output": get_script_task_output,
    "list_firmware_upgrades": list_firmware_upgrades,
}
