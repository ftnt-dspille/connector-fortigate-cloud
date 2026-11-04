""" Copyright start
  Copyright (C) 2008 - 2026 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from typing import Any

from .make_rest_api_call import MakeRestApiCall
from .models import (
    AddDeviceParams,
    AddReportScheduleParams,
    GetDevicesParams,
    ReportScheduleParams,
    SnParams,
    UpdateAutoBackupParams,
    UpdateDeviceManagementParams,
    parse_params,
)


def _client(config: dict[str, Any]) -> MakeRestApiCall:
    return MakeRestApiCall(config=config)


def _body(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Request body from (wire key, value) pairs, leaving out unset values."""
    return {key: value for key, value in pairs if value not in (None, "")}


def get_devices(config: dict[str, Any], params: dict[str, Any]) -> Any:
    p = parse_params(GetDevicesParams, params)
    query = _body([("limit", p.limit), ("offset", p.offset), ("sort", p.sort)])
    return _client(config).make_request(endpoint="/devices", method="GET", params=query)


def get_device(config: dict[str, Any], params: dict[str, Any]) -> Any:
    p = parse_params(SnParams, params)
    return _client(config).make_request(endpoint="/devices/{0}".format(p.sn), method="GET")


def add_device(config: dict[str, Any], params: dict[str, Any]) -> Any:
    p = parse_params(AddDeviceParams, params)
    return _client(config).make_request(
        endpoint="/devices", method="POST", json_data={"deviceKey": p.device_key}
    )


def update_device_management(config: dict[str, Any], params: dict[str, Any]) -> Any:
    p = parse_params(UpdateDeviceManagementParams, params)
    data: dict[str, Any] = {"management": p.management}
    # Enabling management requires the FortiGate's own admin credentials;
    # disabling does not, so only forward them when they were supplied.
    data.update(_body([
        ("username", p.username),
        ("password", p.password),
        ("forcePasswordChange", p.force_password_change),
    ]))
    return _client(config).make_request(
        endpoint="/devices/{0}/management".format(p.sn), method="PUT", json_data=data
    )


def get_report_schedules(config: dict[str, Any], params: dict[str, Any]) -> Any:
    p = parse_params(SnParams, params)
    return _client(config).make_request(
        endpoint="/devices/{0}/reportschedules".format(p.sn), method="GET"
    )


def get_report_schedule(config: dict[str, Any], params: dict[str, Any]) -> Any:
    p = parse_params(ReportScheduleParams, params)
    return _client(config).make_request(
        endpoint="/devices/{0}/reportschedules/{1}".format(p.sn, p.oid), method="GET"
    )


def add_report_schedule(config: dict[str, Any], params: dict[str, Any]) -> Any:
    p = parse_params(AddReportScheduleParams, params)
    data: dict[str, Any] = {"configOid": p.config_oid}
    data.update(_body([
        ("oid", p.oid),
        ("scheduleType", p.schedule_type),
        ("vdom", p.vdom),
        ("email", p.email),
        ("emailFlag", p.email_flag),
    ]))
    return _client(config).make_request(
        endpoint="/devices/{0}/reportschedules".format(p.sn), method="POST", json_data=data
    )


def delete_report_schedule(config: dict[str, Any], params: dict[str, Any]) -> Any:
    p = parse_params(ReportScheduleParams, params)
    return _client(config).make_request(
        endpoint="/devices/{0}/reportschedules/{1}".format(p.sn, p.oid), method="DELETE"
    )


def get_auto_backup_setting(config: dict[str, Any], params: dict[str, Any]) -> Any:
    p = parse_params(SnParams, params)
    return _client(config).make_request(
        endpoint="/devices/{0}/configbackups/setting".format(p.sn), method="GET"
    )


def update_auto_backup_setting(config: dict[str, Any], params: dict[str, Any]) -> Any:
    p = parse_params(UpdateAutoBackupParams, params)
    data = _body([
        ("enable", p.enable),
        ("backupOption", p.backup_option),
        ("alert", p.alert),
        ("alertLang", p.alert_lang),
        ("alertEmails", p.alert_emails),
    ])
    return _client(config).make_request(
        endpoint="/devices/{0}/configbackups/setting".format(p.sn), method="PUT", json_data=data
    )
