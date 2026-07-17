""" Copyright start
  Copyright (C) 2008 - 2026 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from connectors.core.connector import ConnectorError

from .make_rest_api_call import MakeRestApiCall


def _client(config):
    return MakeRestApiCall(config=config)


def _require(params, name):
    value = params.get(name)
    if value is None or (isinstance(value, str) and not value.strip()):
        raise ConnectorError("'{0}' is a required parameter".format(name))
    return value.strip() if isinstance(value, str) else value


def get_devices(config: dict, params: dict) -> dict:
    query = {}
    for key in ("limit", "offset", "sort"):
        value = params.get(key)
        if value is not None and value != "":
            query[key] = value
    fgc = _client(config)
    return fgc.make_request(endpoint="/devices", method="GET", params=query)


def get_device(config: dict, params: dict) -> dict:
    sn = _require(params, "sn")
    fgc = _client(config)
    return fgc.make_request(endpoint="/devices/{0}".format(sn), method="GET")


def add_device(config: dict, params: dict) -> dict:
    device_key = _require(params, "device_key")
    fgc = _client(config)
    return fgc.make_request(endpoint="/devices", method="POST", json_data={"deviceKey": device_key})


def update_device_management(config: dict, params: dict) -> dict:
    sn = _require(params, "sn")
    management = params.get("management")
    if management is None:
        raise ConnectorError("'management' is a required parameter")

    data = {"management": management}
    # Enabling management requires the FortiGate's own admin credentials;
    # disabling does not, so only forward them when they were supplied.
    for param_name, body_key in (
        ("username", "username"),
        ("password", "password"),
        ("force_password_change", "forcePasswordChange"),
    ):
        value = params.get(param_name)
        if value not in (None, ""):
            data[body_key] = value

    if management and not data.get("password"):
        raise ConnectorError(
            "Enabling management requires the FortiGate 'admin' user password. "
            "Provide the Username and Password parameters."
        )

    fgc = _client(config)
    return fgc.make_request(endpoint="/devices/{0}/management".format(sn), method="PUT", json_data=data)


def get_report_schedules(config: dict, params: dict) -> dict:
    sn = _require(params, "sn")
    fgc = _client(config)
    return fgc.make_request(endpoint="/devices/{0}/reportschedules".format(sn), method="GET")


def get_report_schedule(config: dict, params: dict) -> dict:
    sn = _require(params, "sn")
    oid = _require(params, "oid")
    fgc = _client(config)
    return fgc.make_request(endpoint="/devices/{0}/reportschedules/{1}".format(sn, oid), method="GET")


def add_report_schedule(config: dict, params: dict) -> dict:
    sn = _require(params, "sn")
    data = {"configOid": _require(params, "config_oid")}
    for param_name, body_key in (
        ("oid", "oid"),
        ("schedule_type", "scheduleType"),
        ("vdom", "vdom"),
        ("email", "email"),
        ("email_flag", "emailFlag"),
    ):
        value = params.get(param_name)
        if value not in (None, ""):
            data[body_key] = value
    fgc = _client(config)
    return fgc.make_request(endpoint="/devices/{0}/reportschedules".format(sn), method="POST", json_data=data)


def delete_report_schedule(config: dict, params: dict) -> dict:
    sn = _require(params, "sn")
    oid = _require(params, "oid")
    fgc = _client(config)
    return fgc.make_request(endpoint="/devices/{0}/reportschedules/{1}".format(sn, oid), method="DELETE")


def get_auto_backup_setting(config: dict, params: dict) -> dict:
    sn = _require(params, "sn")
    fgc = _client(config)
    return fgc.make_request(endpoint="/devices/{0}/configbackups/setting".format(sn), method="GET")


def update_auto_backup_setting(config: dict, params: dict) -> dict:
    sn = _require(params, "sn")
    data = {}
    for param_name, body_key in (
        ("enable", "enable"),
        ("backup_option", "backupOption"),
        ("alert", "alert"),
        ("alert_lang", "alertLang"),
        ("alert_emails", "alertEmails"),
    ):
        value = params.get(param_name)
        if value not in (None, ""):
            data[body_key] = value
    fgc = _client(config)
    return fgc.make_request(
        endpoint="/devices/{0}/configbackups/setting".format(sn), method="PUT", json_data=data
    )
