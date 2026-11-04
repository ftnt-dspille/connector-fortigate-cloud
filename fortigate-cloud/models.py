""" Copyright start
  Copyright (C) 2008 - 2026 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

# Typed contracts for the connector, in three layers:
#
#   1. Operation parameter models  - what a playbook may pass to an operation.
#      parse_params() validates them and turns a failure into a ConnectorError
#      worded the way the hand-written checks used to word it.
#   2. Vendor response models      - the shapes FortiGate Cloud / FortiOS return
#      that the orchestrations branch on (policy lists, address reads, write
#      replies, the Quarantine Monitor). Every one allows extra fields, so a new
#      vendor field passes through; a missing or mistyped field the code relies
#      on fails loudly instead of being guessed at.
#   3. Operation result models     - what the curated operations hand back to
#      the playbook. model_dump(exclude_unset=True) keeps the output shape
#      identical to the plain dicts they replace.
#
# The appliance runtime is Python 3.9, and pydantic evaluates annotations at
# runtime, so this module uses Optional/Union and builtin generics, never the
# `X | None` syntax.

import ipaddress
import json
from typing import Annotated, Any, Literal, Optional, TypeVar, Union

from connectors.core.connector import ConnectorError
from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    SecretStr,
    StringConstraints,
    ValidationError,
    field_validator,
    model_validator,
)

BLOCK_PREFIX = "FSR-BLOCK-"
MAX_NAME_LEN = 79  # FortiGate object name limit
MAX_PAGE_SIZE = 1000
COMMENT_MAX = 255

EXPIRY_PRESETS = {
    "1 Hour": 3600,
    "6 Hours": 21600,
    "12 Hours": 43200,
    "1 Day": 86400,
    "1 Week": 604800,
    "1 Month": 2592000,
    "Never": 0,
}

# --- field types -----------------------------------------------------------


def _to_text(value: Any) -> Any:
    """Playbooks hand over numbers where text is meant (serials, ids); accept
    them. None and containers are left for pydantic to reject."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    return value


def _blank_to_none(value: Any) -> Any:
    return None if isinstance(value, str) and not value.strip() else value


# A required, whitespace-trimmed, non-empty string.
NonBlankStr = Annotated[
    str, BeforeValidator(_to_text), StringConstraints(strip_whitespace=True, min_length=1)
]
# A string where a blank counts as "not given".
def _non_blank_id(value: Any) -> Any:
    if value is None or (isinstance(value, str) and not value.strip()):
        raise ValueError("required")
    return value.strip() if isinstance(value, str) else value


# An identifier that is sent to the API exactly as given: a number stays a
# number, a string is trimmed. (Coercing to text would change the wire type.)
IdValue = Annotated[Union[int, str], BeforeValidator(_non_blank_id)]
OptStr = Annotated[Optional[str], BeforeValidator(_blank_to_none), BeforeValidator(_to_text)]
OptInt = Annotated[Optional[int], BeforeValidator(_blank_to_none)]
Method = Literal["GET", "POST", "PUT", "DELETE"]
Direction = Literal["inbound", "outbound", "both"]


# --- parameter models ------------------------------------------------------


class Params(BaseModel):
    """Base for operation parameters. Playbooks pass the whole parameter form,
    so unknown keys are ignored rather than rejected."""

    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True, populate_by_name=True)


M = TypeVar("M", bound=Params)


def _describe(error: Any) -> str:
    field = ".".join(str(part) for part in error["loc"])
    kind = error["type"]
    message: str = error["msg"]
    if kind in ("missing", "string_too_short", "too_short") or error.get("input") is None:
        return "'{0}' is a required parameter".format(field)
    if kind == "int_parsing":
        return "'{0}' must be an integer; got '{1}'".format(field, error.get("input"))
    if kind == "value_error" and message == "Value error, required":
        return "'{0}' is a required parameter".format(field)
    if kind == "value_error":
        # A validator's own ValueError text is already a full sentence.
        return message[len("Value error, "):] if message.startswith("Value error, ") else message
    return "'{0}' is invalid: {1}".format(field, message) if field else message


def parse_params(model: type[M], params: Optional[dict[str, Any]]) -> M:
    """Validate an operation's parameters; raise ConnectorError naming every
    problem instead of a pydantic traceback."""
    try:
        return model.model_validate(params or {})
    except ValidationError as err:
        raise ConnectorError("; ".join(_describe(e) for e in err.errors())) from err


V = TypeVar("V", bound="VendorModel")


def parse_reply(model: type[V], body: Any, what: str) -> V:
    """Validate a vendor response. A body of the wrong shape (an HTML error
    page, a list where an object belongs, a mistyped field the code relies on)
    raises a ConnectorError naming what was being read. It is never papered
    over with an empty default: an unblock that mistakes a garbled policy list
    for 'no policies' would report success while leaving the block in place."""
    if not isinstance(body, dict):
        raise ConnectorError(
            "Unexpected response while reading {0}: expected a JSON object, got {1}: {2}".format(
                what, type(body).__name__, str(body)[:200]
            )
        )
    try:
        return model.model_validate(body)
    except ValidationError as err:
        raise ConnectorError(
            "Unexpected response shape while reading {0}: {1}".format(
                what,
                "; ".join("{0}: {1}".format(".".join(map(str, e["loc"])), e["msg"]) for e in err.errors()),
            )
        ) from err


class ConnectorConfig(BaseModel):
    """The connector configuration form."""

    model_config = ConfigDict(extra="allow")  # FortiSOAR adds connector_info

    region: str = "Global"
    server_url: str = ""
    api_id: Optional[str] = None
    password: Optional[SecretStr] = None
    client_id: str = "fortigatecloud"
    verify_ssl: bool = True

    @field_validator("region", "client_id", mode="before")
    @classmethod
    def _default_when_blank(cls, value: Any, info: Any) -> Any:
        if value is None or (isinstance(value, str) and not value.strip()):
            return "Global" if info.field_name == "region" else "fortigatecloud"
        return value

    @field_validator("server_url", mode="before")
    @classmethod
    def _trim_server_url(cls, value: Any) -> str:
        return (value or "").strip().strip("/")


class SnParams(Params):
    sn: NonBlankStr


class GetDevicesParams(Params):
    limit: OptInt = None
    offset: OptInt = None
    sort: OptStr = None


class AddDeviceParams(Params):
    device_key: NonBlankStr


class UpdateDeviceManagementParams(SnParams):
    management: bool
    username: OptStr = None
    password: OptStr = None
    force_password_change: Optional[bool] = None

    @model_validator(mode="after")
    def _enabling_needs_password(self) -> "UpdateDeviceManagementParams":
        # Enabling management requires the FortiGate's own admin credentials;
        # disabling does not.
        if self.management and not self.password:
            raise ValueError(
                "Enabling management requires the FortiGate 'admin' user password. "
                "Provide the Username and Password parameters."
            )
        return self


class ReportScheduleParams(SnParams):
    oid: IdValue


class AddReportScheduleParams(SnParams):
    config_oid: IdValue
    oid: Optional[IdValue] = None
    schedule_type: OptStr = None
    vdom: OptStr = None
    email: OptStr = None
    email_flag: Optional[bool] = None


class UpdateAutoBackupParams(SnParams):
    enable: Optional[bool] = None
    backup_option: OptStr = None
    alert: Optional[bool] = None
    alert_lang: OptStr = None
    alert_emails: OptStr = None


def _json_value(name: str) -> Any:
    def parse(value: Any) -> Any:
        if isinstance(value, str):
            text = value.strip()
            if not text:
                return None
            try:
                return json.loads(text)
            except ValueError as err:
                raise ValueError("'{0}' must be valid JSON".format(name)) from err
        return value or None

    return parse


class GenericApiCallParams(Params):
    method: Method = "GET"
    endpoint: NonBlankStr
    payload: Optional[Any] = None

    @field_validator("method", mode="before")
    @classmethod
    def _upper_method(cls, value: Any) -> Any:
        return value.strip().upper() if isinstance(value, str) and value.strip() else "GET"

    @field_validator("endpoint", mode="after")
    @classmethod
    def _leading_slash(cls, value: str) -> str:
        return value if value.startswith("/") else "/" + value

    @field_validator("payload", mode="before")
    @classmethod
    def _payload(cls, value: Any) -> Any:
        return _json_value("payload")(value)


class FosApiCallParams(Params):
    sn: NonBlankStr
    method: Method = "GET"
    fos_api_path: NonBlankStr
    query_parameters: dict[str, Any] = Field(default_factory=dict)
    payload: Optional[Any] = None

    @field_validator("method", mode="before")
    @classmethod
    def _upper_method(cls, value: Any) -> Any:
        if value is None or (isinstance(value, str) and not value.strip()):
            return "GET"
        text = str(value).strip().upper()
        if text not in ("GET", "POST", "PUT", "DELETE"):
            raise ValueError("'method' must be one of GET, POST, PUT or DELETE; got '{0}'".format(text))
        return text

    @field_validator("fos_api_path", mode="after")
    @classmethod
    def _no_leading_slash(cls, value: str) -> str:
        return value.lstrip("/")

    @field_validator("query_parameters", mode="before")
    @classmethod
    def _query(cls, value: Any) -> Any:
        if not value:
            return {}
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except ValueError as err:
                raise ValueError(
                    "'query_parameters' must be a JSON object or a key/value dictionary; "
                    "got: {0}".format(value)
                ) from err
            if not isinstance(value, dict):
                raise ValueError(
                    "'query_parameters' must be a JSON object, not a {0}".format(type(value).__name__)
                )
        if not isinstance(value, dict):
            raise ValueError("'query_parameters' must be a JSON object or a key/value dictionary")
        return value

    @field_validator("payload", mode="before")
    @classmethod
    def _payload(cls, value: Any) -> Any:
        return _json_value("payload")(value)


class ListParams(SnParams):
    limit: OptInt = None
    offset: OptInt = None

    @property
    def query(self) -> dict[str, int]:
        """FortiOS paging query: limit defaults to 100 and is capped at the
        page size the proxy allows; offset is sent only when non-zero."""
        query = {"limit": min(self.limit if self.limit is not None else 100, MAX_PAGE_SIZE)}
        if self.offset:
            query["offset"] = self.offset
        return query


def ipv4_network(value: str) -> tuple[str, str]:
    """A single IPv4 address or an IPv4 CIDR -> ("<network> <netmask>", network)."""
    text = value.strip()
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError as err:
        raise ValueError(
            "'ip' must be an IPv4 address or CIDR (for example 203.0.113.10 or "
            "203.0.113.0/24); got '{0}'".format(text)
        ) from err
    if net.version != 4:
        raise ValueError("Only IPv4 is supported for this operation; got '{0}'".format(text))
    return "{0} {1}".format(net.network_address, net.netmask), str(net.network_address)


def block_name(ip_value: str) -> str:
    """The deterministic object name for a blocked target."""
    name = BLOCK_PREFIX + ip_value.strip().replace("/", "-").replace(".", "_")
    if len(name) > MAX_NAME_LEN:
        raise ValueError(
            "The normalized block name for '{0}' exceeds the {1} character FortiGate "
            "object name limit; block a shorter prefix".format(ip_value.strip(), MAX_NAME_LEN)
        )
    return name


class CreateFirewallAddressParams(SnParams):
    name: NonBlankStr
    ip: NonBlankStr
    comment: OptStr = None

    @field_validator("ip")
    @classmethod
    def _valid_ip(cls, value: str) -> str:
        ipv4_network(value)
        return value

    @property
    def subnet(self) -> str:
        return ipv4_network(self.ip)[0]


class DeleteFirewallAddressParams(SnParams):
    name: NonBlankStr


def _interfaces(value: Any) -> Any:
    if value is None or (isinstance(value, str) and not value.strip()):
        return ["any"]
    names = value if isinstance(value, list) else str(value).split(",")
    return [str(part).strip() for part in names if str(part).strip()]


class BlockIpParams(SnParams):
    ip: NonBlankStr
    direction: Direction = "both"
    srcintf: Annotated[list[str], BeforeValidator(_interfaces)] = Field(default_factory=lambda: ["any"])
    dstintf: Annotated[list[str], BeforeValidator(_interfaces)] = Field(default_factory=lambda: ["any"])
    comment: OptStr = None

    @field_validator("ip")
    @classmethod
    def _valid_ip(cls, value: str) -> str:
        ipv4_network(value)
        block_name(value)
        return value

    @field_validator("direction", mode="before")
    @classmethod
    def _direction(cls, value: Any) -> Any:
        text = "both" if value is None or not str(value).strip() else str(value).strip().lower()
        if text not in ("inbound", "outbound", "both"):
            raise ValueError("'direction' must be one of inbound, outbound or both; got '{0}'".format(text))
        return text

    @field_validator("srcintf", "dstintf", mode="after")
    @classmethod
    def _interfaces_not_empty(cls, value: list[str], info: Any) -> list[str]:
        if not value:
            raise ValueError("'{0}' resolved to an empty interface list".format(info.field_name))
        return value

    @property
    def subnet(self) -> str:
        return ipv4_network(self.ip)[0]

    @property
    def object_name(self) -> str:
        return block_name(self.ip)

    @property
    def directions(self) -> list[str]:
        # Deterministic order: inbound, then outbound.
        return ["inbound", "outbound"] if self.direction == "both" else [self.direction]


class UnblockIpParams(SnParams):
    ip: NonBlankStr

    @field_validator("ip")
    @classmethod
    def _valid_name(cls, value: str) -> str:
        block_name(value)
        return value

    @property
    def object_name(self) -> str:
        return block_name(self.ip)


def _vdom(value: Any) -> Any:
    return "root" if value is None or not str(value).strip() else str(value).strip()


Vdom = Annotated[str, BeforeValidator(_vdom)]


def _ban_addresses(value: Any) -> Any:
    if value is None or (isinstance(value, str) and not value.strip()):
        raise ValueError("'ips' is a required parameter")
    raw = value if isinstance(value, list) else str(value).split(",")
    items = [str(item).strip() for item in raw if str(item).strip()]
    if not items:
        raise ValueError("'ips' resolved to an empty address list")
    addresses = []
    for item in items:
        try:
            parsed = ipaddress.ip_address(item)
        except ValueError as err:
            raise ValueError(
                "'ips' must be IPv4 addresses separated by commas; got '{0}'".format(item)
            ) from err
        if parsed.version != 4:
            raise ValueError(
                "Only IPv4 addresses are supported by the Quarantine Monitor; got '{0}'".format(item)
            )
        addresses.append(str(parsed))
    return addresses


BanList = Annotated[list[str], BeforeValidator(_ban_addresses)]


class QuarantineParams(SnParams):
    ips: BanList
    time_to_live: str = "1 Hour"
    duration: OptInt = None
    vdom: Vdom = "root"

    @field_validator("time_to_live", mode="before")
    @classmethod
    def _preset(cls, value: Any) -> Any:
        return "1 Hour" if value is None or not str(value).strip() else str(value).strip()

    @model_validator(mode="after")
    def _expiry_is_resolvable(self) -> "QuarantineParams":
        self.expiry_seconds  # noqa: B018 - raises ValueError when the choice is unusable
        return self

    @property
    def expiry_seconds(self) -> int:
        """The ban duration: a named preset, or 'Custom Time' + duration in
        seconds. Zero means the ban never expires."""
        if self.time_to_live == "Custom Time":
            if self.duration is None:
                raise ValueError("'duration' is required when 'time_to_live' is 'Custom Time'")
            if self.duration < 0:
                raise ValueError(
                    "'duration' must be zero (never expires) or a positive number of "
                    "seconds; got '{0}'".format(self.duration)
                )
            return self.duration
        if self.time_to_live not in EXPIRY_PRESETS:
            raise ValueError(
                "'time_to_live' must be one of {0}, or 'Custom Time' with a 'duration' in "
                "seconds; got '{1}'".format(", ".join(sorted(EXPIRY_PRESETS)), self.time_to_live)
            )
        return EXPIRY_PRESETS[self.time_to_live]


class UnquarantineParams(SnParams):
    ips: BanList
    vdom: Vdom = "root"


class ListBannedParams(SnParams):
    vdom: Vdom = "root"


# --- vendor responses ------------------------------------------------------


class VendorModel(BaseModel):
    """A vendor payload: fields the code relies on are typed, everything else
    passes through untouched."""

    model_config = ConfigDict(extra="allow")


class ProxyReply(VendorModel):
    """The envelope the proxy wraps a FortiOS write in:
    {"mkey": 1, "status": "success", "http_status": 200, ...}."""

    http_status: Optional[int] = None
    status: Optional[str] = None
    error: Optional[str] = None
    mkey: Optional[Union[int, str]] = None
    policyid: Optional[Union[int, str]] = None
    results: Optional[Union[dict[str, Any], list[Any]]] = None

    @property
    def created_id(self) -> Optional[Union[int, str]]:
        """The id of the object a POST created. The proxy reports it as a
        top-level mkey; nested-under-results shapes are tolerated."""
        for candidate in (self.mkey, self.policyid):
            if candidate is not None:
                return candidate
        if isinstance(self.results, dict):
            for key in ("mkey", "policyid"):
                if self.results.get(key) is not None:
                    return self.results[key]  # type: ignore[no-any-return]
        elif isinstance(self.results, list) and self.results:
            first = self.results[0]
            if isinstance(first, dict) and first.get("policyid") is not None:
                return first["policyid"]  # type: ignore[no-any-return]
        return None

    @property
    def is_not_found(self) -> bool:
        return self.http_status == 404 or self.error == "not_found"


class AddressRef(VendorModel):
    name: Optional[str] = None


class FirewallPolicy(VendorModel):
    policyid: Optional[int] = None
    name: Optional[str] = None
    srcaddr: list[AddressRef] = Field(default_factory=list)
    dstaddr: list[AddressRef] = Field(default_factory=list)

    @field_validator("srcaddr", "dstaddr", mode="before")
    @classmethod
    def _none_is_empty(cls, value: Any) -> Any:
        return [] if value is None else value


class PolicyList(VendorModel):
    results: list[FirewallPolicy] = Field(default_factory=list)

    @field_validator("results", mode="before")
    @classmethod
    def _none_is_empty(cls, value: Any) -> Any:
        return [] if value is None else value


class FirewallAddress(VendorModel):
    name: Optional[str] = None
    subnet: Optional[str] = None


class AddressRead(VendorModel):
    """GET of one address object: results is a one-item list (or the object)."""

    results: Optional[Union[list[FirewallAddress], FirewallAddress]] = None

    @property
    def subnet(self) -> Optional[str]:
        found = self.results[0] if isinstance(self.results, list) and self.results else self.results
        return found.subnet if isinstance(found, FirewallAddress) else None


class BannedEntry(VendorModel):
    ip_address: Optional[str] = None


def parse_banned_entries(body: Any) -> list[BannedEntry]:
    """The Quarantine Monitor reply: {"results": [...]} or the list itself, and
    occasionally one level deeper ({"results": {"results": [...]}})."""
    results = body.get("results") if isinstance(body, dict) else body
    if isinstance(results, dict):
        results = results.get("results")
    if not isinstance(results, list):
        return []
    return [parse_reply(BannedEntry, item, "a Quarantine Monitor entry") for item in results]


# --- operation results -----------------------------------------------------


class Result(BaseModel):
    """Base for what an operation returns. Build with explicit fields and
    dump with to_dict(): only the fields that were set appear, which keeps
    the playbook-visible shape identical to the dicts these replaced."""

    model_config = ConfigDict(extra="forbid")

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude_unset=True)


class AddressOutcome(BaseModel):
    name: str
    reused: bool
    response: Optional[Any] = None


class PolicyOutcome(BaseModel):
    name: str
    policyid: Optional[Union[int, str]] = None
    created: bool
    moved_to_top: Optional[bool] = None
    position: Optional[int] = None


class BlockResult(Result):
    device: str
    ip: str
    address: AddressOutcome
    policies: list[PolicyOutcome]


class RemovedPolicy(BaseModel):
    name: str
    policyid: Optional[int] = None
    already_absent: Optional[bool] = None


class UnblockResult(Result):
    device: str
    ip: str
    address_name: str
    removed_policies: list[RemovedPolicy]
    address_removed: bool
    address_retained_reason: Optional[str] = None


class QuarantineResult(Result):
    device: str
    vdom: str
    quarantined: list[str]
    pending: list[str]
    already_quarantined: list[str]
    expiry_seconds: int
    response: Optional[Any] = None


class UnquarantineResult(Result):
    device: str
    vdom: str
    released: list[str]
    still_banned: list[str]
    not_banned: list[str]
    response: Optional[Any] = None


class BannedListResult(Result):
    device: str
    vdom: str
    banned: list[dict[str, Any]]
    count: int


# Every operation's parameter model, so tooling (and the test that keeps
# info.json and the code in step) can see the contract in one place.
OPERATION_PARAMS: dict[str, type[Params]] = {
    "get_devices": GetDevicesParams,
    "get_device": SnParams,
    "add_device": AddDeviceParams,
    "update_device_management": UpdateDeviceManagementParams,
    "get_report_schedules": SnParams,
    "get_report_schedule": ReportScheduleParams,
    "add_report_schedule": AddReportScheduleParams,
    "delete_report_schedule": ReportScheduleParams,
    "get_auto_backup_setting": SnParams,
    "update_auto_backup_setting": UpdateAutoBackupParams,
    "fos_api_call": FosApiCallParams,
    "generic_api_call": GenericApiCallParams,
    "get_fgt_system_status": SnParams,
    "list_firewall_addresses": ListParams,
    "list_firewall_policies": ListParams,
    "create_firewall_address": CreateFirewallAddressParams,
    "delete_firewall_address": DeleteFirewallAddressParams,
    "block_ip": BlockIpParams,
    "unblock_ip": UnblockIpParams,
    "quarantine_ip": QuarantineParams,
    "unquarantine_ip": UnquarantineParams,
    "list_banned_ips": ListBannedParams,
}
