""" Copyright start
  Copyright (C) 2008 - 2026 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

# Curated operations that run FortiOS API calls on a cloud-managed FortiGate
# through the FortiGate Cloud proxy (/fgt/{sn}/...). They exist so playbooks do
# not have to assemble FortiOS paths themselves; every one of them is a thin,
# auditable wrapper over the same proxy the generic Call FortiOS API operation
# uses.
#
# Reads are available on free FortiGate Cloud accounts. Writes (and therefore
# block_ip / unblock_ip) require a paid FortiGate; an unentitled device answers
# 403 {"error": "permission_deny"} before the tunnel is consulted.
#
# Block/unblock safety model: the address object and policies this module
# creates are always named FSR-BLOCK-<ip> (dots replaced with underscores), a
# deny policy matches ONLY the blocked address (the opposite side is "all"),
# so no other traffic path changes. unblock_ip removes exactly those objects
# and refuses to delete the address object while a policy it did not create
# still references it.

import json
import time
from typing import Any, Optional, Union
from urllib.parse import quote

from connectors.core.connector import ConnectorError

from .make_rest_api_call import MakeRestApiCall
from .models import (
    COMMENT_MAX,
    AddressOutcome,
    AddressRead,
    BannedListResult,
    BlockIpParams,
    BlockResult,
    CreateFirewallAddressParams,
    DeleteFirewallAddressParams,
    FirewallPolicy,
    ListBannedParams,
    ListParams,
    PolicyList,
    PolicyOutcome,
    ProxyReply,
    QuarantineParams,
    QuarantineResult,
    RemovedPolicy,
    SnParams,
    UnblockIpParams,
    UnblockResult,
    UnquarantineParams,
    UnquarantineResult,
    parse_banned_entries,
    parse_params,
    parse_reply,
)

# Quarantine Monitor (runtime IP bans): the wire shape the FortiGate v2
# connector proved live - a JSON-encoded body sent with a form-urlencoded
# Content-Type. Bans are runtime state, not config objects: each entry expires
# on its own (expiry 0 means never) and does not survive a reboot unless the
# device's banned-IP persistency is enabled.
_QUARANTINE_FORM_HEADERS = {"Content-Type": "application/x-www-form-urlencoded"}
_DEFAULT_COMMENT = "Created by FortiSOAR fortigate-cloud block_ip"

Config = dict[str, Any]
PolicyId = Union[int, str]


def _client(config: Config) -> MakeRestApiCall:
    return MakeRestApiCall(config=config)


def _proxy_path(sn: str, fos_path: str) -> str:
    # Every path segment built from operation input is URL-quoted so an input
    # like "a/b" or "a?b" cannot change which resource the proxy addresses.
    return "/fgt/{0}/{1}".format(quote(str(sn), safe=""), fos_path)


def _object_path(sn: str, collection: str, key: Any) -> str:
    return _proxy_path(sn, "api/v2/cmdb/firewall/{0}/{1}".format(collection, quote(str(key), safe="")))


def _comment(value: Optional[str]) -> str:
    return (value or _DEFAULT_COMMENT)[:COMMENT_MAX]


# --- curated reads --------------------------------------------------------


def get_fgt_system_status(config: Config, params: Config) -> Any:
    """Read the FortiOS system status of a cloud-managed FortiGate (hostname,
    model, firmware, serial, vdom, resource use) through FortiGate Cloud."""
    p = parse_params(SnParams, params)
    return _client(config).make_request(
        endpoint=_proxy_path(p.sn, "api/v2/monitor/system/status"), method="GET"
    )


def list_firewall_addresses(config: Config, params: Config) -> Any:
    """List firewall address objects on a cloud-managed FortiGate through
    FortiGate Cloud. Supports limit and offset pagination."""
    p = parse_params(ListParams, params)
    return _client(config).make_request(
        endpoint=_proxy_path(p.sn, "api/v2/cmdb/firewall/address"),
        method="GET",
        params=p.query,
    )


def list_firewall_policies(config: Config, params: Config) -> Any:
    """List firewall policies on a cloud-managed FortiGate through FortiGate
    Cloud, in policy order (top of the match order first)."""
    p = parse_params(ListParams, params)
    return _client(config).make_request(
        endpoint=_proxy_path(p.sn, "api/v2/cmdb/firewall/policy"),
        method="GET",
        params=p.query,
    )


# --- curated writes -------------------------------------------------------


def create_firewall_address(config: Config, params: Config) -> Any:
    """Create a firewall address object on a cloud-managed FortiGate through
    FortiGate Cloud. 'ip' accepts a single IPv4 address (a /32 object) or a
    CIDR network."""
    p = parse_params(CreateFirewallAddressParams, params)
    body = {"name": p.name, "type": "ipmask", "subnet": p.subnet}
    if p.comment:
        body["comment"] = p.comment[:COMMENT_MAX]
    return _client(config).make_request(
        endpoint=_proxy_path(p.sn, "api/v2/cmdb/firewall/address"),
        method="POST",
        json_data=body,
    )


def delete_firewall_address(config: Config, params: Config) -> Any:
    """Delete a firewall address object on a cloud-managed FortiGate through
    FortiGate Cloud. The operation fails safely if the object does not exist."""
    p = parse_params(DeleteFirewallAddressParams, params)
    return _client(config).make_request(
        endpoint=_object_path(p.sn, "address", p.name), method="DELETE"
    )


# --- block / unblock flow -------------------------------------------------


def _find_policy(policies: list[FirewallPolicy], name: str) -> Optional[FirewallPolicy]:
    return next((policy for policy in policies if policy.name == name), None)


def _position_of(policies: list[FirewallPolicy], policy_id: PolicyId) -> Optional[int]:
    return next(
        (index for index, p in enumerate(policies) if p.policyid == policy_id),
        None,
    )


# The FortiGate Cloud proxy caches CMDB reads per request identity and can
# serve a view that is minutes old - including one that still shows a policy
# deleted earlier - and it keeps doing so even while the device is unreachable.
# Anything that must reflect the device's real state verifies with a direct
# read of the object itself (a different, uncached request) instead of
# trusting a list.
_NOT_FOUND_MARKERS = ("not_found", "not found")


def _is_not_found(err: Exception) -> bool:
    text = str(err).lower()
    return any(marker in text for marker in _NOT_FOUND_MARKERS)


def _policy_exists(fgc: MakeRestApiCall, sn: str, policy_id: Optional[PolicyId]) -> bool:
    """Direct GET of one policy by id, to confirm a list entry is real."""
    if policy_id is None:
        return False
    try:
        fgc.make_request(endpoint=_object_path(sn, "policy", policy_id), method="GET")
    except ConnectorError as err:
        if _is_not_found(err):
            return False
        raise
    return True


# FortiGate Cloud's proxy can serve policy reads that lag a write by a few
# seconds: a list taken right after a create may omit the new policy, and one
# taken right after a move may still show the old order. Verification that
# must observe a specific state polls instead of trusting the first read.
_LIST_RETRY_ATTEMPTS = 5
_LIST_RETRY_DELAY = 2.0


def _list_policies_waiting(
    fgc: MakeRestApiCall,
    sn: str,
    want_name: Optional[str] = None,
    attempts: Optional[int] = None,
    delay: Optional[float] = None,
) -> list[FirewallPolicy]:
    """List policies, retrying while the proxy's read-after-write view lags.
    With want_name set, retries until that policy appears in the list (or the
    attempts run out). In the common fresh-read case this is a single call."""
    attempts = _LIST_RETRY_ATTEMPTS if attempts is None else attempts
    delay = _LIST_RETRY_DELAY if delay is None else delay
    policies = _list_policies(fgc, sn)
    for _ in range(attempts - 1):
        if want_name is None or _find_policy(policies, want_name) is not None:
            return policies
        time.sleep(delay)
        policies = _list_policies(fgc, sn)
    return policies


def _list_policies(fgc: MakeRestApiCall, sn: str, limit: int = 1000) -> list[FirewallPolicy]:
    body = fgc.make_request(
        endpoint=_proxy_path(sn, "api/v2/cmdb/firewall/policy"),
        method="GET",
        params={"limit": limit},
    )
    return parse_reply(PolicyList, body, "the firewall policy list").results


def _address_exists(fgc: MakeRestApiCall, sn: str, name: str) -> Optional[AddressRead]:
    """Return the address read when it exists, None when it does not. Any
    other failure raises: treating an error as 'absent' could double-create
    or mask a real problem."""
    body = fgc.make_request(
        endpoint=_object_path(sn, "address", name),
        method="GET",
        ok_statuses=(404,),
    )
    what = "firewall address '{0}'".format(name)
    if parse_reply(ProxyReply, body, what).is_not_found:
        return None
    return parse_reply(AddressRead, body, what)


def _ensure_address(
    fgc: MakeRestApiCall, sn: str, name: str, subnet: str, comment: Optional[str]
) -> AddressOutcome:
    existing = _address_exists(fgc, sn, name)
    if existing is not None:
        current = existing.subnet
        if current and current != subnet:
            raise ConnectorError(
                "An address object named '{0}' already exists with subnet '{1}', "
                "which does not match the requested '{2}'. Unblock or rename the "
                "existing object first.".format(name, current, subnet)
            )
        return AddressOutcome(name=name, reused=True)
    body = fgc.make_request(
        endpoint=_proxy_path(sn, "api/v2/cmdb/firewall/address"),
        method="POST",
        json_data={"name": name, "type": "ipmask", "subnet": subnet, "comment": _comment(comment)},
    )
    return AddressOutcome(name=name, reused=False, response=body)


def _deny_policy_body(
    name: str,
    address_name: str,
    direction: str,
    srcintf: list[str],
    dstintf: list[str],
    comment: Optional[str],
) -> dict[str, Any]:
    return {
        "name": name,
        "action": "deny",
        "srcintf": [{"name": n} for n in srcintf],
        "dstintf": [{"name": n} for n in dstintf],
        "srcaddr": [{"name": address_name}] if direction == "inbound" else [{"name": "all"}],
        "dstaddr": [{"name": address_name}] if direction == "outbound" else [{"name": "all"}],
        "schedule": "always",
        "service": [{"name": "ALL"}],
        "logtraffic": "all",
        "status": "enable",
        "comments": _comment(comment),
    }


def _move_to_top(
    fgc: MakeRestApiCall, sn: str, policy_id: PolicyId, policy_name: str
) -> dict[str, Any]:
    """Move a policy above the current top policy so the deny is evaluated
    before any broad accept policy. Uses the FortiOS CMDB move action, then
    verifies with re-lists (the proxy's reads can lag the move) before
    declaring failure."""
    policies = _list_policies_waiting(fgc, sn, want_name=policy_name)
    position = _position_of(policies, policy_id)
    if position == 0:
        return {"moved": False, "position": 0, "top_policy_id": policy_id}
    top_id = policies[0].policyid if policies else None
    if top_id is not None and top_id != policy_id:
        fgc.make_request(
            endpoint=_object_path(sn, "policy", policy_id),
            method="PUT",
            params={"action": "move", "before": top_id},
        )
    for attempt in range(_LIST_RETRY_ATTEMPTS):
        policies = _list_policies_waiting(fgc, sn, want_name=policy_name)
        position = _position_of(policies, policy_id)
        if position == 0:
            return {"moved": True, "position": 0, "top_policy_id": top_id}
        if attempt < _LIST_RETRY_ATTEMPTS - 1:
            time.sleep(_LIST_RETRY_DELAY)
    raise ConnectorError(
        "The deny policy {0} was created but could not be moved to the top of "
        "the policy order; it currently sits at position {1}. It may not take "
        "effect above existing accept policies. Remove it with unblock_ip and "
        "retry, or move it manually.".format(policy_id, position)
    )


def block_ip(config: Config, params: Config) -> dict[str, Any]:
    """Block an IPv4 address or CIDR on a cloud-managed FortiGate through
    FortiGate Cloud: create (or reuse) an FSR-BLOCK-<ip> address object and a
    deny policy that matches only that address, then move the policy to the
    top of the policy order. Traffic to or from other hosts is not affected.
    Idempotent: rerunning block_ip reuses existing objects."""
    p = parse_params(BlockIpParams, params)
    name = p.object_name
    fgc = _client(config)
    address = _ensure_address(fgc, p.sn, name, p.subnet, p.comment)

    policies = _list_policies(fgc, p.sn)
    results: list[PolicyOutcome] = []
    for item in p.directions:
        policy_name = "{0}-{1}".format(name, item.upper())
        existing = _find_policy(policies, policy_name)
        if existing is not None and _policy_exists(fgc, p.sn, existing.policyid):
            results.append(PolicyOutcome(name=policy_name, policyid=existing.policyid, created=False))
            continue
        body = _deny_policy_body(policy_name, name, item, p.srcintf, p.dstintf, p.comment)
        response = fgc.make_request(
            endpoint=_proxy_path(p.sn, "api/v2/cmdb/firewall/policy"),
            method="POST",
            json_data=body,
        )
        created_policy = parse_reply(ProxyReply, response, "the policy create reply").created_id
        if created_policy is None:
            raise ConnectorError(
                "The deny policy '{0}' was created but FortiGate Cloud did not "
                "return its policy id, so it cannot be moved or verified. Remove "
                "it with unblock_ip and retry.".format(policy_name)
            )
        move = _move_to_top(fgc, p.sn, created_policy, policy_name)
        policies = _list_policies(fgc, p.sn)  # refresh order for the next direction
        results.append(PolicyOutcome(
            name=policy_name,
            policyid=created_policy,
            created=True,
            moved_to_top=move.get("moved", False),
            position=move.get("position"),
        ))

    return BlockResult(device=p.sn, ip=p.ip, address=address, policies=results).to_dict()


def _is_block_policy(policy: FirewallPolicy, name: str) -> bool:
    policy_name = policy.name or ""
    return policy_name == name or policy_name.startswith(name + "-")


def unblock_ip(config: Config, params: Config) -> dict[str, Any]:
    """Remove what block_ip created for an IPv4 address or CIDR: delete the
    FSR-BLOCK deny policies, then delete the address object unless a policy
    this connector did not create still references it. Idempotent: objects
    that are already absent are reported, not treated as errors."""
    p = parse_params(UnblockIpParams, params)
    name = p.object_name
    fgc = _client(config)

    removed: list[RemovedPolicy] = []
    for policy in _list_policies(fgc, p.sn):
        if not _is_block_policy(policy, name):
            continue
        policy_name = policy.name or ""
        try:
            fgc.make_request(endpoint=_object_path(p.sn, "policy", policy.policyid), method="DELETE")
            removed.append(RemovedPolicy(name=policy_name, policyid=policy.policyid))
        except ConnectorError as err:
            if not _is_not_found(err):
                raise
            # A stale proxy list can still show a policy deleted earlier;
            # the goal (the policy is gone) already holds.
            removed.append(RemovedPolicy(name=policy_name, policyid=policy.policyid, already_absent=True))

    address_removed = False
    retained_reason: Optional[str] = None
    if _address_exists(fgc, p.sn, name) is not None:
        foreign_refs = []
        for policy in _list_policies(fgc, p.sn):
            if _is_block_policy(policy, name):
                continue
            for field_name, members in (("srcaddr", policy.srcaddr), ("dstaddr", policy.dstaddr)):
                if any(member.name == name for member in members):
                    foreign_refs.append("{0}#{1}".format(policy.name or "", field_name))
        if foreign_refs:
            retained_reason = (
                "The address object is still referenced by: {0}. Delete those "
                "references first.".format(", ".join(foreign_refs))
            )
        else:
            try:
                fgc.make_request(endpoint=_object_path(p.sn, "address", name), method="DELETE")
                address_removed = True
            except ConnectorError as err:
                if not _is_not_found(err):
                    raise
                # The address was already gone (the exists-check read a stale
                # proxy view); cleanup is idempotent, so that is success.

    return UnblockResult(
        device=p.sn,
        ip=p.ip,
        address_name=name,
        removed_policies=removed,
        address_removed=address_removed,
        address_retained_reason=retained_reason,
    ).to_dict()


# --- quarantine (ban-IP) flow ---------------------------------------------
#
# A second containment style alongside the policy flow above: the FortiOS
# Quarantine Monitor bans IPv4 addresses at runtime. One call bans a whole
# batch, no address objects or policies are touched, every entry carries its
# own expiry, and the ban survives neither expiry nor reboot - so a playbook
# that fails to clean up still cannot leave the device blocked permanently.


def _banned_entries(fgc: MakeRestApiCall, sn: str, vdom: str) -> tuple[list[dict[str, Any]], set[str]]:
    """Read the Quarantine Monitor. Returns (entries, banned_ip_set); the
    entries are passed through verbatim so no vendor field is lost."""
    body = fgc.make_request(
        endpoint=_proxy_path(sn, "api/v2/monitor/user/banned/select"),
        method="GET",
        params={"vdom": vdom},
    )
    entries = parse_banned_entries(body)
    banned = {entry.ip_address for entry in entries if entry.ip_address}
    return [entry.model_dump() for entry in entries], banned


def _ban_post(fgc: MakeRestApiCall, sn: str, vdom: str, fos_path: str, body: dict[str, Any]) -> Any:
    return fgc.make_request(
        endpoint=_proxy_path(sn, fos_path),
        method="POST",
        params={"vdom": vdom},
        headers=_QUARANTINE_FORM_HEADERS,
        data=json.dumps(body),
    )


def quarantine_ip(config: Config, params: Config) -> dict[str, Any]:
    """Quarantine (ban) IPv4 addresses on a cloud-managed FortiGate through
    FortiGate Cloud using the Quarantine Monitor: a runtime ban with its own
    expiry that needs no address objects or policies. Idempotent - addresses
    that are already banned are reported, not re-banned. Rerunning is safe;
    leaving the ban in place is also safe, because it expires on its own
    unless 'time_to_live' is 'Never'."""
    p = parse_params(QuarantineParams, params)
    expiry = p.expiry_seconds
    fgc = _client(config)

    _, banned_now = _banned_entries(fgc, p.sn, p.vdom)
    already = [ip for ip in p.ips if ip in banned_now]
    to_ban = [ip for ip in p.ips if ip not in banned_now]

    response = None
    if to_ban:
        response = _ban_post(
            fgc, p.sn, p.vdom, "api/v2/monitor/user/banned/add_users",
            {"ip_addresses": to_ban, "expiry": expiry, "src": "ips"},
        )
        _, banned_now = _banned_entries(fgc, p.sn, p.vdom)

    result = QuarantineResult(
        device=p.sn,
        vdom=p.vdom,
        quarantined=[ip for ip in to_ban if ip in banned_now],
        pending=[ip for ip in to_ban if ip not in banned_now],
        already_quarantined=already,
        expiry_seconds=expiry,
    )
    if response is not None:
        result.response = response
    return result.to_dict()


def unquarantine_ip(config: Config, params: Config) -> dict[str, Any]:
    """Release Quarantine Monitor bans created by quarantine_ip (or the CLI's
    'diagnose user banned-ip add'). Idempotent: addresses that are not banned
    are reported as such instead of erroring."""
    p = parse_params(UnquarantineParams, params)
    fgc = _client(config)

    _, banned_now = _banned_entries(fgc, p.sn, p.vdom)
    to_clear = [ip for ip in p.ips if ip in banned_now]
    not_banned = [ip for ip in p.ips if ip not in banned_now]

    response = None
    if to_clear:
        response = _ban_post(
            fgc, p.sn, p.vdom, "api/v2/monitor/user/banned/clear_users",
            {"ip_addresses": to_clear},
        )
        _, banned_now = _banned_entries(fgc, p.sn, p.vdom)

    result = UnquarantineResult(
        device=p.sn,
        vdom=p.vdom,
        released=[ip for ip in to_clear if ip not in banned_now],
        still_banned=[ip for ip in to_clear if ip in banned_now],
        not_banned=not_banned,
    )
    if response is not None:
        result.response = response
    return result.to_dict()


def list_banned_ips(config: Config, params: Config) -> dict[str, Any]:
    """List the Quarantine Monitor's current IP bans on a cloud-managed
    FortiGate through FortiGate Cloud. Entries are the vendor's own fields
    (ip_address, expiry, created, cause), passed through verbatim."""
    p = parse_params(ListBannedParams, params)
    entries, _ = _banned_entries(_client(config), p.sn, p.vdom)
    return BannedListResult(device=p.sn, vdom=p.vdom, banned=entries, count=len(entries)).to_dict()
