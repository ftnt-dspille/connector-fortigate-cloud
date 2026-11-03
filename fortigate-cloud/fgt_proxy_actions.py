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

import ipaddress
import json
import time
from urllib.parse import quote

from connectors.core.connector import ConnectorError

from .make_rest_api_call import MakeRestApiCall

_BLOCK_PREFIX = "FSR-BLOCK-"
_MAX_NAME_LEN = 79  # FortiGate object name limit

# Quarantine Monitor (runtime IP bans): the wire shape the FortiGate v2
# connector proved live — a JSON-encoded body sent with a form-urlencoded
# Content-Type. Bans are runtime state, not config objects: each entry expires
# on its own (expiry 0 means never) and does not survive a reboot unless the
# device's banned-IP persistency is enabled.
_QUARANTINE_FORM_HEADERS = {"Content-Type": "application/x-www-form-urlencoded"}
_EXPIRY_PRESETS = {
    "1 Hour": 3600,
    "6 Hours": 21600,
    "12 Hours": 43200,
    "1 Day": 86400,
    "1 Week": 604800,
    "1 Month": 2592000,
    "Never": 0,
}


def _client(config):
    return MakeRestApiCall(config=config)


def _require(params, name):
    value = params.get(name)
    if value is None or (isinstance(value, str) and not value.strip()):
        raise ConnectorError("'{0}' is a required parameter".format(name))
    return value.strip() if isinstance(value, str) else value


def _proxy_path(sn, fos_path):
    # Every path segment built from operation input is URL-quoted so an input
    # like "a/b" or "a?b" cannot change which resource the proxy addresses.
    return "/fgt/{0}/{1}".format(quote(str(sn), safe=""), fos_path)


def _ipv4_network(value):
    """Accept a single IPv4 address or an IPv4 CIDR; return (subnet_text, normalized_ip)."""
    text = str(value).strip()
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError as err:
        raise ConnectorError(
            "'ip' must be an IPv4 address or CIDR (for example 203.0.113.10 or "
            "203.0.113.0/24); got '{0}'".format(text)
        ) from err
    if net.version != 4:
        raise ConnectorError(
            "Only IPv4 is supported for this operation; got '{0}'".format(text)
        )
    subnet = "{0} {1}".format(net.network_address, net.netmask)
    return subnet, str(net.network_address)


def _block_name(ip_value):
    """The deterministic object name for a blocked target, and its reversal."""
    text = str(ip_value).strip()
    name = _BLOCK_PREFIX + text.replace("/", "-").replace(".", "_")
    if len(name) > _MAX_NAME_LEN:
        raise ConnectorError(
            "The normalized block name for '{0}' exceeds the {1} character FortiGate "
            "object name limit; block a shorter prefix".format(text, _MAX_NAME_LEN)
        )
    return name


def _int_param(params, name, default=None, maximum=None):
    value = params.get(name)
    if value in (None, ""):
        return default
    try:
        number = int(value)
    except (TypeError, ValueError) as err:
        raise ConnectorError("'{0}' must be an integer; got '{1}'".format(name, value)) from err
    if maximum is not None and number > maximum:
        number = maximum
    return number


def _interface_list(params, name, default="any"):
    value = params.get(name)
    if value in (None, ""):
        value = default
    names = [part.strip() for part in str(value).split(",") if part.strip()]
    if not names:
        raise ConnectorError("'{0}' resolved to an empty interface list".format(name))
    return [{"name": n} for n in names]


# --- curated reads --------------------------------------------------------


def get_fgt_system_status(config: dict, params: dict) -> dict:
    """Read the FortiOS system status of a cloud-managed FortiGate (hostname,
    model, firmware, serial, vdom, resource use) through FortiGate Cloud."""
    sn = _require(params, "sn")
    fgc = _client(config)
    return fgc.make_request(
        endpoint=_proxy_path(sn, "api/v2/monitor/system/status"), method="GET"
    )


def list_firewall_addresses(config: dict, params: dict) -> dict:
    """List firewall address objects on a cloud-managed FortiGate through
    FortiGate Cloud. Supports limit and offset pagination."""
    sn = _require(params, "sn")
    query = {}
    limit = _int_param(params, "limit", default=100, maximum=1000)
    offset = _int_param(params, "offset", default=0)
    query["limit"] = limit
    if offset:
        query["offset"] = offset
    fgc = _client(config)
    return fgc.make_request(
        endpoint=_proxy_path(sn, "api/v2/cmdb/firewall/address"),
        method="GET",
        params=query,
    )


def list_firewall_policies(config: dict, params: dict) -> dict:
    """List firewall policies on a cloud-managed FortiGate through FortiGate
    Cloud, in policy order (top of the match order first)."""
    sn = _require(params, "sn")
    query = {}
    limit = _int_param(params, "limit", default=100, maximum=1000)
    offset = _int_param(params, "offset", default=0)
    query["limit"] = limit
    if offset:
        query["offset"] = offset
    fgc = _client(config)
    return fgc.make_request(
        endpoint=_proxy_path(sn, "api/v2/cmdb/firewall/policy"),
        method="GET",
        params=query,
    )


# --- curated writes -------------------------------------------------------


def create_firewall_address(config: dict, params: dict) -> dict:
    """Create a firewall address object on a cloud-managed FortiGate through
    FortiGate Cloud. 'ip' accepts a single IPv4 address (a /32 object) or a
    CIDR network."""
    sn = _require(params, "sn")
    name = _require(params, "name")
    subnet, _ = _ipv4_network(_require(params, "ip"))
    body = {"name": name, "type": "ipmask", "subnet": subnet}
    comment = params.get("comment")
    if comment:
        body["comment"] = str(comment)[:255]
    fgc = _client(config)
    return fgc.make_request(
        endpoint=_proxy_path(sn, "api/v2/cmdb/firewall/address"),
        method="POST",
        json_data=body,
    )


def delete_firewall_address(config: dict, params: dict) -> dict:
    """Delete a firewall address object on a cloud-managed FortiGate through
    FortiGate Cloud. The operation fails safely if the object does not exist."""
    sn = _require(params, "sn")
    name = _require(params, "name")
    fgc = _client(config)
    return fgc.make_request(
        endpoint=_proxy_path(
            sn, "api/v2/cmdb/firewall/address/{0}".format(quote(name, safe=""))
        ),
        method="DELETE",
    )


# --- block / unblock flow -------------------------------------------------


def _find_policy(policies, name):
    for policy in policies:
        if policy.get("name") == name:
            return policy
    return None


def _position_of(policies, policy_id):
    return next(
        (index for index, p in enumerate(policies) if p.get("policyid") == policy_id),
        None,
    )


# The FortiGate Cloud proxy caches CMDB reads per request identity and can
# serve a view that is minutes old — including one that still shows a policy
# deleted earlier — and it keeps doing so even while the device is unreachable.
# Anything that must reflect the device's real state verifies with a direct
# read of the object itself (a different, uncached request) instead of
# trusting a list.
_NOT_FOUND_MARKERS = ("not_found", "not found")


def _is_not_found(err):
    text = str(err).lower()
    return any(marker in text for marker in _NOT_FOUND_MARKERS)


def _policy_exists(fgc, sn, policy_id):
    """Direct GET of one policy by id, to confirm a list entry is real."""
    if policy_id is None:
        return False
    try:
        fgc.make_request(
            endpoint=_proxy_path(
                sn, "api/v2/cmdb/firewall/policy/{0}".format(quote(str(policy_id), safe=""))
            ),
            method="GET",
        )
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


def _list_policies_waiting(fgc, sn, want_name=None, attempts=None, delay=None):
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


def _list_policies(fgc, sn, limit=1000):
    body = fgc.make_request(
        endpoint=_proxy_path(sn, "api/v2/cmdb/firewall/policy"),
        method="GET",
        params={"limit": limit},
    )
    return body.get("results") or []


def _address_exists(fgc, sn, name):
    """Return the address body when it exists, None when it does not. Any
    other failure raises: treating an error as 'absent' could double-create
    or mask a real problem."""
    body = fgc.make_request(
        endpoint=_proxy_path(
            sn, "api/v2/cmdb/firewall/address/{0}".format(quote(name, safe=""))
        ),
        method="GET",
        ok_statuses=(404,),
    )
    if isinstance(body, dict) and (
        body.get("http_status") == 404 or body.get("error") == "not_found"
    ):
        return None
    return body


def _ensure_address(fgc, sn, name, subnet, comment):
    existing = _address_exists(fgc, sn, name)
    if existing is not None:
        results = existing.get("results") if isinstance(existing, dict) else None
        if isinstance(results, list) and results:
            results = results[0]
        current = results.get("subnet") if isinstance(results, dict) else None
        if current and current != subnet:
            raise ConnectorError(
                "An address object named '{0}' already exists with subnet '{1}', "
                "which does not match the requested '{2}'. Unblock or rename the "
                "existing object first.".format(name, current, subnet)
            )
        return {"name": name, "reused": True}
    body = fgc.make_request(
        endpoint=_proxy_path(sn, "api/v2/cmdb/firewall/address"),
        method="POST",
        json_data={"name": name, "type": "ipmask", "subnet": subnet,
                   "comment": (comment or "Created by FortiSOAR fortigate-cloud block_ip")[:255]},
    )
    return {"name": name, "reused": False, "response": body}


def _deny_policy_body(name, address_name, direction, srcintf, dstintf, comment):
    body = {
        "name": name,
        "action": "deny",
        "srcintf": srcintf,
        "dstintf": dstintf,
        "srcaddr": [{"name": address_name}] if direction == "inbound" else [{"name": "all"}],
        "dstaddr": [{"name": address_name}] if direction == "outbound" else [{"name": "all"}],
        "schedule": "always",
        "service": [{"name": "ALL"}],
        "logtraffic": "all",
        "status": "enable",
        "comments": (comment or "Created by FortiSOAR fortigate-cloud block_ip")[:255],
    }
    return body


def _move_to_top(fgc, sn, policy_id, policy_name):
    """Move a policy above the current top policy so the deny is evaluated
    before any broad accept policy. Uses the FortiOS CMDB move action, then
    verifies with re-lists (the proxy's reads can lag the move) before
    declaring failure."""
    policies = _list_policies_waiting(fgc, sn, want_name=policy_name)
    position = _position_of(policies, policy_id)
    if position == 0:
        return {"moved": False, "position": 0, "top_policy_id": policy_id}
    top_id = policies[0].get("policyid") if policies else None
    if top_id is not None and top_id != policy_id:
        fgc.make_request(
            endpoint=_proxy_path(
                sn, "api/v2/cmdb/firewall/policy/{0}".format(quote(str(policy_id), safe=""))
            ),
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


def block_ip(config: dict, params: dict) -> dict:
    """Block an IPv4 address or CIDR on a cloud-managed FortiGate through
    FortiGate Cloud: create (or reuse) an FSR-BLOCK-<ip> address object and a
    deny policy that matches only that address, then move the policy to the
    top of the policy order. Traffic to or from other hosts is not affected.
    Idempotent: rerunning block_ip reuses existing objects."""
    sn = _require(params, "sn")
    ip_value = _require(params, "ip")
    subnet, _ = _ipv4_network(ip_value)
    name = _block_name(ip_value)
    direction = (params.get("direction") or "both").strip().lower()
    if direction not in ("inbound", "outbound", "both"):
        raise ConnectorError(
            "'direction' must be one of inbound, outbound or both; got '{0}'".format(direction)
        )
    srcintf = _interface_list(params, "srcintf")
    dstintf = _interface_list(params, "dstintf")
    comment = params.get("comment")

    fgc = _client(config)
    address = _ensure_address(fgc, sn, name, subnet, comment)

    directions = {"inbound", "outbound"} if direction == "both" else {direction}
    policies = _list_policies(fgc, sn)
    results = []
    for item in sorted(directions):  # deterministic order: inbound, then outbound
        policy_name = "{0}-{1}".format(name, item.upper())
        existing = _find_policy(policies, policy_name)
        if existing is not None and _policy_exists(fgc, sn, existing.get("policyid")):
            results.append({
                "name": policy_name,
                "policyid": existing.get("policyid"),
                "created": False,
            })
            continue
        body = _deny_policy_body(policy_name, name, item, srcintf, dstintf, comment)
        response = fgc.make_request(
            endpoint=_proxy_path(sn, "api/v2/cmdb/firewall/policy"),
            method="POST",
            json_data=body,
        )
        created_policy = None
        resp_results = response.get("results") if isinstance(response, dict) else None
        if isinstance(resp_results, dict):
            created_policy = resp_results.get("mkey") or resp_results.get("policyid")
        elif isinstance(resp_results, list) and resp_results:
            created_policy = resp_results[0].get("policyid")
        if created_policy is None:
            raise ConnectorError(
                "The deny policy '{0}' was created but FortiGate Cloud did not "
                "return its policy id, so it cannot be moved or verified. Remove "
                "it with unblock_ip and retry.".format(policy_name)
            )
        move = _move_to_top(fgc, sn, created_policy, policy_name)
        policies = _list_policies(fgc, sn)  # refresh order for the next direction
        results.append({
            "name": policy_name,
            "policyid": created_policy,
            "created": True,
            "moved_to_top": move.get("moved", False),
            "position": move.get("position"),
        })

    return {
        "device": sn,
        "ip": str(ip_value).strip(),
        "address": address,
        "policies": results,
    }


def unblock_ip(config: dict, params: dict) -> dict:
    """Remove what block_ip created for an IPv4 address or CIDR: delete the
    FSR-BLOCK deny policies, then delete the address object unless a policy
    this connector did not create still references it. Idempotent: objects
    that are already absent are reported, not treated as errors."""
    sn = _require(params, "sn")
    ip_value = _require(params, "ip")
    name = _block_name(ip_value)
    fgc = _client(config)

    policies = _list_policies(fgc, sn)
    removed = []
    for policy in policies:
        policy_name = policy.get("name") or ""
        if policy_name == name or policy_name.startswith(name + "-"):
            try:
                fgc.make_request(
                    endpoint=_proxy_path(
                        sn,
                        "api/v2/cmdb/firewall/policy/{0}".format(
                            quote(str(policy.get("policyid")), safe="")
                        ),
                    ),
                    method="DELETE",
                )
                removed.append({"name": policy_name, "policyid": policy.get("policyid")})
            except ConnectorError as err:
                if not _is_not_found(err):
                    raise
                # A stale proxy list can still show a policy deleted earlier;
                # the goal (the policy is gone) already holds.
                removed.append({"name": policy_name, "policyid": policy.get("policyid"),
                                "already_absent": True})

    address_removed = False
    retained_reason = None
    if _address_exists(fgc, sn, name) is not None:
        remaining = _list_policies(fgc, sn)
        foreign_refs = []
        for policy in remaining:
            policy_name = policy.get("name") or ""
            if policy_name == name or policy_name.startswith(name + "-"):
                continue
            for field in ("srcaddr", "dstaddr"):
                for member in policy.get(field) or []:
                    if member.get("name") == name:
                        foreign_refs.append("{0}#{1}".format(policy_name, field))
        if foreign_refs:
            retained_reason = (
                "The address object is still referenced by: {0}. Delete those "
                "references first.".format(", ".join(foreign_refs))
            )
        else:
            try:
                fgc.make_request(
                    endpoint=_proxy_path(
                        sn, "api/v2/cmdb/firewall/address/{0}".format(quote(name, safe=""))
                    ),
                    method="DELETE",
                )
                address_removed = True
            except ConnectorError as err:
                if not _is_not_found(err):
                    raise
                # The address was already gone (the exists-check read a stale
                # proxy view); cleanup is idempotent, so that is success.

    return {
        "device": sn,
        "ip": str(ip_value).strip(),
        "address_name": name,
        "removed_policies": removed,
        "address_removed": address_removed,
        "address_retained_reason": retained_reason,
    }


# --- quarantine (ban-IP) flow ---------------------------------------------
#
# A second containment style alongside the policy flow above: the FortiOS
# Quarantine Monitor bans IPv4 addresses at runtime. One call bans a whole
# batch, no address objects or policies are touched, every entry carries its
# own expiry, and the ban survives neither expiry nor reboot — so a playbook
# that fails to clean up still cannot leave the device blocked permanently.


def _ban_ips(params, name="ips"):
    """Parse a comma-separated string (or list) of strict IPv4 addresses."""
    value = params.get(name)
    if value in (None, ""):
        raise ConnectorError("'{0}' is a required parameter".format(name))
    raw = value if isinstance(value, list) else str(value).split(",")
    items = [str(item).strip() for item in raw if str(item).strip()]
    if not items:
        raise ConnectorError("'{0}' resolved to an empty address list".format(name))
    addresses = []
    for item in items:
        try:
            parsed = ipaddress.ip_address(item)
        except ValueError as err:
            raise ConnectorError(
                "'{0}' must be IPv4 addresses separated by commas; "
                "got '{1}'".format(name, item)
            ) from err
        if parsed.version != 4:
            raise ConnectorError(
                "Only IPv4 addresses are supported by the Quarantine Monitor; "
                "got '{0}'".format(item)
            )
        addresses.append(str(parsed))
    return addresses


def _ban_expiry(params, name="time_to_live", duration_name="duration"):
    """Resolve the ban duration: a named preset, or 'Custom Time' + duration
    seconds. Zero means the ban never expires."""
    preset = (params.get(name) or "1 Hour").strip()
    if preset == "Custom Time":
        duration = _int_param(params, duration_name)
        if duration is None:
            raise ConnectorError(
                "'duration' is required when 'time_to_live' is 'Custom Time'"
            )
        if duration < 0:
            raise ConnectorError(
                "'duration' must be zero (never expires) or a positive number "
                "of seconds; got '{0}'".format(duration)
            )
        return duration
    if preset not in _EXPIRY_PRESETS:
        raise ConnectorError(
            "'time_to_live' must be one of {0}, or 'Custom Time' with a "
            "'duration' in seconds; got '{1}'".format(
                ", ".join(sorted(_EXPIRY_PRESETS)), preset
            )
        )
    return _EXPIRY_PRESETS[preset]


def _banned_entries(fgc, sn, vdom):
    """Read the Quarantine Monitor. Returns (entries, banned_ip_set); the
    entries are passed through verbatim so no vendor field is lost."""
    body = fgc.make_request(
        endpoint=_proxy_path(sn, "api/v2/monitor/user/banned/select"),
        method="GET",
        params={"vdom": vdom},
    )
    results = body.get("results") if isinstance(body, dict) else body
    if isinstance(results, dict):
        results = results.get("results")
    entries = results if isinstance(results, list) else []
    banned = {entry.get("ip_address") for entry in entries
              if isinstance(entry, dict) and entry.get("ip_address")}
    return entries, banned


def _ban_post(fgc, sn, vdom, fos_path, body):
    return fgc.make_request(
        endpoint=_proxy_path(sn, fos_path),
        method="POST",
        params={"vdom": vdom},
        headers=_QUARANTINE_FORM_HEADERS,
        data=json.dumps(body),
    )


def quarantine_ip(config: dict, params: dict) -> dict:
    """Quarantine (ban) IPv4 addresses on a cloud-managed FortiGate through
    FortiGate Cloud using the Quarantine Monitor: a runtime ban with its own
    expiry that needs no address objects or policies. Idempotent — addresses
    that are already banned are reported, not re-banned. Rerunning is safe;
    leaving the ban in place is also safe, because it expires on its own
    unless 'time_to_live' is 'Never'."""
    sn = _require(params, "sn")
    addresses = _ban_ips(params, "ips")
    expiry = _ban_expiry(params, "time_to_live", "duration")
    vdom = (params.get("vdom") or "root").strip() or "root"
    fgc = _client(config)

    _, banned_now = _banned_entries(fgc, sn, vdom)
    already = [ip for ip in addresses if ip in banned_now]
    to_ban = [ip for ip in addresses if ip not in banned_now]

    response = None
    if to_ban:
        response = _ban_post(
            fgc, sn, vdom, "api/v2/monitor/user/banned/add_users",
            {"ip_addresses": to_ban, "expiry": expiry, "src": "ips"},
        )
        _, banned_now = _banned_entries(fgc, sn, vdom)

    result = {
        "device": sn,
        "vdom": vdom,
        "quarantined": [ip for ip in to_ban if ip in banned_now],
        "pending": [ip for ip in to_ban if ip not in banned_now],
        "already_quarantined": already,
        "expiry_seconds": expiry,
    }
    if response is not None:
        result["response"] = response
    return result


def unquarantine_ip(config: dict, params: dict) -> dict:
    """Release Quarantine Monitor bans created by quarantine_ip (or the CLI's
    'diagnose user banned-ip add'). Idempotent: addresses that are not banned
    are reported as such instead of erroring."""
    sn = _require(params, "sn")
    addresses = _ban_ips(params, "ips")
    vdom = (params.get("vdom") or "root").strip() or "root"
    fgc = _client(config)

    _, banned_now = _banned_entries(fgc, sn, vdom)
    to_clear = [ip for ip in addresses if ip in banned_now]
    not_banned = [ip for ip in addresses if ip not in banned_now]

    response = None
    if to_clear:
        response = _ban_post(
            fgc, sn, vdom, "api/v2/monitor/user/banned/clear_users",
            {"ip_addresses": to_clear},
        )
        _, banned_now = _banned_entries(fgc, sn, vdom)

    result = {
        "device": sn,
        "vdom": vdom,
        "released": [ip for ip in to_clear if ip not in banned_now],
        "still_banned": [ip for ip in to_clear if ip in banned_now],
        "not_banned": not_banned,
    }
    if response is not None:
        result["response"] = response
    return result


def list_banned_ips(config: dict, params: dict) -> dict:
    """List the Quarantine Monitor's current IP bans on a cloud-managed
    FortiGate through FortiGate Cloud. Entries are the vendor's own fields
    (ip_address, expiry, created, cause), passed through verbatim."""
    sn = _require(params, "sn")
    vdom = (params.get("vdom") or "root").strip() or "root"
    fgc = _client(config)
    entries, _ = _banned_entries(fgc, sn, vdom)
    return {
        "device": sn,
        "vdom": vdom,
        "banned": entries,
        "count": len(entries),
    }
