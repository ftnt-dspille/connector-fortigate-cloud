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
from urllib.parse import quote

from connectors.core.connector import ConnectorError

from .make_rest_api_call import MakeRestApiCall

_BLOCK_PREFIX = "FSR-BLOCK-"
_MAX_NAME_LEN = 79  # FortiGate object name limit


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


def _move_to_top(fgc, sn, policy_id):
    """Move a policy above the current top policy so the deny is evaluated
    before any broad accept policy. Uses the FortiOS CMDB move action."""
    policies = _list_policies(fgc, sn)
    position = next(
        (index for index, p in enumerate(policies) if p.get("policyid") == policy_id),
        None,
    )
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
    policies = _list_policies(fgc, sn)
    position = next(
        (index for index, p in enumerate(policies) if p.get("policyid") == policy_id),
        None,
    )
    if position != 0:
        raise ConnectorError(
            "The deny policy {0} was created but could not be moved to the top of "
            "the policy order; it currently sits at position {1}. It may not take "
            "effect above existing accept policies. Remove it with unblock_ip and "
            "retry, or move it manually.".format(policy_id, position)
        )
    return {"moved": True, "position": 0, "top_policy_id": top_id}


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
        if existing is not None:
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
        move = _move_to_top(fgc, sn, created_policy)
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
            fgc.make_request(
                endpoint=_proxy_path(
                    sn, "api/v2/cmdb/firewall/address/{0}".format(quote(name, safe=""))
                ),
                method="DELETE",
            )
            address_removed = True

    return {
        "device": sn,
        "ip": str(ip_value).strip(),
        "address_name": name,
        "removed_policies": removed,
        "address_removed": address_removed,
        "address_retained_reason": retained_reason,
    }
