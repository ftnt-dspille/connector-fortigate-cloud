"""Unit tests for the curated FortiOS proxy operations (fgt_proxy_actions).

Same discipline as test_fortigate_cloud.py: every outbound HTTP call is
intercepted, so these assert on the request the connector builds and on how
orchestrations sequence reads and writes. The request shapes follow the ones
confirmed live against the FortiGate Cloud proxy.
"""

from __future__ import annotations

import json

import pytest


class FakeResponse:
    def __init__(self, status=200, payload=None, text='', content_type='application/json'):
        self.status_code = status
        self._payload = payload if payload is not None else {}
        self.text = text or json.dumps(self._payload)
        self.headers = {'Content-Type': content_type}

    @property
    def ok(self):
        return 200 <= self.status_code < 300

    def json(self):
        if self._payload is None:
            raise ValueError('no json')
        return self._payload


BASE = 'https://api.fortigate.forticloud.com/forticloudapi/v1'
SN = 'FGT91GTK25007142'


def fgt_url(fos_path):
    return '{0}/fgt/{1}/{2}'.format(BASE, SN, fos_path)


@pytest.fixture
def router(monkeypatch, rest_mod):
    """Route outbound calls by (method, url substring) to scripted responses.

    Each route holds a list of responses popped in order; when the list runs
    dry the last response repeats. Token grants are answered automatically.
    """
    recorded = []
    routes = []

    def fake_post(url, **kw):
        recorded.append({'method': 'POST', 'url': url, **kw})
        return FakeResponse(payload={
            'status': 'success', 'access_token': 'tok-123',
            'refresh_token': 'refresh-tok-123', 'expires_in': 3660,
        })

    def fake_request(method=None, url=None, **kw):
        call = {'method': method, 'url': url, **kw}
        recorded.append(call)
        for route_method, substring, responses in routes:
            if method == route_method and substring in url:
                return responses[-1] if len(responses) == 1 else responses.pop(0)
        raise AssertionError('unexpected call: {0} {1}'.format(method, url))

    monkeypatch.setattr(rest_mod.requests, 'post', fake_post)
    monkeypatch.setattr(rest_mod.requests, 'request', fake_request)

    def add(method, substring, *responses):
        # Extend an existing route when one for the same (method, substring)
        # already exists, so scripted sequences for one endpoint stay in order.
        for route in routes:
            if route[0] == method and route[1] == substring:
                route[2].extend(responses)
                return
        routes.append([method, substring, list(responses)])

    router.calls = recorded
    router.add = add
    return router


def api_calls(router):
    return [c for c in router.calls if 'oauth' not in c['url']]


NOT_FOUND = {'status': 'error', 'http_status': 404, 'revision': 'rev-0'}


def policy(pid, name):
    return {'policyid': pid, 'name': name, 'action': 'accept',
            'srcintf': [{'name': 'lan'}], 'dstintf': [{'name': 'underlay'}]}


# --- curated reads --------------------------------------------------------


def test_system_status_url_and_method(ops, config, router):
    router.add('GET', '/api/v2/monitor/system/status', FakeResponse(payload={'results': {}}))
    ops.operations['get_fgt_system_status'](config, {'sn': SN})
    call = api_calls(router)[0]
    assert call['method'] == 'GET'
    assert call['url'] == fgt_url('api/v2/monitor/system/status')


def test_sn_is_url_quoted(ops, config, router):
    router.add('GET', '/api/v2/monitor/system/status', FakeResponse(payload={}))
    ops.operations['get_fgt_system_status'](config, {'sn': 'FGT abc/1'})
    assert api_calls(router)[0]['url'].endswith('/fgt/FGT%20abc%2F1/api/v2/monitor/system/status')


def test_list_addresses_default_sends_limit_only(ops, config, router):
    router.add('GET', '/api/v2/cmdb/firewall/address',
               FakeResponse(payload={'results': [], 'matched_count': 0}))
    ops.operations['list_firewall_addresses'](config, {'sn': SN})
    call = api_calls(router)[0]
    assert call['url'] == fgt_url('api/v2/cmdb/firewall/address')
    assert call['params'] == {'limit': 100}


def test_list_addresses_offset_and_cap(ops, config, router):
    router.add('GET', '/api/v2/cmdb/firewall/address', FakeResponse(payload={'results': []}))
    ops.operations['list_firewall_addresses'](config, {'sn': SN, 'limit': '5000', 'offset': '40'})
    call = api_calls(router)[0]
    assert call['params'] == {'limit': 1000, 'offset': 40}


def test_list_addresses_non_integer_limit_raises(ops, config, connector_error, router):
    with pytest.raises(connector_error):
        ops.operations['list_firewall_addresses'](config, {'sn': SN, 'limit': 'many'})


def test_list_policies_url_and_defaults(ops, config, router):
    router.add('GET', '/api/v2/cmdb/firewall/policy', FakeResponse(payload={'results': []}))
    ops.operations['list_firewall_policies'](config, {'sn': SN})
    call = api_calls(router)[0]
    assert call['url'] == fgt_url('api/v2/cmdb/firewall/policy')
    assert call['params'] == {'limit': 100}


# --- curated writes -------------------------------------------------------


def test_create_address_body_slash32(ops, config, router):
    router.add('POST', '/api/v2/cmdb/firewall/address',
               FakeResponse(payload={'status': 'success', 'revision_changed': True}))
    ops.operations['create_firewall_address'](config, {'sn': SN, 'name': 'srv', 'ip': '203.0.113.10'})
    call = api_calls(router)[0]
    assert call['method'] == 'POST'
    assert call['url'] == fgt_url('api/v2/cmdb/firewall/address')
    assert call['json'] == {'name': 'srv', 'type': 'ipmask',
                            'subnet': '203.0.113.10 255.255.255.255'}


def test_create_address_body_cidr(ops, config, router):
    router.add('POST', '/api/v2/cmdb/firewall/address', FakeResponse(payload={}))
    ops.operations['create_firewall_address'](config, {
        'sn': SN, 'name': 'net', 'ip': '203.0.113.0/24', 'comment': 'block net'})
    call = api_calls(router)[0]
    assert call['json'] == {'name': 'net', 'type': 'ipmask',
                            'subnet': '203.0.113.0 255.255.255.0', 'comment': 'block net'}


def test_create_address_rejects_ipv6(ops, config, connector_error):
    with pytest.raises(connector_error):
        ops.operations['create_firewall_address'](config, {
            'sn': SN, 'name': 'v6', 'ip': '2001:db8::1'})


def test_create_address_rejects_non_ip(ops, config, connector_error):
    with pytest.raises(connector_error):
        ops.operations['create_firewall_address'](config, {
            'sn': SN, 'name': 'x', 'ip': 'not-an-ip'})


def test_delete_address_quotes_name(ops, config, router):
    router.add('DELETE', '/api/v2/cmdb/firewall/address/', FakeResponse(payload={}))
    ops.operations['delete_firewall_address'](config, {'sn': SN, 'name': 'bad name/1'})
    call = api_calls(router)[0]
    assert call['method'] == 'DELETE'
    assert call['url'].endswith('/api/v2/cmdb/firewall/address/bad%20name%2F1')


# --- make_request ok_statuses --------------------------------------------


def test_make_request_ok_statuses_returns_404_body(ops, config, router):
    router.add('GET', '/whatever', FakeResponse(status=404, payload=NOT_FOUND))
    fgc = ops.MakeRestApiCall(config=config)
    body = fgc.make_request(endpoint='/whatever', method='GET', ok_statuses=(404,))
    assert body['http_status'] == 404


def test_make_request_unexpected_404_still_raises(ops, config, connector_error, router):
    router.add('GET', '/whatever', FakeResponse(status=404, payload=NOT_FOUND))
    fgc = ops.MakeRestApiCall(config=config)
    with pytest.raises(connector_error):
        fgc.make_request(endpoint='/whatever', method='GET')


# --- block_ip -------------------------------------------------------------


def _shorten_retries(monkeypatch, ops):
    """Keep retry-loop tests fast: two verify attempts, no sleep.

    Patch the globals dict of the executing function itself: several fixtures
    reload the connector modules, so the object under sys.modules is not
    guaranteed to be the one whose code runs.
    """
    g = ops.operations['block_ip'].__globals__
    monkeypatch.setitem(g, '_LIST_RETRY_ATTEMPTS', 2)
    monkeypatch.setitem(g, '_LIST_RETRY_DELAY', 0.0)


def _created_list(existing, addr_name, suffix):
    """A policy list in which the just-created deny policy exists but still
    sits at the bottom — the stale-ordered view the proxy can serve."""
    return {'results': list(existing) + [policy(99, addr_name + '-' + suffix)],
            'matched_count': len(existing) + 1}


def test_block_ip_fresh_inbound_flow(ops, config, router):
    addr_name = 'FSR-BLOCK-203_0_113_77'
    initial = {'results': [policy(1, 'Home-to-Internet')], 'matched_count': 1}
    created = _created_list([policy(1, 'Home-to-Internet')], addr_name, 'INBOUND')
    moved = {'results': [policy(99, addr_name + '-INBOUND'), policy(1, 'Home-to-Internet')],
             'matched_count': 2}
    router.add('GET', '/address/' + addr_name, FakeResponse(status=404, payload=NOT_FOUND))
    router.add('POST', '/cmdb/firewall/address', FakeResponse(payload={'revision_changed': True}))
    router.add('GET', '/cmdb/firewall/policy', FakeResponse(payload=initial))
    router.add('POST', '/cmdb/firewall/policy',
               FakeResponse(payload={'results': {'policyid': 99}, 'revision_changed': True}))
    router.add('GET', '/cmdb/firewall/policy', FakeResponse(payload=created))
    router.add('PUT', '/cmdb/firewall/policy/99', FakeResponse(payload={'revision_changed': True}))
    router.add('GET', '/cmdb/firewall/policy', FakeResponse(payload=moved),
               FakeResponse(payload=moved))

    result = ops.operations['block_ip'](config, {'sn': SN, 'ip': '203.0.113.77', 'direction': 'inbound'})

    assert result['address'] == {'name': addr_name, 'reused': False, 'response': {'revision_changed': True}}
    assert result['policies'] == [{'name': addr_name + '-INBOUND', 'policyid': 99,
                                   'created': True, 'moved_to_top': True, 'position': 0}]

    create_addr = api_calls(router)[1]
    assert create_addr['json'] == {'name': addr_name, 'type': 'ipmask',
                                   'subnet': '203.0.113.77 255.255.255.255',
                                   'comment': 'Created by FortiSOAR fortigate-cloud block_ip'}
    create_pol = api_calls(router)[3]
    assert create_pol['json']['action'] == 'deny'
    assert create_pol['json']['srcaddr'] == [{'name': addr_name}]
    assert create_pol['json']['dstaddr'] == [{'name': 'all'}]
    assert create_pol['json']['srcintf'] == [{'name': 'any'}]
    assert create_pol['json']['dstintf'] == [{'name': 'any'}]
    assert create_pol['json']['status'] == 'enable'
    move = api_calls(router)[5]
    assert move['method'] == 'PUT'
    assert move['url'] == fgt_url('api/v2/cmdb/firewall/policy/99')
    assert move['params'] == {'action': 'move', 'before': 1}


def test_block_ip_reads_policy_id_from_top_level_mkey(ops, config, router):
    addr_name = 'FSR-BLOCK-203_0_113_77'
    initial = {'results': [policy(1, 'Home-to-Internet')], 'matched_count': 1}
    created = _created_list([policy(1, 'Home-to-Internet')], addr_name, 'INBOUND')
    moved = {'results': [policy(99, addr_name + '-INBOUND'), policy(1, 'Home-to-Internet')],
             'matched_count': 2}
    router.add('GET', '/address/' + addr_name, FakeResponse(status=404, payload=NOT_FOUND))
    router.add('POST', '/cmdb/firewall/address', FakeResponse(payload={'revision_changed': True}))
    router.add('GET', '/cmdb/firewall/policy', FakeResponse(payload=initial))
    router.add('POST', '/cmdb/firewall/policy',
               FakeResponse(payload={'mkey': 99, 'status': 'success', 'revision_changed': True}))
    router.add('GET', '/cmdb/firewall/policy', FakeResponse(payload=created))
    router.add('PUT', '/cmdb/firewall/policy/99', FakeResponse(payload={'revision_changed': True}))
    router.add('GET', '/cmdb/firewall/policy', FakeResponse(payload=moved),
               FakeResponse(payload=moved))

    result = ops.operations['block_ip'](config, {'sn': SN, 'ip': '203.0.113.77', 'direction': 'inbound'})

    assert result['address'] == {'name': addr_name, 'reused': False, 'response': {'revision_changed': True}}
    assert result['policies'] == [{'name': addr_name + '-INBOUND', 'policyid': 99,
                                   'created': True, 'moved_to_top': True, 'position': 0}]

    create_addr = api_calls(router)[1]
    assert create_addr['json'] == {'name': addr_name, 'type': 'ipmask',
                                   'subnet': '203.0.113.77 255.255.255.255',
                                   'comment': 'Created by FortiSOAR fortigate-cloud block_ip'}
    create_pol = api_calls(router)[3]
    assert create_pol['json']['action'] == 'deny'
    assert create_pol['json']['srcaddr'] == [{'name': addr_name}]
    assert create_pol['json']['dstaddr'] == [{'name': 'all'}]
    assert create_pol['json']['srcintf'] == [{'name': 'any'}]
    assert create_pol['json']['dstintf'] == [{'name': 'any'}]
    assert create_pol['json']['status'] == 'enable'
    move = api_calls(router)[5]
    assert move['method'] == 'PUT'
    assert move['url'] == fgt_url('api/v2/cmdb/firewall/policy/99')
    assert move['params'] == {'action': 'move', 'before': 1}


def test_block_ip_reuses_existing_address_and_policy(ops, config, router):
    addr_name = 'FSR-BLOCK-203_0_113_77'
    router.add('GET', '/address/' + addr_name,
               FakeResponse(payload={'results': {'subnet': '203.0.113.77 255.255.255.255'}}))
    # Routes match by substring, so the by-id route must be registered before
    # the list route or the list answers for the direct read too.
    router.add('GET', '/cmdb/firewall/policy/5',
               FakeResponse(payload={'results': policy(5, addr_name + '-INBOUND')}))
    router.add('GET', '/cmdb/firewall/policy',
               FakeResponse(payload={'results': [policy(5, addr_name + '-INBOUND')],
                                     'matched_count': 1}))
    result = ops.operations['block_ip'](config, {'sn': SN, 'ip': '203.0.113.77',
                                                 'direction': 'inbound'})
    assert result['address'] == {'name': addr_name, 'reused': True}
    assert result['policies'] == [{'name': addr_name + '-INBOUND', 'policyid': 5, 'created': False}]
    # No POST and no move happened.
    assert not [c for c in api_calls(router) if c['method'] == 'POST']
    assert [c for c in api_calls(router) if c['url'].endswith('/policy/5')]


def test_block_ip_creates_fresh_when_the_list_shows_a_deleted_policy(ops, config, router):
    """The proxy's list reads can serve a cached view that still contains a
    policy deleted earlier. Reusing it would report a block that is not in
    effect, so block_ip verifies the listed policy and creates a new one."""
    addr_name = 'FSR-BLOCK-203_0_113_77'
    ghost_list = {'results': [policy(5, addr_name + '-INBOUND')], 'matched_count': 1}
    created = _created_list([policy(1, 'Home-to-Internet')], addr_name, 'INBOUND')
    moved = {'results': [policy(99, addr_name + '-INBOUND'), policy(1, 'Home-to-Internet')],
             'matched_count': 2}
    router.add('GET', '/address/' + addr_name, FakeResponse(status=404, payload=NOT_FOUND))
    router.add('POST', '/cmdb/firewall/address', FakeResponse(payload={}))
    # The by-id route must be registered before the list route: routes match
    # by substring, so '/cmdb/firewall/policy' also matches '/policy/5'.
    router.add('GET', '/cmdb/firewall/policy/5', FakeResponse(status=404, payload=NOT_FOUND))
    router.add('GET', '/cmdb/firewall/policy', FakeResponse(payload=ghost_list),
               FakeResponse(payload=created), FakeResponse(payload=moved),
               FakeResponse(payload=moved))
    router.add('POST', '/cmdb/firewall/policy', FakeResponse(payload={'results': {'policyid': 99}}))
    router.add('PUT', '/cmdb/firewall/policy/99', FakeResponse(payload={}))

    result = ops.operations['block_ip'](config, {'sn': SN, 'ip': '203.0.113.77',
                                                 'direction': 'inbound'})
    assert result['policies'] == [{'name': addr_name + '-INBOUND', 'policyid': 99,
                                   'created': True, 'moved_to_top': True, 'position': 0}]


def test_unblock_ip_treats_stale_list_ghost_policies_as_absent(ops, config, router):
    ghost = {'results': [policy(5, 'FSR-BLOCK-203_0_113_77-INBOUND')], 'matched_count': 1}
    router.add('GET', '/cmdb/firewall/policy', FakeResponse(payload=ghost))
    router.add('DELETE', '/cmdb/firewall/policy/5', FakeResponse(status=404, payload=NOT_FOUND))
    router.add('GET', '/address/FSR-BLOCK-203_0_113_77', FakeResponse(status=404, payload=NOT_FOUND))

    result = ops.operations['unblock_ip'](config, {'sn': SN, 'ip': '203.0.113.77'})
    assert result['removed_policies'] == [
        {'name': 'FSR-BLOCK-203_0_113_77-INBOUND', 'policyid': 5, 'already_absent': True}]
    assert result['address_removed'] is False
    assert result['address_retained_reason'] is None


def test_unblock_ip_survives_a_stale_address_view(ops, config, router):
    """The exists-check can read a stale view that still shows an address that
    was already deleted; the delete then 404s and unblock_ip stays idempotent."""
    router.add('GET', '/cmdb/firewall/policy',
               FakeResponse(payload={'results': [], 'matched_count': 0}))
    router.add('GET', '/address/FSR-BLOCK-203_0_113_77',
               FakeResponse(payload={'results': {'subnet': '203.0.113.77 255.255.255.255'}}))
    router.add('GET', '/cmdb/firewall/policy',
               FakeResponse(payload={'results': [], 'matched_count': 0}))
    router.add('DELETE', '/address/FSR-BLOCK-203_0_113_77',
               FakeResponse(status=404, payload=NOT_FOUND))

    result = ops.operations['unblock_ip'](config, {'sn': SN, 'ip': '203.0.113.77'})
    assert result['removed_policies'] == []
    assert result['address_removed'] is False
    assert result['address_retained_reason'] is None


def test_block_ip_rejects_bad_direction(ops, config, connector_error):
    with pytest.raises(connector_error):
        ops.operations['block_ip'](config, {'sn': SN, 'ip': '203.0.113.77', 'direction': 'sideways'})


def test_block_ip_rejects_non_ip(ops, config, connector_error):
    with pytest.raises(connector_error):
        ops.operations['block_ip'](config, {'sn': SN, 'ip': 'example.com'})


def test_block_ip_rejects_existing_name_other_subnet(ops, config, connector_error, router):
    addr_name = 'FSR-BLOCK-203_0_113_77'
    router.add('GET', '/address/' + addr_name,
               FakeResponse(payload={'results': {'subnet': '198.51.100.1 255.255.255.255'}}))
    with pytest.raises(connector_error) as err:
        ops.operations['block_ip'](config, {'sn': SN, 'ip': '203.0.113.77'})
    assert 'already exists' in str(err.value)


def test_block_ip_move_failure_raises_with_state(ops, config, connector_error, router,
                                                 monkeypatch):
    addr_name = 'FSR-BLOCK-203_0_113_77'
    initial = {'results': [policy(1, 'Home-to-Internet')], 'matched_count': 1}
    created = _created_list([policy(1, 'Home-to-Internet')], addr_name, 'INBOUND')
    _shorten_retries(monkeypatch, ops)
    router.add('GET', '/address/' + addr_name, FakeResponse(status=404, payload=NOT_FOUND))
    router.add('POST', '/cmdb/firewall/address', FakeResponse(payload={}))
    router.add('GET', '/cmdb/firewall/policy', FakeResponse(payload=initial))
    router.add('POST', '/cmdb/firewall/policy',
               FakeResponse(payload={'results': {'policyid': 99}}))
    router.add('GET', '/cmdb/firewall/policy', FakeResponse(payload=created))
    router.add('PUT', '/cmdb/firewall/policy/99', FakeResponse(payload={}))
    router.add('GET', '/cmdb/firewall/policy', FakeResponse(payload=created),
               FakeResponse(payload=created))  # move did not stick
    with pytest.raises(connector_error) as err:
        ops.operations['block_ip'](config, {'sn': SN, 'ip': '203.0.113.77'})
    assert 'unblock_ip' in str(err.value)


def test_block_ip_both_directions_moves_each_to_top(ops, config, router):
    addr_name = 'FSR-BLOCK-203_0_113_77'
    initial = {'results': [policy(1, 'Home-to-Internet')], 'matched_count': 1}
    after_in = {'results': [policy(99, addr_name + '-INBOUND'), policy(1, 'Home-to-Internet')],
                'matched_count': 2}
    after_out = {'results': [policy(100, addr_name + '-OUTBOUND'), policy(99, addr_name + '-INBOUND'),
                             policy(1, 'Home-to-Internet')], 'matched_count': 3}
    router.add('GET', '/address/' + addr_name, FakeResponse(status=404, payload=NOT_FOUND))
    router.add('POST', '/cmdb/firewall/address', FakeResponse(payload={}))
    # GET policy sequence: pre-loop, move-read IN, verify IN, refresh, move-read OUT,
    # verify OUT, refresh. Each move-read already shows the policy created in that
    # step (the connector polls until the proxy's read-after-write view catches up).
    created_in = _created_list([policy(1, 'Home-to-Internet')], addr_name, 'INBOUND')
    created_out = {'results': [policy(99, addr_name + '-INBOUND'), policy(1, 'Home-to-Internet'),
                               policy(100, addr_name + '-OUTBOUND')], 'matched_count': 3}
    router.add('GET', '/cmdb/firewall/policy',
               FakeResponse(payload=initial), FakeResponse(payload=created_in),
               FakeResponse(payload=after_in), FakeResponse(payload=after_in),
               FakeResponse(payload=created_out), FakeResponse(payload=after_out),
               FakeResponse(payload=after_out))
    router.add('POST', '/cmdb/firewall/policy', FakeResponse(payload={'results': {'policyid': 99}}),
               FakeResponse(payload={'results': {'policyid': 100}}))
    router.add('PUT', '/cmdb/firewall/policy/99', FakeResponse(payload={}))
    router.add('PUT', '/cmdb/firewall/policy/100', FakeResponse(payload={}))

    result = ops.operations['block_ip'](config, {'sn': SN, 'ip': '203.0.113.77'})

    moves = [c for c in api_calls(router) if c['method'] == 'PUT']
    assert [(m['url'].rsplit('/', 1)[-1], m['params']) for m in moves] == [
        ('99', {'action': 'move', 'before': 1}),
        ('100', {'action': 'move', 'before': 99}),
    ]
    assert [p['name'] for p in result['policies']] == [addr_name + '-INBOUND', addr_name + '-OUTBOUND']
    assert all(p['moved_to_top'] and p['position'] == 0 for p in result['policies'])


def test_block_ip_custom_interfaces_reach_the_policy_body(ops, config, router):
    addr_name = 'FSR-BLOCK-203_0_113_77'
    initial = {'results': [policy(1, 'Home-to-Internet')], 'matched_count': 1}
    created = _created_list([policy(1, 'Home-to-Internet')], addr_name, 'INBOUND')
    moved = {'results': [policy(99, addr_name + '-INBOUND'), policy(1, 'Home-to-Internet')],
             'matched_count': 2}
    router.add('GET', '/address/' + addr_name, FakeResponse(status=404, payload=NOT_FOUND))
    router.add('POST', '/cmdb/firewall/address', FakeResponse(payload={}))
    router.add('GET', '/cmdb/firewall/policy', FakeResponse(payload=initial))
    router.add('POST', '/cmdb/firewall/policy', FakeResponse(payload={'results': {'policyid': 99}}))
    router.add('GET', '/cmdb/firewall/policy', FakeResponse(payload=created))
    router.add('PUT', '/cmdb/firewall/policy/99', FakeResponse(payload={}))
    router.add('GET', '/cmdb/firewall/policy', FakeResponse(payload=moved),
               FakeResponse(payload=moved))
    ops.operations['block_ip'](config, {'sn': SN, 'ip': '203.0.113.77',
                                        'direction': 'inbound', 'srcintf': 'wan1, lan'})
    create_pol = [c for c in api_calls(router) if c['method'] == 'POST'
                  and c['url'].endswith('/policy')][0]
    assert create_pol['json']['srcintf'] == [{'name': 'wan1'}, {'name': 'lan'}]


# --- unblock_ip -----------------------------------------------------------


def test_unblock_ip_removes_policies_and_address(ops, config, router):
    addr_name = 'FSR-BLOCK-203_0_113_77'
    router.add('GET', '/cmdb/firewall/policy',
               FakeResponse(payload={'results': [policy(99, addr_name + '-INBOUND'),
                                                 policy(100, addr_name + '-OUTBOUND'),
                                                 policy(1, 'Home-to-Internet')],
                                     'matched_count': 3}))
    router.add('DELETE', '/cmdb/firewall/policy/99', FakeResponse(payload={'revision_changed': True}))
    router.add('DELETE', '/cmdb/firewall/policy/100', FakeResponse(payload={'revision_changed': True}))
    router.add('GET', '/cmdb/firewall/policy',
               FakeResponse(payload={'results': [policy(1, 'Home-to-Internet')],
                                     'matched_count': 1}))
    router.add('GET', '/address/' + addr_name,
               FakeResponse(payload={'results': {'subnet': '203.0.113.77 255.255.255.255'}}))
    router.add('DELETE', '/cmdb/firewall/address/' + addr_name,
               FakeResponse(payload={'revision_changed': True}))

    result = ops.operations['unblock_ip'](config, {'sn': SN, 'ip': '203.0.113.77'})

    assert result['removed_policies'] == [
        {'name': addr_name + '-INBOUND', 'policyid': 99},
        {'name': addr_name + '-OUTBOUND', 'policyid': 100},
    ]
    assert result['address_removed'] is True
    assert result['address_retained_reason'] is None
    deletes = [c for c in api_calls(router) if c['method'] == 'DELETE']
    assert [d['url'].rsplit('/', 1)[-1] for d in deletes] == ['99', '100', addr_name]


def test_unblock_ip_retains_address_when_foreign_policy_references_it(ops, config, router):
    addr_name = 'FSR-BLOCK-203_0_113_77'
    foreign = policy(7, 'user-made')
    foreign['srcaddr'] = [{'name': addr_name}]
    router.add('GET', '/cmdb/firewall/policy',
               FakeResponse(payload={'results': [policy(99, addr_name + '-INBOUND'), foreign],
                                     'matched_count': 2}))
    router.add('DELETE', '/cmdb/firewall/policy/99', FakeResponse(payload={}))
    router.add('GET', '/cmdb/firewall/policy',
               FakeResponse(payload={'results': [foreign], 'matched_count': 1}))
    router.add('GET', '/address/' + addr_name,
               FakeResponse(payload={'results': {'subnet': '203.0.113.77 255.255.255.255'}}))

    result = ops.operations['unblock_ip'](config, {'sn': SN, 'ip': '203.0.113.77'})

    assert result['removed_policies'] == [{'name': addr_name + '-INBOUND', 'policyid': 99}]
    assert result['address_removed'] is False
    assert 'user-made' in result['address_retained_reason']
    assert not [c for c in api_calls(router) if c['method'] == 'DELETE'
                and '/address/' in c['url']]


def test_unblock_ip_idempotent_when_absent(ops, config, router):
    router.add('GET', '/cmdb/firewall/policy',
               FakeResponse(payload={'results': [policy(1, 'Home-to-Internet')],
                                     'matched_count': 1}))
    router.add('GET', '/address/FSR-BLOCK-203_0_113_77',
               FakeResponse(status=404, payload=NOT_FOUND))

    result = ops.operations['unblock_ip'](config, {'sn': SN, 'ip': '203.0.113.77'})

    assert result['removed_policies'] == []
    assert result['address_removed'] is False
    assert result['address_retained_reason'] is None
    assert not [c for c in api_calls(router) if c['method'] == 'DELETE']


# --- quarantine (ban-IP) flow ---------------------------------------------


def banned_entry(ip, expiry=3600):
    return {'ip_address': ip, 'expiry': expiry, 'created': 1700000000, 'cause': 'ips'}


def test_quarantine_ip_sends_the_fortigatev2_wire_shape(ops, config, router):
    """The ban body is JSON-encoded but sent with a form-urlencoded
    Content-Type — the shape the FortiGate v2 connector proved live — and the
    Authorization header must survive the per-call content-type override."""
    router.add('GET', '/monitor/user/banned/select', FakeResponse(payload={'results': []}))
    router.add('POST', '/monitor/user/banned/add_users',
               FakeResponse(payload={'result': 1, 'status': 'success'}))
    router.add('GET', '/monitor/user/banned/select',
               FakeResponse(payload={'results': [banned_entry('203.0.113.77')]}))

    result = ops.operations['quarantine_ip'](config, {'sn': SN, 'ips': '203.0.113.77',
                                                      'time_to_live': '1 Hour'})

    select, post, confirm = api_calls(router)
    assert select['method'] == 'GET'
    assert select['url'] == fgt_url('api/v2/monitor/user/banned/select')
    assert select['params'] == {'vdom': 'root'}
    assert post['method'] == 'POST'
    assert post['url'] == fgt_url('api/v2/monitor/user/banned/add_users')
    assert post['headers']['Content-Type'] == 'application/x-www-form-urlencoded'
    assert post['headers']['Authorization'] == 'Bearer tok-123'
    assert json.loads(post['data']) == {'ip_addresses': ['203.0.113.77'],
                                        'expiry': 3600, 'src': 'ips'}
    assert result['quarantined'] == ['203.0.113.77']
    assert result['already_quarantined'] == []
    assert result['expiry_seconds'] == 3600


def test_quarantine_ip_reports_already_banned_without_posting(ops, config, router):
    router.add('GET', '/monitor/user/banned/select',
               FakeResponse(payload={'results': [banned_entry('203.0.113.77')]}))

    result = ops.operations['quarantine_ip'](config, {'sn': SN, 'ips': '203.0.113.77'})

    assert result['already_quarantined'] == ['203.0.113.77']
    assert result['quarantined'] == []
    assert not [c for c in api_calls(router) if c['method'] == 'POST']


def test_quarantine_ip_batch_and_custom_duration(ops, config, router):
    router.add('GET', '/monitor/user/banned/select', FakeResponse(payload={'results': []}))
    router.add('POST', '/monitor/user/banned/add_users', FakeResponse(payload={}))
    router.add('GET', '/monitor/user/banned/select', FakeResponse(payload={'results': [
        banned_entry('203.0.113.77'), banned_entry('203.0.113.78')]}))

    result = ops.operations['quarantine_ip'](config, {
        'sn': SN, 'ips': '203.0.113.77, 203.0.113.78',
        'time_to_live': 'Custom Time', 'duration': 45})
    post = [c for c in api_calls(router) if c['method'] == 'POST'][0]
    assert json.loads(post['data']) == {'ip_addresses': ['203.0.113.77', '203.0.113.78'],
                                        'expiry': 45, 'src': 'ips'}
    assert result['quarantined'] == ['203.0.113.77', '203.0.113.78']


def test_quarantine_ip_accepts_a_list_param(ops, config, router):
    router.add('GET', '/monitor/user/banned/select', FakeResponse(payload={'results': []}))
    router.add('POST', '/monitor/user/banned/add_users',
               FakeResponse(payload={}))
    router.add('GET', '/monitor/user/banned/select',
               FakeResponse(payload={'results': [banned_entry('203.0.113.9')]}))

    result = ops.operations['quarantine_ip'](config, {'sn': SN, 'ips': ['203.0.113.9']})
    assert result['quarantined'] == ['203.0.113.9']


def test_quarantine_ip_never_expires_sends_zero(ops, config, router):
    router.add('GET', '/monitor/user/banned/select', FakeResponse(payload={'results': []}))
    router.add('POST', '/monitor/user/banned/add_users', FakeResponse(payload={}))
    router.add('GET', '/monitor/user/banned/select',
               FakeResponse(payload={'results': [banned_entry('203.0.113.77', 0)]}))

    ops.operations['quarantine_ip'](config, {'sn': SN, 'ips': '203.0.113.77',
                                             'time_to_live': 'Never'})
    post = [c for c in api_calls(router) if c['method'] == 'POST'][0]
    assert json.loads(post['data'])['expiry'] == 0


def test_quarantine_ip_rejects_invalid_input(ops, config, connector_error, router):
    with pytest.raises(connector_error):
        ops.operations['quarantine_ip'](config, {'sn': SN, 'ips': '999.1.1.1'})
    with pytest.raises(connector_error):
        ops.operations['quarantine_ip'](config, {'sn': SN, 'ips': '203.0.113.0/24'})
    with pytest.raises(connector_error):
        ops.operations['quarantine_ip'](config, {'sn': SN, 'ips': '203.0.113.77',
                                                 'time_to_live': 'Fortnight'})
    with pytest.raises(connector_error):
        ops.operations['quarantine_ip'](config, {'sn': SN, 'ips': '203.0.113.77',
                                                 'time_to_live': 'Custom Time'})
    with pytest.raises(connector_error):
        ops.operations['quarantine_ip'](config, {'sn': SN, 'ips': '203.0.113.77',
                                                 'time_to_live': 'Custom Time', 'duration': -5})
    with pytest.raises(connector_error):
        ops.operations['quarantine_ip'](config, {'sn': SN})
    assert api_calls(router) == []


def test_unquarantine_ip_clears_only_banned_addresses(ops, config, router):
    router.add('GET', '/monitor/user/banned/select',
               FakeResponse(payload={'results': [banned_entry('203.0.113.77')]}))
    router.add('POST', '/monitor/user/banned/clear_users', FakeResponse(payload={'status': 'success'}))
    router.add('GET', '/monitor/user/banned/select', FakeResponse(payload={'results': []}))

    result = ops.operations['unquarantine_ip'](config, {'sn': SN,
                                                        'ips': '203.0.113.77, 203.0.113.78'})
    post = [c for c in api_calls(router) if c['method'] == 'POST'][0]
    assert post['url'] == fgt_url('api/v2/monitor/user/banned/clear_users')
    assert json.loads(post['data']) == {'ip_addresses': ['203.0.113.77']}
    assert result['released'] == ['203.0.113.77']
    assert result['not_banned'] == ['203.0.113.78']
    assert result['still_banned'] == []


def test_unquarantine_ip_without_bans_makes_no_write(ops, config, router):
    router.add('GET', '/monitor/user/banned/select', FakeResponse(payload={'results': []}))

    result = ops.operations['unquarantine_ip'](config, {'sn': SN, 'ips': '203.0.113.77'})
    assert result['not_banned'] == ['203.0.113.77']
    assert not [c for c in api_calls(router) if c['method'] == 'POST']


def test_list_banned_ips_passes_entries_through(ops, config, router):
    router.add('GET', '/monitor/user/banned/select',
               FakeResponse(payload={'results': [banned_entry('203.0.113.77'),
                                                 banned_entry('203.0.113.78', 0)]}))

    result = ops.operations['list_banned_ips'](config, {'sn': SN})
    assert result['count'] == 2
    assert result['banned'][0]['ip_address'] == '203.0.113.77'
    assert result['banned'][1]['expiry'] == 0
