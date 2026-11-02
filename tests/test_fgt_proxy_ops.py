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
            'status': 'success', 'access_token': 'tok-123', 'expires_in': 3660,
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


def test_block_ip_fresh_inbound_flow(ops, config, router):
    addr_name = 'FSR-BLOCK-203_0_113_77'
    initial = {'results': [policy(1, 'Home-to-Internet')], 'matched_count': 1}
    moved = {'results': [policy(99, addr_name + '-INBOUND'), policy(1, 'Home-to-Internet')],
             'matched_count': 2}
    router.add('GET', '/address/' + addr_name, FakeResponse(status=404, payload=NOT_FOUND))
    router.add('POST', '/cmdb/firewall/address', FakeResponse(payload={'revision_changed': True}))
    router.add('GET', '/cmdb/firewall/policy', FakeResponse(payload=initial))
    router.add('POST', '/cmdb/firewall/policy',
               FakeResponse(payload={'results': {'policyid': 99}, 'revision_changed': True}))
    router.add('GET', '/cmdb/firewall/policy', FakeResponse(payload=initial))
    router.add('PUT', '/cmdb/firewall/policy/99', FakeResponse(payload={'revision_changed': True}))
    router.add('GET', '/cmdb/firewall/policy', FakeResponse(payload=moved))

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
    router.add('GET', '/cmdb/firewall/policy',
               FakeResponse(payload={'results': [policy(5, addr_name + '-INBOUND')],
                                     'matched_count': 1}))
    result = ops.operations['block_ip'](config, {'sn': SN, 'ip': '203.0.113.77',
                                                 'direction': 'inbound'})
    assert result['address'] == {'name': addr_name, 'reused': True}
    assert result['policies'] == [{'name': addr_name + '-INBOUND', 'policyid': 5, 'created': False}]
    # No POST and no move happened.
    assert not [c for c in api_calls(router) if c['method'] == 'POST']


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


def test_block_ip_move_failure_raises_with_state(ops, config, connector_error, router):
    addr_name = 'FSR-BLOCK-203_0_113_77'
    initial = {'results': [policy(1, 'Home-to-Internet')], 'matched_count': 1}
    router.add('GET', '/address/' + addr_name, FakeResponse(status=404, payload=NOT_FOUND))
    router.add('POST', '/cmdb/firewall/address', FakeResponse(payload={}))
    router.add('GET', '/cmdb/firewall/policy', FakeResponse(payload=initial))
    router.add('POST', '/cmdb/firewall/policy',
               FakeResponse(payload={'results': {'policyid': 99}}))
    router.add('GET', '/cmdb/firewall/policy', FakeResponse(payload=initial))
    router.add('PUT', '/cmdb/firewall/policy/99', FakeResponse(payload={}))
    router.add('GET', '/cmdb/firewall/policy', FakeResponse(payload=initial))  # move did not stick
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
    # verify OUT, refresh.
    router.add('GET', '/cmdb/firewall/policy',
               FakeResponse(payload=initial), FakeResponse(payload=initial),
               FakeResponse(payload=after_in), FakeResponse(payload=after_in),
               FakeResponse(payload=after_in), FakeResponse(payload=after_out),
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
    moved = {'results': [policy(99, addr_name + '-INBOUND'), policy(1, 'Home-to-Internet')],
             'matched_count': 2}
    router.add('GET', '/address/' + addr_name, FakeResponse(status=404, payload=NOT_FOUND))
    router.add('POST', '/cmdb/firewall/address', FakeResponse(payload={}))
    router.add('GET', '/cmdb/firewall/policy', FakeResponse(payload=initial))
    router.add('POST', '/cmdb/firewall/policy', FakeResponse(payload={'results': {'policyid': 99}}))
    router.add('GET', '/cmdb/firewall/policy', FakeResponse(payload=initial))
    router.add('PUT', '/cmdb/firewall/policy/99', FakeResponse(payload={}))
    router.add('GET', '/cmdb/firewall/policy', FakeResponse(payload=moved))
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
