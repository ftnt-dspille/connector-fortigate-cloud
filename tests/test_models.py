"""Unit tests for the typed contracts (models.py): parameter validation and
its error wording, the vendor-response models, and the result shapes."""

from __future__ import annotations

import sys

import pytest


@pytest.fixture
def models(ops):
    return sys.modules['fsr_test_pkg_fortigate_cloud.models']


def fail(models, connector_error, model, params):
    with pytest.raises(connector_error) as err:
        models.parse_params(getattr(models, model), params)
    return str(err.value)


# --- parameters ------------------------------------------------------------

@pytest.mark.parametrize('value', [None, '', '   '])
def test_blank_required_param_reads_as_required(models, connector_error, value):
    assert fail(models, connector_error, 'SnParams', {'sn': value}) == "'sn' is a required parameter"


def test_missing_required_param_reads_as_required(models, connector_error):
    assert fail(models, connector_error, 'SnParams', {}) == "'sn' is a required parameter"


def test_every_problem_is_reported_not_just_the_first(models, connector_error):
    message = fail(models, connector_error, 'BlockIpParams', {'direction': 'sideways'})
    assert "'sn' is a required parameter" in message
    assert "'ip' is a required parameter" in message
    assert "'direction' must be one of inbound, outbound or both; got 'sideways'" in message


def test_text_params_are_trimmed_and_numbers_become_text(models):
    assert models.parse_params(models.SnParams, {'sn': '  FGT1 '}).sn == 'FGT1'
    assert models.parse_params(models.SnParams, {'sn': 12345}).sn == '12345'


def test_identifiers_keep_their_wire_type(models):
    p = models.parse_params(models.ReportScheduleParams, {'sn': 'S', 'oid': 7})
    assert p.oid == 7 and isinstance(p.oid, int)
    p = models.parse_params(models.ReportScheduleParams, {'sn': 'S', 'oid': ' 7 '})
    assert p.oid == '7'


def test_unknown_keys_are_ignored(models):
    assert models.parse_params(models.SnParams, {'sn': 'S', 'surprise': 1}).sn == 'S'


def test_list_limit_is_capped_and_offset_only_sent_when_set(models):
    assert models.parse_params(models.ListParams, {'sn': 'S'}).query == {'limit': 100}
    assert models.parse_params(models.ListParams, {'sn': 'S', 'limit': '5000', 'offset': '40'}).query == {
        'limit': 1000, 'offset': 40}
    blank = models.parse_params(models.ListParams, {'sn': 'S', 'limit': '', 'offset': ''})
    assert blank.query == {'limit': 100}


def test_non_integer_limit_names_the_value(models, connector_error):
    assert fail(models, connector_error, 'ListParams', {'sn': 'S', 'limit': 'many'}) == (
        "'limit' must be an integer; got 'many'")


def test_enabling_management_requires_the_password(models, connector_error):
    message = fail(models, connector_error, 'UpdateDeviceManagementParams', {'sn': 'S', 'management': True})
    assert 'admin' in message and 'Password' in message
    ok = models.parse_params(models.UpdateDeviceManagementParams, {'sn': 'S', 'management': False})
    assert ok.management is False


def test_block_ip_defaults_and_derived_values(models):
    p = models.parse_params(models.BlockIpParams, {'sn': 'S', 'ip': '203.0.113.0/24'})
    assert p.direction == 'both' and p.directions == ['inbound', 'outbound']
    assert p.srcintf == ['any'] and p.dstintf == ['any']
    assert p.subnet == '203.0.113.0 255.255.255.0'
    assert p.object_name == 'FSR-BLOCK-203_0_113_0-24'


def test_block_ip_interface_lists_and_direction_case(models):
    p = models.parse_params(models.BlockIpParams, {
        'sn': 'S', 'ip': '203.0.113.9', 'direction': ' Inbound ', 'srcintf': 'wan1, wan2', 'dstintf': ''})
    assert p.direction == 'inbound' and p.srcintf == ['wan1', 'wan2'] and p.dstintf == ['any']


def test_block_ip_rejects_ipv6_and_junk(models, connector_error):
    assert 'Only IPv4' in fail(models, connector_error, 'BlockIpParams', {'sn': 'S', 'ip': '2001:db8::1'})
    assert 'IPv4 address or CIDR' in fail(models, connector_error, 'BlockIpParams', {'sn': 'S', 'ip': 'nope'})


def test_quarantine_expiry_resolution(models, connector_error):
    base = {'sn': 'S', 'ips': '203.0.113.1, 203.0.113.2'}
    p = models.parse_params(models.QuarantineParams, base)
    assert p.ips == ['203.0.113.1', '203.0.113.2'] and p.expiry_seconds == 3600 and p.vdom == 'root'
    assert models.parse_params(models.QuarantineParams, {**base, 'time_to_live': 'Never'}).expiry_seconds == 0
    custom = models.parse_params(models.QuarantineParams,
                                 {**base, 'time_to_live': 'Custom Time', 'duration': '90'})
    assert custom.expiry_seconds == 90
    assert "'duration' is required" in fail(models, connector_error, 'QuarantineParams',
                                            {**base, 'time_to_live': 'Custom Time'})
    assert 'must be zero' in fail(models, connector_error, 'QuarantineParams',
                                  {**base, 'time_to_live': 'Custom Time', 'duration': -1})
    assert 'time_to_live' in fail(models, connector_error, 'QuarantineParams',
                                  {**base, 'time_to_live': 'Fortnight'})


def test_ban_list_rejects_non_ipv4(models, connector_error):
    assert 'IPv4 addresses separated by commas' in fail(
        models, connector_error, 'UnquarantineParams', {'sn': 'S', 'ips': '203.0.113.1,nope'})
    assert 'Only IPv4' in fail(models, connector_error, 'UnquarantineParams', {'sn': 'S', 'ips': '::1'})


def test_fos_api_call_params(models, connector_error):
    p = models.parse_params(models.FosApiCallParams, {
        'sn': 'S', 'method': 'post', 'fos_api_path': '/api/v2/x', 'query_parameters': '{"a": 1}',
        'payload': '{"b": 2}'})
    assert (p.method, p.fos_api_path) == ('POST', 'api/v2/x')
    assert (p.query_parameters, p.payload) == ({'a': 1}, {'b': 2})
    assert "'payload' must be valid JSON" in fail(
        models, connector_error, 'FosApiCallParams', {'sn': 'S', 'fos_api_path': 'x', 'payload': '{nope'})


# --- vendor responses ------------------------------------------------------

@pytest.mark.parametrize('body,expected', [
    ({'mkey': 5, 'status': 'success'}, 5),                      # the shape the proxy really returns
    ({'results': {'policyid': 6}}, 6),                          # nested object
    ({'results': [{'policyid': 7}]}, 7),                        # nested list
    ({'mkey': 'name-key'}, 'name-key'),
    ({'status': 'success'}, None),
])
def test_created_id_reads_every_known_shape(models, body, expected):
    assert models.ProxyReply.model_validate(body).created_id == expected


def test_vendor_models_keep_unknown_fields(models):
    reply = models.parse_reply(models.PolicyList, {
        'results': [{'policyid': 1, 'name': 'p', 'q_origin_key': 1, 'srcaddr': None}], 'vdom': 'root'}, 'x')
    assert reply.results[0].policyid == 1 and reply.results[0].srcaddr == []
    assert reply.results[0].model_dump()['q_origin_key'] == 1
    assert reply.model_dump()['vdom'] == 'root'


@pytest.mark.parametrize('body', ['<html>gateway timeout</html>', ['a', 'list'], None])
def test_non_object_vendor_body_fails_loudly(models, connector_error, body):
    with pytest.raises(connector_error, match='Unexpected response while reading the firewall policy list'):
        models.parse_reply(models.PolicyList, body, 'the firewall policy list')


def test_mistyped_vendor_field_fails_loudly(models, connector_error):
    with pytest.raises(connector_error, match='Unexpected response shape while reading'):
        bad = {'results': [{'policyid': 'not-a-number'}]}
        models.parse_reply(models.PolicyList, bad, 'the firewall policy list')


def test_banned_entries_accept_both_envelopes(models):
    entry = {'ip_address': '203.0.113.5', 'expiry': 60, 'cause': 'admin'}
    for body in ({'results': [entry]}, [entry], {'results': {'results': [entry]}}):
        parsed = models.parse_banned_entries(body)
        assert [e.ip_address for e in parsed] == ['203.0.113.5']
        assert parsed[0].model_dump() == entry
    assert models.parse_banned_entries({'results': None}) == []


# --- results ---------------------------------------------------------------

def test_results_dump_only_what_was_set(models):
    result = models.BlockResult(
        device='S', ip='203.0.113.9',
        address=models.AddressOutcome(name='A', reused=True),
        policies=[models.PolicyOutcome(name='P', policyid=3, created=False)],
    ).to_dict()
    assert result == {'device': 'S', 'ip': '203.0.113.9', 'address': {'name': 'A', 'reused': True},
                      'policies': [{'name': 'P', 'policyid': 3, 'created': False}]}


def test_unblock_result_keeps_an_explicit_none_reason(models):
    result = models.UnblockResult(
        device='S', ip='203.0.113.9', address_name='A', removed_policies=[], address_removed=True,
        address_retained_reason=None).to_dict()
    assert result['address_retained_reason'] is None


def test_config_hides_the_password_and_defaults(models):
    cfg = models.ConnectorConfig.model_validate({'api_id': 'x', 'password': 'hunter2', 'region': ''})
    assert cfg.region == 'Global' and cfg.client_id == 'fortigatecloud' and cfg.verify_ssl is True
    assert 'hunter2' not in repr(cfg) and cfg.password.get_secret_value() == 'hunter2'
