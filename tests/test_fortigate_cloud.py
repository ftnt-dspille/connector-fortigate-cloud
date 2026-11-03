"""Unit tests for the FortiGate Cloud connector.

Every outbound HTTP call is intercepted, so these assert on the *request the
connector builds* — the URL shape, method, and body — rather than on any live
response. The request shapes asserted here were confirmed against the live
FortiGate Cloud API and the published v25.3 spec.
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


@pytest.fixture
def calls(monkeypatch, rest_mod):
    """Capture every outbound request; auto-answer the token grant."""
    recorded = []

    def fake_post(url, **kw):
        recorded.append({'method': 'POST', 'url': url, **kw})
        return FakeResponse(payload={
            'status': 'success', 'access_token': 'tok-123',
            'refresh_token': 'refresh-tok-123', 'expires_in': 3660,
        })

    def fake_request(method=None, url=None, **kw):
        recorded.append({'method': method, 'url': url, **kw})
        return FakeResponse(payload={'result': 'ok'})

    monkeypatch.setattr(rest_mod.requests, 'post', fake_post)
    monkeypatch.setattr(rest_mod.requests, 'request', fake_request)
    return recorded


def api_calls(calls):
    """The non-token calls."""
    return [c for c in calls if 'oauth' not in c['url']]


# --- authentication -------------------------------------------------------

def test_token_url_has_trailing_slash(ops, config, calls):
    """Without the trailing slash the IAM endpoint 301s and the redirect drops
    the POST body, which surfaces as a misleading 400 'Request is not valid JSON'."""
    ops.operations['get_devices'](config, {})
    token_call = calls[0]
    assert token_call['url'] == 'https://customerapiauth.fortinet.com/api/v1/oauth/token/'
    assert token_call['url'].endswith('/')


def test_token_grant_body(ops, config, calls):
    ops.operations['get_devices'](config, {})
    assert calls[0]['json'] == {
        'username': config['api_id'],
        'password': config['password'],
        'client_id': 'fortigatecloud',
        'grant_type': 'password',
    }


def test_bearer_token_applied(ops, config, calls):
    ops.operations['get_devices'](config, {})
    assert api_calls(calls)[0]['headers']['Authorization'] == 'Bearer tok-123'


def test_token_is_cached_across_operations(ops, config, calls):
    ops.operations['get_devices'](config, {})
    ops.operations['get_device'](config, {'sn': 'FGT60D4615007890'})
    ops.operations['get_devices'](config, {})
    token_calls = [c for c in calls if 'oauth' in c['url']]
    assert len(token_calls) == 1, 'token must be reused; re-auth per call risks account lockout'


def test_invalid_grant_raises_lockout_warning(ops, config, monkeypatch, rest_mod, connector_error):
    monkeypatch.setattr(rest_mod.requests, 'post', lambda url, **kw: FakeResponse(
        status=400, payload={'error': 'invalid_grant', 'error_description': 'nope'}))
    with pytest.raises(connector_error, match='invalid_grant'):
        ops.operations['get_devices'](config, {})


def _token_cache(ops):
    """The token cache of the module instance whose code actually runs.

    conftest reloads the connector modules per fixture, so rest_mod's module
    object can differ from the one behind ops; the running code's globals are
    the only reliable handle.
    """
    return ops.MakeRestApiCall._post_token.__globals__['_TOKEN_CACHE']


def test_password_grant_stores_the_refresh_token(ops, config, calls, rest_mod):
    ops.operations['get_devices'](config, {})
    entry = next(iter(_token_cache(ops).values()))
    assert entry['refresh_token'] == 'refresh-tok-123'


def test_expired_token_renews_with_a_refresh_grant_without_the_password(ops, config, calls, rest_mod):
    """The IAM endpoint issues a refresh_token with every grant; renewing with
    it sends no account password, which keeps playbook runs away from the
    invalid_grant lockout that repeated password grants can trigger."""
    ops.operations['get_devices'](config, {})  # prime the cache with a grant
    next(iter(_token_cache(ops).values()))['expires_at'] = 0  # force expiry
    ops.operations['get_devices'](config, {})
    grants = [c for c in calls if 'oauth' in c['url']]
    assert len(grants) == 2
    assert grants[1]['json'] == {
        'client_id': 'fortigatecloud',
        'grant_type': 'refresh_token',
        'refresh_token': 'refresh-tok-123',
    }


def test_rejected_refresh_falls_back_to_a_password_grant(ops, config, calls, rest_mod, monkeypatch):
    ops.operations['get_devices'](config, {})  # prime the cache with a grant
    next(iter(_token_cache(ops).values()))['expires_at'] = 0

    def fake_post(url, **kw):
        calls.append({'method': 'POST', 'url': url, **kw})
        if kw['json']['grant_type'] == 'refresh_token':
            return FakeResponse(status=400, payload={'error': 'invalid_grant',
                                                     'error_description': 'token expired'})
        return FakeResponse(payload={'status': 'success', 'access_token': 'tok-2',
                                     'refresh_token': 'refresh-tok-2', 'expires_in': 3660})

    monkeypatch.setattr(rest_mod.requests, 'post', fake_post)
    ops.operations['get_devices'](config, {})
    grants = [c for c in calls if 'oauth' in c['url']]
    assert grants[1]['json']['grant_type'] == 'refresh_token'
    assert grants[2]['json']['grant_type'] == 'password'
    entry = next(iter(_token_cache(ops).values()))
    assert entry['access_token'] == 'tok-2'
    assert entry['refresh_token'] == 'refresh-tok-2'


def test_a_rejected_token_is_dropped_so_the_next_call_re_authenticates(
    ops, config, calls, rest_mod, monkeypatch, connector_error
):
    ops.operations['get_devices'](config, {})  # prime the cache
    assert _token_cache(ops)

    def fake_request(method=None, url=None, **kw):
        calls.append({'method': method, 'url': url, **kw})
        return FakeResponse(status=401, payload={'error': 'invalid_client'})

    monkeypatch.setattr(rest_mod.requests, 'request', fake_request)
    with pytest.raises(connector_error):
        ops.operations['get_devices'](config, {})
    assert not _token_cache(ops), 'a rejected token must not survive in the cache'


# --- base URL / region ----------------------------------------------------

@pytest.mark.parametrize('region,host', [
    ('Global', 'https://api.fortigate.forticloud.com'),
    ('US', 'https://usapi.fortigate.forticloud.com'),
    ('EU', 'https://euapi.fortigate.forticloud.com'),
    ('Japan', 'https://jpapi.fortigate.forticloud.com'),
])
def test_region_maps_to_host(ops, config, calls, region, host):
    config['region'] = region
    ops.operations['get_devices'](config, {})
    assert api_calls(calls)[0]['url'] == host + '/forticloudapi/v1/devices'


def test_base_path_is_forticloudapi_v1(ops, config, calls):
    """The spec's servers block (/forticloudapi/v1) and its /v1-prefixed paths do
    not concatenate. /v1/devices without the prefix serves the web app, not the API."""
    ops.operations['get_devices'](config, {})
    url = api_calls(calls)[0]['url']
    assert '/forticloudapi/v1/devices' in url
    assert '/forticloudapi/v1/v1/' not in url


def test_unknown_region_raises(ops, config, connector_error):
    config['region'] = 'Mars'
    with pytest.raises(connector_error, match='Unknown region'):
        ops.operations['get_devices'](config, {})


def test_server_url_overrides_region(ops, config, calls):
    config['server_url'] = 'https://custom.example.com'
    ops.operations['get_devices'](config, {})
    assert api_calls(calls)[0]['url'].startswith('https://custom.example.com/forticloudapi/v1')


def test_custom_region_requires_server_url(ops, config, connector_error):
    config['region'] = 'Custom'
    with pytest.raises(connector_error, match='Server URL'):
        ops.operations['get_devices'](config, {})


def test_custom_region_uses_the_server_url(ops, config, calls):
    config['region'] = 'Custom'
    config['server_url'] = 'https://custom.example.com'
    ops.operations['get_devices'](config, {})
    assert api_calls(calls)[0]['url'].startswith('https://custom.example.com/forticloudapi/v1')


def test_bare_host_gets_https_scheme(ops, config, calls):
    config['server_url'] = 'custom.example.com'
    ops.operations['get_devices'](config, {})
    assert api_calls(calls)[0]['url'].startswith('https://custom.example.com/')


def test_http_scheme_is_not_double_wrapped(ops, config, calls):
    """Guards the bug fixed in the Asset Management connector, where a
    startswith('http') check rewrote http:// into https://http://."""
    config['server_url'] = 'http://custom.example.com'
    ops.operations['get_devices'](config, {})
    assert api_calls(calls)[0]['url'].startswith('http://custom.example.com/')


# --- device operations ----------------------------------------------------

def test_get_devices_passes_pagination(ops, config, calls):
    ops.operations['get_devices'](config, {'limit': 10, 'offset': 0, 'sort': 'sn'})
    call = api_calls(calls)[0]
    assert call['method'] == 'GET'
    assert call['params'] == {'limit': 10, 'offset': 0, 'sort': 'sn'}


def test_get_devices_omits_blank_pagination(ops, config, calls):
    ops.operations['get_devices'](config, {'limit': '', 'offset': None})
    assert api_calls(calls)[0]['params'] == {}


def test_get_device_by_sn(ops, config, calls):
    ops.operations['get_device'](config, {'sn': 'FGT60D4615007890'})
    call = api_calls(calls)[0]
    assert call['url'].endswith('/devices/FGT60D4615007890')
    assert call['method'] == 'GET'


def test_get_device_requires_sn(ops, config, calls, connector_error):
    with pytest.raises(connector_error, match='sn'):
        ops.operations['get_device'](config, {'sn': '  '})


def test_add_device_body(ops, config, calls):
    ops.operations['add_device'](config, {'device_key': 'KEY-123'})
    call = api_calls(calls)[0]
    assert call['method'] == 'POST'
    assert call['url'].endswith('/devices')
    assert call['json'] == {'deviceKey': 'KEY-123'}


def test_enable_management_sends_credentials(ops, config, calls):
    ops.operations['update_device_management'](config, {
        'sn': 'FGT1', 'management': True, 'username': 'admin', 'password': 'pw',
        'force_password_change': True,
    })
    call = api_calls(calls)[0]
    assert call['method'] == 'PUT'
    assert call['url'].endswith('/devices/FGT1/management')
    assert call['json'] == {
        'management': True, 'username': 'admin', 'password': 'pw', 'forcePasswordChange': True,
    }


def test_enable_management_without_password_raises(ops, config, calls, connector_error):
    """The API requires the FortiGate admin password to enable management."""
    with pytest.raises(connector_error, match='password'):
        ops.operations['update_device_management'](config, {'sn': 'FGT1', 'management': True})


def test_disable_management_needs_no_credentials(ops, config, calls):
    ops.operations['update_device_management'](config, {'sn': 'FGT1', 'management': False})
    assert api_calls(calls)[0]['json'] == {'management': False}


def test_report_schedule_crud_urls(ops, config, calls):
    ops.operations['get_report_schedules'](config, {'sn': 'FGT1'})
    ops.operations['get_report_schedule'](config, {'sn': 'FGT1', 'oid': 506313})
    ops.operations['delete_report_schedule'](config, {'sn': 'FGT1', 'oid': 506313})
    urls = [(c['method'], c['url']) for c in api_calls(calls)]
    assert urls[0][1].endswith('/devices/FGT1/reportschedules')
    assert urls[1][1].endswith('/devices/FGT1/reportschedules/506313')
    assert urls[2] == ('DELETE', urls[2][1])
    assert urls[2][1].endswith('/devices/FGT1/reportschedules/506313')


def test_add_report_schedule_maps_camel_case(ops, config, calls):
    ops.operations['add_report_schedule'](config, {
        'sn': 'FGT1', 'config_oid': 1218, 'schedule_type': 'daily', 'email_flag': False,
    })
    call = api_calls(calls)[0]
    assert call['method'] == 'POST'
    assert call['json'] == {'configOid': 1218, 'scheduleType': 'daily', 'emailFlag': False}


def test_add_report_schedule_requires_config_oid(ops, config, calls, connector_error):
    with pytest.raises(connector_error, match='config_oid'):
        ops.operations['add_report_schedule'](config, {'sn': 'FGT1'})


def test_auto_backup_setting_urls_and_body(ops, config, calls):
    ops.operations['get_auto_backup_setting'](config, {'sn': 'FGT1'})
    ops.operations['update_auto_backup_setting'](config, {
        'sn': 'FGT1', 'enable': True, 'backup_option': 'PERSESSION', 'alert': True,
        'alert_lang': 'en', 'alert_emails': 'soc@example.com',
    })
    get_call, put_call = api_calls(calls)
    assert get_call['url'].endswith('/devices/FGT1/configbackups/setting')
    assert put_call['method'] == 'PUT'
    assert put_call['json'] == {
        'enable': True, 'backupOption': 'PERSESSION', 'alert': True,
        'alertLang': 'en', 'alertEmails': 'soc@example.com',
    }


# --- FortiOS proxy --------------------------------------------------------

def test_fos_api_call_builds_proxy_url(ops, config, calls):
    ops.operations['fos_api_call'](config, {
        'sn': 'FGT60D4615007890', 'method': 'GET',
        'fos_api_path': 'api/v2/monitor/license/status',
    })
    call = api_calls(calls)[0]
    assert call['url'].endswith('/forticloudapi/v1/fgt/FGT60D4615007890/api/v2/monitor/license/status')
    assert call['method'] == 'GET'


def test_fos_api_call_strips_leading_slash(ops, config, calls):
    ops.operations['fos_api_call'](config, {
        'sn': 'FGT1', 'fos_api_path': '/api/v2/monitor/license/status',
    })
    assert '/fgt/FGT1/api/v2/' in api_calls(calls)[0]['url']
    assert '/fgt/FGT1//api' not in api_calls(calls)[0]['url']


def test_fos_api_call_parses_json_string_params(ops, config, calls):
    ops.operations['fos_api_call'](config, {
        'sn': 'FGT1', 'fos_api_path': 'api/v2/cmdb/firewall/policy',
        'query_parameters': '{"vdom": "root"}',
    })
    assert api_calls(calls)[0]['params'] == {'vdom': 'root'}


def test_fos_api_call_rejects_bad_json_params(ops, config, calls, connector_error):
    with pytest.raises(connector_error, match='query_parameters'):
        ops.operations['fos_api_call'](config, {
            'sn': 'FGT1', 'fos_api_path': 'api/v2/x', 'query_parameters': 'not json',
        })


def test_fos_api_call_rejects_bad_method(ops, config, calls, connector_error):
    with pytest.raises(connector_error, match='method'):
        ops.operations['fos_api_call'](config, {
            'sn': 'FGT1', 'fos_api_path': 'api/v2/x', 'method': 'PATCH',
        })


def test_fos_api_call_requires_path(ops, config, calls, connector_error):
    with pytest.raises(connector_error, match='fos_api_path'):
        ops.operations['fos_api_call'](config, {'sn': 'FGT1'})


def test_fos_api_call_posts_payload(ops, config, calls):
    ops.operations['fos_api_call'](config, {
        'sn': 'FGT1', 'method': 'POST', 'fos_api_path': 'api/v2/cmdb/system/admin',
        'payload': '{"name": "test"}',
    })
    call = api_calls(calls)[0]
    assert call['method'] == 'POST'
    assert call['json'] == {'name': 'test'}


# --- generic call + errors ------------------------------------------------

def test_generic_api_call_normalises_endpoint(ops, config, calls):
    ops.operations['generic_api_call'](config, {'method': 'GET', 'endpoint': 'devices'})
    assert api_calls(calls)[0]['url'].endswith('/forticloudapi/v1/devices')


def test_error_status_raises_with_detail(ops, config, monkeypatch, rest_mod, connector_error):
    monkeypatch.setattr(rest_mod.requests, 'post', lambda url, **kw: FakeResponse(
        payload={'status': 'success', 'access_token': 't', 'expires_in': 3660}))
    monkeypatch.setattr(rest_mod.requests, 'request', lambda **kw: FakeResponse(
        status=401, payload={'error': 'invalid_client'}))
    with pytest.raises(connector_error, match='Admin permissions for FortiGate Cloud'):
        ops.operations['get_devices'](config, {})


def test_rate_limit_message(ops, config, monkeypatch, rest_mod, connector_error):
    monkeypatch.setattr(rest_mod.requests, 'post', lambda url, **kw: FakeResponse(
        payload={'status': 'success', 'access_token': 't', 'expires_in': 3660}))
    monkeypatch.setattr(rest_mod.requests, 'request', lambda **kw: FakeResponse(
        status=429, payload={}))
    with pytest.raises(connector_error, match='Rate limit'):
        ops.operations['get_devices'](config, {})


# --- health check ---------------------------------------------------------

def test_check_health_probes_device_api(ops, config, calls):
    """A token grant alone is not health: FortiGate Cloud issues a token to any
    valid FortiCloud identity but rejects it with 401 unless the IAM user holds
    Admin permissions for FortiGate Cloud."""
    assert ops._check_health(config) is True
    probe = api_calls(calls)[0]
    assert probe['url'].endswith('/forticloudapi/v1/devices')
    assert probe['params'] == {'limit': 1, 'offset': 0}


def test_check_health_fails_when_device_api_rejects_token(
    ops, config, monkeypatch, rest_mod, connector_error
):
    monkeypatch.setattr(rest_mod.requests, 'post', lambda url, **kw: FakeResponse(
        payload={'status': 'success', 'access_token': 't', 'expires_in': 3660}))
    monkeypatch.setattr(rest_mod.requests, 'request', lambda **kw: FakeResponse(
        status=401, payload={'error': 'invalid_client'}))
    with pytest.raises(connector_error):
        ops._check_health(config)


# --- info.json coherence --------------------------------------------------

def test_every_declared_operation_is_implemented(ops):
    import pathlib
    info = json.loads((pathlib.Path(__file__).resolve().parent.parent /
                       'fortigate-cloud' / 'info.json').read_text())
    declared = {o['operation'] for o in info['operations']}
    assert declared == set(ops.operations), 'info.json and operations dict disagree'


def test_every_operation_param_is_read_by_its_action(ops):
    """Each parameter declared in info.json must be consumed by the action, or it
    silently does nothing at runtime."""
    import inspect
    import pathlib
    info = json.loads((pathlib.Path(__file__).resolve().parent.parent /
                       'fortigate-cloud' / 'info.json').read_text())
    problems = []
    for op in info['operations']:
        src = inspect.getsource(ops.operations[op['operation']])
        for param in op['parameters']:
            if f"\"{param['name']}\"" not in src and f"'{param['name']}'" not in src:
                problems.append(f"{op['operation']}: {param['name']}")
    assert not problems, f"declared but unused parameters: {problems}"
