"""Unit tests for the CLI script, script run and firmware upgrade operations.

Every outbound call is intercepted, so these assert on the requests the
connector builds (shapes captured from the product and verified live) and on
how run_script sequences scheduling, polling and output reads.
"""

from __future__ import annotations

import pytest
from test_fgt_proxy_ops import FakeResponse, api_calls, router  # noqa: F401

BASE = 'https://api.fortigate.forticloud.com/forticloudapi/v1'
SN = 'FGVMMLTM26024888'


@pytest.fixture
def clock(monkeypatch, ops):
    """A fake clock for the polling loop: sleeping advances time instantly."""

    class Clock:
        now = 1000.0

        def time(self):
            return self.now

        def sleep(self, seconds):
            self.now += seconds

    fake = Clock()
    # The fixtures reload the connector, so patch the module the operations
    # actually run in rather than whatever sys.modules holds now.
    monkeypatch.setitem(ops.operations['run_script'].__globals__, 'time', fake)
    return fake


def script(oid=42, name='probe'):
    return {'oid': oid, 'name': name, 'forticloudId': 1, 'deviceType': 'FortiGate'}


def task(oid, status='SUCCEED', name='probe', sn=SN, archive=5000):
    return {'oid': oid, 'scriptName': name, 'sn': sn, 'taskStatus': status,
            'scheduledTime': 4000, 'archiveTime': archive, 'message': 'ok. '}


def text(body):
    return FakeResponse(payload=None, text=body, content_type='text/plain')


# --- scripts -----------------------------------------------------------------

def test_list_scripts_defaults(ops, config, router):  # noqa: F811
    router.add('GET', '/scripts', FakeResponse(payload=[script()]))
    result = ops.operations['list_scripts'](config, {})
    call = api_calls(router)[0]
    assert call['url'] == BASE + '/scripts'
    assert call['params'] == {'manageable': 'false', 'includeContent': 'false'}
    assert result[0]['oid'] == 42 and result[0]['forticloudId'] == 1  # vendor fields pass through


def test_list_scripts_with_content_and_folder(ops, config, router):  # noqa: F811
    router.add('GET', '/scripts', FakeResponse(payload=[]))
    ops.operations['list_scripts'](config, {'include_content': True, 'folder': '3'})
    assert api_calls(router)[0]['params'] == {
        'manageable': 'false', 'includeContent': 'true', 'folder': 3}


def test_list_scripts_rejects_a_non_array_reply(ops, config, router, connector_error):  # noqa: F811
    router.add('GET', '/scripts', FakeResponse(payload={'error': 'x'}))
    with pytest.raises(connector_error, match='expected a JSON array'):
        ops.operations['list_scripts'](config, {})


def test_create_script_request_shape(ops, config, router):  # noqa: F811
    router.add('POST', '/scripts', FakeResponse(payload=script(7, 'new')))
    result = ops.operations['create_script'](config, {
        'name': ' new ', 'script': 'get system status', 'description': 'd'})
    call = api_calls(router)[0]
    assert call['url'] == BASE + '/scripts'
    assert call['params'] == {'folder': 0}
    assert call['json'] == {'name': 'new', 'comments': 'd', 'text': 'get system status',
                            'ouExposed': False, 'deviceType': 'FortiGate'}
    assert result['oid'] == 7


def test_create_script_requires_name_and_text(ops, config, connector_error):
    with pytest.raises(connector_error) as err:
        ops.operations['create_script'](config, {'name': ' '})
    assert "'name' is a required parameter" in str(err.value)
    assert "'script' is a required parameter" in str(err.value)


def test_delete_script_request_and_result(ops, config, router):  # noqa: F811
    router.add('DELETE', '/scripts/42', FakeResponse(status=204, payload={}, text=' ', content_type=''))
    result = ops.operations['delete_script'](config, {'oid': '42'})
    call = api_calls(router)[0]
    assert (call['method'], call['url']) == ('DELETE', BASE + '/scripts/42')
    assert result == {'oid': 42, 'deleted': True}


def test_delete_script_rejects_a_non_numeric_id(ops, config, connector_error):
    with pytest.raises(connector_error, match="'oid' must be an integer; got 'abc'"):
        ops.operations['delete_script'](config, {'oid': 'abc'})


# --- running -----------------------------------------------------------------

def schedule_ok(devs=(SN,), conflict=(), invalid=()):
    return FakeResponse(payload={'successDevs': list(devs), 'conflictDevs': list(conflict),
                                 'otherInvalidDevs': list(invalid)})


def test_run_script_without_waiting_returns_after_accept(ops, config, router, clock):  # noqa: F811
    router.add('GET', '/scripts', FakeResponse(payload=[script(42, 'probe')]))
    router.add('GET', '/tasks/script', FakeResponse(payload=[task(1)]))
    router.add('POST', '/tasks/script/schedule', schedule_ok())
    result = ops.operations['run_script'](config, {'oid': 42, 'sns': SN, 'wait': False})
    schedule = [c for c in api_calls(router) if c['url'].endswith('/tasks/script/schedule')][0]
    assert schedule['json'] == {'sns': [SN], 'immediate': True,
                                'targetScript': {'oid': 42, 'name': 'probe'}}
    assert result['scheduled'] == [SN] and result['waited'] is False
    assert result['tasks'] == [] and result['timed_out'] is False


def test_run_script_waits_and_returns_each_devices_output(ops, config, router, clock):  # noqa: F811
    router.add('GET', '/scripts', FakeResponse(payload=[script(42, 'probe')]))
    # known tasks, then the new one still running, then finished
    router.add('GET', '/tasks/script',
               FakeResponse(payload=[task(1, name='old')]),
               FakeResponse(payload=[task(1, name='old')]),
               FakeResponse(payload=[task(2, 'RUNNING'), task(1, name='old')]),
               FakeResponse(payload=[task(2, 'SUCCEED'), task(1, name='old')]))
    router.add('POST', '/tasks/script/schedule', schedule_ok())
    router.add('GET', '/tasks/log', text('Version: FortiGate-VM64-KVM v7.6.4\n'))
    result = ops.operations['run_script'](config, {'oid': 42, 'sns': SN})
    assert result['timed_out'] is False and result['waited'] is True
    assert result['tasks'] == [{'oid': 2, 'sn': SN, 'status': 'SUCCEED', 'message': 'ok. ',
                                'archive_time': 5000, 'output': 'Version: FortiGate-VM64-KVM v7.6.4\n'}]
    log = [c for c in api_calls(router) if c['url'].endswith('/tasks/log')][0]
    assert log['params'] == {'taskOid': 2, 'archiveTime': 5000}


def test_run_script_ignores_other_scripts_and_devices(ops, config, router, clock):  # noqa: F811
    """Only a NEW task for this script on a device we scheduled counts."""
    router.add('GET', '/tasks/script',
               FakeResponse(payload=[]),
               FakeResponse(payload=[task(9, name='someone-elses'), task(10, sn='FGT-OTHER')]),
               FakeResponse(payload=[task(11), task(9, name='someone-elses')]))
    router.add('POST', '/tasks/script/schedule', schedule_ok())
    router.add('GET', '/tasks/log', text('out'))
    result = ops.operations['run_script'](config, {
        'oid': 42, 'script_name': 'probe', 'sns': SN})
    assert [t['oid'] for t in result['tasks']] == [11]


def test_run_script_times_out_without_raising(ops, config, router, clock):  # noqa: F811
    router.add('GET', '/tasks/script', FakeResponse(payload=[]))
    router.add('POST', '/tasks/script/schedule', schedule_ok())
    result = ops.operations['run_script'](config, {
        'oid': 42, 'script_name': 'probe', 'sns': SN, 'timeout': 10})
    assert result['timed_out'] is True and result['tasks'] == []
    assert result['scheduled'] == [SN]
    assert clock.now >= 1010.0


def test_run_script_reports_devices_that_refused(ops, config, router, clock):  # noqa: F811
    router.add('GET', '/tasks/script', FakeResponse(payload=[]))
    router.add('POST', '/tasks/script/schedule',
               schedule_ok(devs=(), conflict=('FGT-BUSY',), invalid=('FGT-BAD',)))
    result = ops.operations['run_script'](config, {
        'oid': 42, 'script_name': 'probe', 'sns': 'FGT-BUSY, FGT-BAD'})
    assert result['scheduled'] == [] and result['conflict'] == ['FGT-BUSY']
    assert result['invalid'] == ['FGT-BAD'] and result['tasks'] == []
    assert result['timed_out'] is False  # nothing was accepted, so nothing to wait for


def test_run_script_unknown_id_is_a_clear_error(ops, config, router, connector_error):  # noqa: F811
    router.add('GET', '/scripts', FakeResponse(payload=[script(1, 'other')]))
    with pytest.raises(connector_error, match='No CLI script with id 42'):
        ops.operations['run_script'](config, {'oid': 42, 'sns': SN})


def test_run_script_parameter_errors(ops, config, connector_error):
    with pytest.raises(connector_error) as err:
        ops.operations['run_script'](config, {'oid': 42, 'sns': ' , ', 'timeout': 0})
    assert "'sns' is a required parameter" in str(err.value)
    with pytest.raises(connector_error, match="'timeout' must be between 1 and 900"):
        ops.operations['run_script'](config, {'oid': 42, 'sns': SN, 'timeout': 5000})


# --- runs and output -----------------------------------------------------------

def test_list_script_tasks_shape(ops, config, router):  # noqa: F811
    router.add('GET', '/tasks/script', FakeResponse(payload=[task(2), task(1)]))
    result = ops.operations['list_script_tasks'](config, {})
    assert [t['oid'] for t in result] == [2, 1]
    assert result[0]['taskStatus'] == 'SUCCEED'
    assert api_calls(router)[0]['params'] is None or api_calls(router)[0]['params'] == {}


def test_get_script_task_output(ops, config, router):  # noqa: F811
    router.add('GET', '/tasks/log', text('line1\nline2\n'))
    result = ops.operations['get_script_task_output'](config, {'task_oid': 9, 'archive_time': '123'})
    assert api_calls(router)[0]['params'] == {'taskOid': 9, 'archiveTime': 123}
    assert result == {'task_oid': 9, 'output': 'line1\nline2\n'}


def test_get_script_task_output_without_archive_time(ops, config, router):  # noqa: F811
    router.add('GET', '/tasks/log', text('x'))
    ops.operations['get_script_task_output'](config, {'task_oid': 9})
    assert api_calls(router)[0]['params'] == {'taskOid': 9}


# --- firmware ------------------------------------------------------------------

def test_list_firmware_upgrades(ops, config, router):  # noqa: F811
    router.add('GET', '/upgrade', FakeResponse(payload=[]))
    assert ops.operations['list_firmware_upgrades'](config, {'folder': 0}) == []
    call = api_calls(router)[0]
    assert call['url'] == BASE + '/upgrade' and call['params'] == {'folder': 0}
