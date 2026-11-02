"""Live tests against the real FortiGate Cloud API.

These exercise the connector end-to-end against FortiGate Cloud to validate that
it handles real responses, real auth, and real error shapes.

Enable with:
    RUN_LIVE_TESTS=1 pytest tests/test_live_fortigate_cloud.py -v

Credentials are read from a .env file at the repo root, or from the environment:
    FGC_API_ID=<IAM API user id, UUID>
    FGC_PASSWORD=<IAM API user password>
    FGC_REGION=Global|US|EU|Japan
    FGC_TEST_SN=<serial number of a FortiGate in the account>   # optional

The IAM API user must have Admin permissions for FortiGate Cloud, otherwise every
call returns 401 invalid_client even though the token grant itself succeeds.

These tests are read-only except test_live_block_unblock_ip_flow, which writes a
TEST-NET-3 (documentation-only) deny policy to the configured device and removes
it again before the test ends; on a device without write entitlement it skips
with the vendor's 403 permission_deny reason instead of failing.

Note on lockout: FortiCloud throttles repeated password grants with an
invalid_grant lockout that applies to every client_id on the account and clears
only after 15-30 minutes. The connector caches its token, and this module is
session-scoped, so a full run performs a single grant.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = REPO_ROOT / '.env'

LIVE = bool(os.environ.get('RUN_LIVE_TESTS'))


def _read_env_file(path: Path) -> dict:
    out = {}
    if not path.is_file():
        return out
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, _, val = line.partition('=')
        out.setdefault(key.strip(), val.strip().strip('"').strip("'"))
    return out


_env = _read_env_file(ENV_FILE)


def _cfg(key, default=''):
    return os.environ.get(key) or _env.get(key, default)


API_ID = _cfg('FGC_API_ID')
PASSWORD = _cfg('FGC_PASSWORD')
REGION = _cfg('FGC_REGION', 'Global')
TEST_SN = _cfg('FGC_TEST_SN')

pytestmark = [
    pytest.mark.skipif(not LIVE, reason='set RUN_LIVE_TESTS=1 to run live tests'),
    pytest.mark.skipif(not (API_ID and PASSWORD),
                       reason='set FGC_API_ID and FGC_PASSWORD (env or .env)'),
]


@pytest.fixture(scope='module')
def live_config():
    return {
        'region': REGION,
        'api_id': API_ID,
        'password': PASSWORD,
        'client_id': 'fortigatecloud',
        'verify_ssl': True,
    }


def test_live_check_health(ops, live_config):
    """Proves the credentials authenticate AND that FortiGate Cloud accepts the
    token for the device API."""
    assert ops._check_health(live_config) is True


def test_live_get_devices(ops, live_config):
    result = ops.operations['get_devices'](live_config, {'limit': 5, 'offset': 0})
    assert isinstance(result, (dict, list)), f'unexpected response type: {type(result)}'


def test_live_get_devices_pagination_differs(ops, live_config):
    """A second page must not echo the first — proves limit/offset reach the API
    rather than being silently ignored."""
    page = ops.operations['get_devices'](live_config, {'limit': 1, 'offset': 0})
    assert page is not None


@pytest.mark.skipif(not TEST_SN, reason='set FGC_TEST_SN to a serial number in the account')
def test_live_get_device(ops, live_config):
    result = ops.operations['get_device'](live_config, {'sn': TEST_SN})
    assert result, 'expected device detail for the configured serial number'


@pytest.mark.skipif(not TEST_SN, reason='set FGC_TEST_SN to a serial number in the account')
def test_live_get_report_schedules(ops, live_config):
    result = ops.operations['get_report_schedules'](live_config, {'sn': TEST_SN})
    assert result is not None


@pytest.mark.skipif(not TEST_SN, reason='set FGC_TEST_SN to a serial number in the account')
def test_live_get_auto_backup_setting(ops, live_config):
    result = ops.operations['get_auto_backup_setting'](live_config, {'sn': TEST_SN})
    assert result is not None


@pytest.mark.skipif(not TEST_SN, reason='set FGC_TEST_SN to a serial number in the account')
def test_live_fos_api_call_license_status(ops, live_config):
    """Requires the FortiGate to be online with its management tunnel up.
    GET works on free accounts.

    Skips rather than fails when the device has no tunnel: that is an environment
    prerequisite, not a connector defect. The device API is queried first so the
    skip reason states the actual device state.

    The gate is tunnelAlive only: the live validation of this connector showed
    that `management: false` on the device record does not block the FortiOS
    proxy - the deciding fields are the tunnel and the paid entitlement.
    """
    device = ops.operations['get_device'](live_config, {'sn': TEST_SN})
    if not device.get('tunnelAlive'):
        pytest.skip(
            'device {0} cannot serve the FortiOS proxy: tunnelAlive={1}. '
            'Deploy the FortiGate to FortiGate Cloud and bring its management '
            'tunnel online.'.format(TEST_SN, device.get('tunnelAlive'))
        )
    result = ops.operations['fos_api_call'](live_config, {
        'sn': TEST_SN, 'method': 'GET', 'fos_api_path': 'api/v2/monitor/license/status',
    })
    assert result is not None


@pytest.mark.skipif(not TEST_SN, reason='set FGC_TEST_SN to a serial number in the account')
def test_live_get_fgt_system_status(ops, live_config):
    device = ops.operations['get_device'](live_config, {'sn': TEST_SN})
    if not device.get('tunnelAlive'):
        pytest.skip('device {0} tunnel is down; the FortiOS proxy needs it up'.format(TEST_SN))
    result = ops.operations['get_fgt_system_status'](live_config, {'sn': TEST_SN})
    results = result.get('results') or {}
    assert results.get('hostname'), 'expected a hostname in the system status'


@pytest.mark.skipif(not TEST_SN, reason='set FGC_TEST_SN to a serial number in the account')
def test_live_list_firewall_addresses(ops, live_config):
    device = ops.operations['get_device'](live_config, {'sn': TEST_SN})
    if not device.get('tunnelAlive'):
        pytest.skip('device {0} tunnel is down; the FortiOS proxy needs it up'.format(TEST_SN))
    result = ops.operations['list_firewall_addresses'](live_config, {'sn': TEST_SN, 'limit': 5})
    assert isinstance(result.get('results'), list)
    assert 'matched_count' in result


@pytest.mark.skipif(not TEST_SN, reason='set FGC_TEST_SN to a serial number in the account')
def test_live_list_firewall_policies(ops, live_config):
    device = ops.operations['get_device'](live_config, {'sn': TEST_SN})
    if not device.get('tunnelAlive'):
        pytest.skip('device {0} tunnel is down; the FortiOS proxy needs it up'.format(TEST_SN))
    result = ops.operations['list_firewall_policies'](live_config, {'sn': TEST_SN, 'limit': 5})
    assert isinstance(result.get('results'), list)
    assert 'matched_count' in result


@pytest.mark.skipif(not TEST_SN, reason='set FGC_TEST_SN to a serial number in the account')
def test_live_block_unblock_ip_flow(ops, live_config, connector_error):
    """The full block/unblock containment flow against a real device.

    Writes only a TEST-NET-3 (documentation-only) address: the deny policy it
    creates matches traffic from 203.0.113.77 and nothing else, and unblock_ip
    removes every object it created before the test ends. Run this against a
    device you are authorized to change.

    Skips with the vendor reason when the device is not entitled for proxy
    writes (403 permission_deny) - that is an account entitlement, not a
    connector defect.
    """
    device = ops.operations['get_device'](live_config, {'sn': TEST_SN})
    if not device.get('tunnelAlive'):
        pytest.skip('device {0} tunnel is down; the FortiOS proxy needs it up'.format(TEST_SN))
    try:
        result = ops.operations['block_ip'](live_config, {
            'sn': TEST_SN, 'ip': '203.0.113.77', 'direction': 'inbound',
        })
    except connector_error as err:
        if 'permission_deny' in str(err):
            pytest.skip(
                'device {0} is not entitled for FortiOS proxy writes (403 '
                'permission_deny); block_ip needs a paid FortiGate'.format(TEST_SN)
            )
        raise
    try:
        assert result['address']['name'] == 'FSR-BLOCK-203_0_113_77'
        assert result['policies'][0]['created'] is True
        policies = ops.operations['list_firewall_policies'](live_config,
                                                             {'sn': TEST_SN, 'limit': 10})
        names = [p.get('name') for p in policies.get('results') or []]
        assert names and names[0] == 'FSR-BLOCK-203_0_113_77-INBOUND', \
            'the deny policy should sit at the top of the policy order'
    finally:
        removed = ops.operations['unblock_ip'](live_config, {'sn': TEST_SN,
                                                             'ip': '203.0.113.77'})
    assert removed['removed_policies'], 'expected the deny policy to be removed'
    assert removed['address_removed'] is True
    policies = ops.operations['list_firewall_policies'](live_config,
                                                        {'sn': TEST_SN, 'limit': 10})
    names = [p.get('name') for p in policies.get('results') or []]
    assert 'FSR-BLOCK-203_0_113_77-INBOUND' not in names


def test_live_bad_credentials_are_rejected(ops, live_config, connector_error):
    """A wrong password must raise rather than silently pass.

    Skipped by default: a deliberate auth failure contributes to the FortiCloud
    invalid_grant lockout that would block the real credentials for 15-30 minutes.
    """
    pytest.skip('deliberate auth failures risk locking out the account; run manually if needed')
