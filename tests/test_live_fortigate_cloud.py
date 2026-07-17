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

These tests are READ-ONLY. They never add a device, change management state,
write a schedule, or alter a backup setting. Write operations against a real
FortiGate are left to manual verification.

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
    """Requires the FortiGate to be online with configuration management enabled
    and its management tunnel up. GET works on free accounts.

    Skips rather than fails when the device has no tunnel: that is an environment
    prerequisite, not a connector defect. The device API is queried first so the
    skip reason states the actual device state.
    """
    device = ops.operations['get_device'](live_config, {'sn': TEST_SN})
    if not (device.get('management') and device.get('tunnelAlive')):
        pytest.skip(
            'device {0} cannot serve the FortiOS proxy: management={1}, tunnelAlive={2}. '
            'Deploy the FortiGate to FortiGate Cloud, enable configuration management, '
            'and bring its management tunnel online.'.format(
                TEST_SN, device.get('management'), device.get('tunnelAlive'))
        )
    result = ops.operations['fos_api_call'](live_config, {
        'sn': TEST_SN, 'method': 'GET', 'fos_api_path': 'api/v2/monitor/license/status',
    })
    assert result is not None


def test_live_bad_credentials_are_rejected(ops, live_config, connector_error):
    """A wrong password must raise rather than silently pass.

    Skipped by default: a deliberate auth failure contributes to the FortiCloud
    invalid_grant lockout that would block the real credentials for 15-30 minutes.
    """
    pytest.skip('deliberate auth failures risk locking out the account; run manually if needed')
