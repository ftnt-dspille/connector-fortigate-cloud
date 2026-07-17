"""Shared test fixtures for the FortiGate Cloud connector test suite.

The connector imports from FortiSOAR's runtime packages (``connectors.core.connector``)
which are not installable outside the FortiSOAR appliance. This conftest installs
lightweight stubs into ``sys.modules`` *before* any test imports the connector, so the
connector modules can be imported and unit-tested in isolation.
"""

from __future__ import annotations

import importlib.util
import logging
import sys
import types
from pathlib import Path

import pytest


def _install_framework_stubs() -> None:
    if 'connectors' in sys.modules:
        return

    connectors_pkg = types.ModuleType('connectors')
    connectors_pkg.__path__ = []
    core_pkg = types.ModuleType('connectors.core')
    core_pkg.__path__ = []
    core_connector = types.ModuleType('connectors.core.connector')

    class ConnectorError(Exception):
        """Stub matching FortiSOAR's ConnectorError."""

    class Connector:
        """Stub base class — connectors only override execute() / check_health()."""

        def execute(self, config, operation, params, **kwargs):  # pragma: no cover
            raise NotImplementedError

        def check_health(self, config):  # pragma: no cover
            return True

    core_connector.ConnectorError = ConnectorError
    core_connector.Connector = Connector
    core_connector.get_logger = lambda name: logging.getLogger(name)

    sys.modules['connectors'] = connectors_pkg
    sys.modules['connectors.core'] = core_pkg
    sys.modules['connectors.core.connector'] = core_connector


_install_framework_stubs()

REPO_ROOT = Path(__file__).resolve().parent.parent
CONNECTOR_NAME = 'fortigate-cloud'


def _load_connector(connector_name: str = CONNECTOR_NAME):
    """Import the connector package under an isolated alias so its relative
    imports (``from .constants import ...``) resolve."""
    conn_dir = REPO_ROOT / connector_name
    if not conn_dir.is_dir():
        raise RuntimeError(f"Connector dir not found: {conn_dir}")

    pkg_alias = 'fsr_test_pkg_{}'.format(connector_name.replace('-', '_'))
    for mod_name in list(sys.modules):
        if mod_name == pkg_alias or mod_name.startswith(pkg_alias + '.'):
            del sys.modules[mod_name]

    pkg = types.ModuleType(pkg_alias)
    pkg.__path__ = [str(conn_dir)]
    sys.modules[pkg_alias] = pkg

    def _load(mod_name):
        path = conn_dir / f'{mod_name}.py'
        spec = importlib.util.spec_from_file_location(f'{pkg_alias}.{mod_name}', path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[f'{pkg_alias}.{mod_name}'] = mod
        spec.loader.exec_module(mod)
        return mod

    # Load in dependency order so each relative import finds its target.
    for name in ('constants', 'make_rest_api_call', 'device_actions', 'fos_actions', 'generic_api_call'):
        _load(name)
    return _load('operations')


@pytest.fixture
def ops():
    """The connector's operations module, with the token cache cleared."""
    mod = _load_connector()
    mod.MakeRestApiCall.__module__  # noqa: B018 — ensure module import succeeded
    sys.modules['fsr_test_pkg_fortigate_cloud.make_rest_api_call']._TOKEN_CACHE.clear()
    return mod


@pytest.fixture
def rest_mod():
    """The make_rest_api_call module (for token-cache assertions)."""
    _load_connector()
    mod = sys.modules['fsr_test_pkg_fortigate_cloud.make_rest_api_call']
    mod._TOKEN_CACHE.clear()
    return mod


@pytest.fixture
def connector_error():
    return sys.modules['connectors.core.connector'].ConnectorError


@pytest.fixture
def config():
    return {
        'region': 'Global',
        'api_id': 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
        'password': 'stub-password',
        'client_id': 'fortigatecloud',
        'verify_ssl': True,
    }
