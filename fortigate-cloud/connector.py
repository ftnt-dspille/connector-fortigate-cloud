""" Copyright start
  Copyright (C) 2008 - 2026 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from connectors.core.connector import Connector, ConnectorError, get_logger

from .constants import CONNECTOR_NAME
from .operations import _check_health, operations

logger = get_logger(CONNECTOR_NAME)


class FortiGateCloud(Connector):
    def execute(self, config, operation, params, **kwargs):
        try:
            config['connector_info'] = {"connector_name": self._info_json.get('name'),
                                        "connector_version": self._info_json.get('version')}
            action = operations.get(operation)
            if not action:
                logger.error('Unsupported operation: {}'.format(operation))
                raise ConnectorError('Unsupported operation: {}'.format(operation))
            return action(config, params)
        except Exception as err:
            logger.exception(err)
            raise ConnectorError(err)

    def check_health(self, config=None):
        try:
            config['connector_info'] = {"connector_name": self._info_json.get('name'),
                                        "connector_version": self._info_json.get('version')}
            return _check_health(config)
        except Exception as err:
            raise ConnectorError(err)

    def on_app_start(self, config, active):
        pass

    def on_add_config(self, config, active):
        pass

    def on_update_config(self, old_config, new_config, active):
        pass

    def on_delete_config(self, config):
        pass

    def on_activate(self, config):
        pass

    def on_deactivate(self, config):
        pass

    def teardown(self, config):
        pass
