""" Copyright start
  Copyright (C) 2008 - 2026 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from typing import Any, Optional

from connectors.core.connector import Connector, ConnectorError, get_logger

from .constants import CONNECTOR_NAME
from .operations import _check_health, operations

logger = get_logger(CONNECTOR_NAME)


class FortiGateCloud(Connector):
    def execute(self, config: dict[str, Any], operation: str, params: dict[str, Any], **kwargs: Any) -> Any:
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

    def check_health(self, config: Optional[dict[str, Any]] = None) -> bool:
        try:
            config = {} if config is None else config
            config['connector_info'] = {"connector_name": self._info_json.get('name'),
                                        "connector_version": self._info_json.get('version')}
            return _check_health(config)
        except Exception as err:
            raise ConnectorError(err)

    def on_app_start(self, config: Any, active: Any) -> None:
        pass

    def on_add_config(self, config: Any, active: Any) -> None:
        pass

    def on_update_config(self, old_config: Any, new_config: Any, active: Any) -> None:
        pass

    def on_delete_config(self, config: Any) -> None:
        pass

    def on_activate(self, config: Any) -> None:
        pass

    def on_deactivate(self, config: Any) -> None:
        pass

    def teardown(self, config: Any) -> None:
        pass
