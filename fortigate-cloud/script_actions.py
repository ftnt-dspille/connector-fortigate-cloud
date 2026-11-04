""" Copyright start
  Copyright (C) 2008 - 2026 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

# CLI scripts and script runs. A script is stored in the FortiGate Cloud
# account, then scheduled against one or more FortiGates; each device gets a
# task whose final state and CLI output can be read back.
#
# These calls are served by the FortiGate Cloud gateway but are not in the
# published API specification: the request shapes were captured from the
# product and verified live, so treat them as less stable than the documented
# device calls.

import time
from typing import Any, Optional

from connectors.core.connector import ConnectorError

from .make_rest_api_call import MakeRestApiCall
from .models import (
    PENDING_TASK_STATES,
    CreateScriptParams,
    DeleteScriptParams,
    DeleteScriptResult,
    ListScriptsParams,
    ListScriptTasksParams,
    RunScriptParams,
    RunScriptResult,
    ScheduleReply,
    Script,
    ScriptTask,
    ScriptTaskOutputParams,
    ScriptTaskOutputResult,
    TaskOutcome,
    parse_params,
    parse_reply,
    parse_reply_list,
)

Config = dict[str, Any]

# How often a run is polled while waiting for its tasks to finish.
_POLL_INTERVAL = 3.0


def _client(config: Config) -> MakeRestApiCall:
    return MakeRestApiCall(config=config)


def _folder(folder: Optional[int]) -> dict[str, Any]:
    return {} if folder is None else {"folder": folder}


def _dump(models: list[Any]) -> list[dict[str, Any]]:
    return [model.model_dump() for model in models]


def list_scripts(config: Config, params: Config) -> list[dict[str, Any]]:
    """List the CLI scripts stored in the FortiGate Cloud account. With
    'include_content' the script text is returned too."""
    p = parse_params(ListScriptsParams, params)
    query: dict[str, Any] = {
        "manageable": "false",
        "includeContent": "true" if p.include_content else "false",
        **_folder(p.folder),
    }
    body = _client(config).make_request(endpoint="/scripts", method="GET", params=query)
    return _dump(parse_reply_list(Script, body, "the script list"))


def create_script(config: Config, params: Config) -> dict[str, Any]:
    """Store a CLI script in the FortiGate Cloud account. Creating a script
    does not run it; use run_script for that."""
    p = parse_params(CreateScriptParams, params)
    body = {
        "name": p.name,
        "comments": p.description or "",
        "text": p.script,
        "ouExposed": False,
        "deviceType": p.device_type,
    }
    reply = _client(config).make_request(
        endpoint="/scripts", method="POST", params=_folder(p.folder) or {"folder": 0}, json_data=body
    )
    return parse_reply(Script, reply, "the created script").model_dump()


def delete_script(config: Config, params: Config) -> dict[str, Any]:
    """Delete a stored CLI script. Task history for earlier runs is kept."""
    p = parse_params(DeleteScriptParams, params)
    _client(config).make_request(endpoint="/scripts/{0}".format(p.oid), method="DELETE")
    return DeleteScriptResult(oid=p.oid, deleted=True).to_dict()


def _list_tasks(fgc: MakeRestApiCall, folder: Optional[int] = None) -> list[ScriptTask]:
    body = fgc.make_request(endpoint="/tasks/script", method="GET", params=_folder(folder))
    return parse_reply_list(ScriptTask, body, "the script task list")


def list_script_tasks(config: Config, params: Config) -> list[dict[str, Any]]:
    """List script runs: one entry per device a script was run on, newest
    first, with its status and short message. Use get_script_task_output for
    the CLI output."""
    p = parse_params(ListScriptTasksParams, params)
    return _dump(_list_tasks(_client(config), p.folder))


def _read_output(fgc: MakeRestApiCall, task_oid: int, archive_time: Optional[int]) -> str:
    query: dict[str, Any] = {"taskOid": task_oid}
    if archive_time is not None:
        query["archiveTime"] = archive_time
    body = fgc.make_request(endpoint="/tasks/log", method="GET", params=query)
    return body if isinstance(body, str) else str(body)


def get_script_task_output(config: Config, params: Config) -> dict[str, Any]:
    """Read the CLI output a script produced on one device."""
    p = parse_params(ScriptTaskOutputParams, params)
    output = _read_output(_client(config), p.task_oid, p.archive_time)
    return ScriptTaskOutputResult(task_oid=p.task_oid, output=output).to_dict()


def _script_name(fgc: MakeRestApiCall, oid: int) -> str:
    """The scheduling call wants the script's name as well as its id."""
    body = fgc.make_request(
        endpoint="/scripts", method="GET", params={"manageable": "false", "includeContent": "false"}
    )
    for script in parse_reply_list(Script, body, "the script list"):
        if script.oid == oid:
            if not script.name:
                break
            return script.name
    raise ConnectorError("No CLI script with id {0} was found in the FortiGate Cloud account".format(oid))


def run_script(config: Config, params: Config) -> dict[str, Any]:
    """Run a stored CLI script on one or more FortiGates now. With 'wait' (the
    default) the operation polls until every accepted device has a finished
    task, then returns each device's status and CLI output; without it, it
    returns as soon as FortiGate Cloud has accepted the run. Devices that
    FortiGate Cloud reports as busy or invalid are listed, not raised; a
    serial number that is not in the account makes FortiGate Cloud reject the
    whole call, which raises with the serial named."""
    p = parse_params(RunScriptParams, params)
    fgc = _client(config)
    name = p.script_name or _script_name(fgc, p.oid)
    known = {task.oid for task in _list_tasks(fgc)}

    raw = fgc.make_request(
        endpoint="/tasks/script/schedule",
        method="POST",
        json_data={"sns": p.sns, "immediate": True, "targetScript": {"oid": p.oid, "name": name}},
    )
    reply = parse_reply(ScheduleReply, raw, "the script schedule reply")

    finished: dict[str, ScriptTask] = {}
    timed_out = False
    if p.wait and reply.successDevs:
        deadline = time.time() + p.timeout
        while True:
            for task in _list_tasks(fgc):
                is_ours = task.oid not in known and task.scriptName == name
                if is_ours and task.sn in reply.successDevs and task.sn not in finished:
                    if (task.taskStatus or "").upper() not in PENDING_TASK_STATES:
                        finished[task.sn or ""] = task
            if len(finished) == len(reply.successDevs):
                break
            if time.time() >= deadline:
                timed_out = True
                break
            time.sleep(_POLL_INTERVAL)

    outcomes = [
        TaskOutcome(
            oid=task.oid,
            sn=task.sn,
            status=task.taskStatus,
            message=task.message,
            archive_time=task.archiveTime,
            output=_read_output(fgc, task.oid, task.archiveTime),
        )
        for task in finished.values()
    ]
    return RunScriptResult(
        oid=p.oid,
        script_name=name,
        scheduled=reply.successDevs,
        conflict=reply.conflictDevs,
        invalid=reply.otherInvalidDevs,
        waited=p.wait,
        timed_out=timed_out,
        tasks=outcomes,
    ).to_dict()
