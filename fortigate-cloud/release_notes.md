#### 1.0.0

##### What's Added

Initial release of the FortiGate Cloud connector, with 12 operations:

- **Devices**: Get Devices, Get Device, Add Device, Update Device Management.
- **Report schedules**: Get Report Schedules, Get Report Schedule, Add or Update Report Schedule, Delete Report Schedule.
- **Configuration backup**: Get Config Auto Backup Setting, Update Config Auto Backup Setting.
- **Call FortiOS API**: proxies a FortiOS API call to a managed FortiGate through FortiGate Cloud. The FortiGate must be deployed to FortiGate Cloud with configuration management enabled and its management tunnel online. Only the GET method is available on free FortiGate Cloud accounts; POST, PUT and DELETE require a paid FortiGate.
- **Generic API Call**: makes an arbitrary call to the FortiGate Cloud API, for endpoints the connector does not expose as a dedicated action.

##### Notes

- Authentication uses a FortiCloud IAM API user (API ID + password) with the `fortigatecloud` client ID. The IAM API user must be granted Admin permissions for FortiGate Cloud. Permissions are granted per-user, so an API user without the FortiGate Cloud Admin permission authenticates but is then rejected by the API.
- A device is only visible from the region it was provisioned into. Select the matching region, or override it with an explicit Server URL.
