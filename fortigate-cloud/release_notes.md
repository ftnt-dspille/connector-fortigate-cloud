#### 1.1.0

##### What's Added

Seven curated operations that run FortiOS API calls on a cloud-managed FortiGate
through the FortiGate Cloud proxy, so playbooks no longer have to assemble
FortiOS paths themselves:

- **Get FortiGate System Status**: hostname, model, firmware, serial, VDOM and
  resource use of a managed FortiGate, retrieved through FortiGate Cloud.
- **List Firewall Addresses** and **List Firewall Policies**: the device's
  address objects and policies, in policy order, with limit/offset pagination.
- **Create Firewall Address** and **Delete Firewall Address**: manage address
  objects remotely; the IP accepts a single IPv4 address (a /32 object) or a
  CIDR network.
- **Block IP**: containment flow that creates (or reuses) an `FSR-BLOCK-<ip>`
  address object and a deny policy matching only that address, then moves the
  policy to the top of the policy order. Traffic to or from other hosts is not
  affected. Idempotent.
- **Unblock IP**: removes exactly the objects Block IP created, and keeps the
  address object if a policy the connector did not create still references it.
  Idempotent.

##### Notes

- The curated reads work on free FortiGate Cloud accounts. The writes, including
  Block IP and Unblock IP, require a paid FortiGate; an unentitled device
  answers `403 permission_deny` before the management tunnel is consulted.
- Block IP / Unblock IP only ever touch objects named `FSR-BLOCK-<ip>` (dots
  replaced with underscores). Unblock IP is safe to run at any time: objects
  that are already absent are reported, not treated as errors.
- FortiGate Cloud has been renamed FortiManagement Cloud. Hosts, API paths and
  the `fortigatecloud` client id are unchanged, and this connector keeps its
  `fortigate-cloud` name so existing deployments upgrade in place.

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
