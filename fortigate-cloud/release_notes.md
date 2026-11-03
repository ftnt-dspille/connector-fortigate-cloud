#### 1.3.0

##### What's Changed

- **Region selection with a Custom override**: the configuration's Region is a
  select of the documented FortiGate Cloud endpoints — Global (default), US, EU
  and Japan — plus a Custom entry that requires the Server URL field, for
  accounts or environments reached through a host that is not one of the four
  published regions.
- **Token renewal via refresh_token**: the FortiCloud IAM endpoint issues a
  refresh token alongside every grant. The connector now renews an expired
  access token with a refresh grant — which carries no account password — and
  only falls back to a password grant when the refresh token is rejected. This
  keeps long playbook runs away from the invalid_grant lockout that repeated
  password grants can trigger.
- **A rejected token is dropped from the cache**: when FortiGate Cloud answers
  401 for a cached token, the connector discards it so the next operation
  re-authenticates instead of retrying the same dead token.

##### Notes

- Verified against the vendor's device and FortiOS-proxy API specifications:
  all ten documented device calls (devices, report schedules, config backup
  settings, management toggle) and the four FortiOS-proxy verbs are available
  as operations, and the base URL, auth grant and bearer-header shapes match
  the specification.
- FortiOS proxy operations require the device to be provisioned to FortiGate
  Cloud with management enabled and the management tunnel online; the
  Update Device Management operation toggles management on the device.

#### 1.2.0

##### What's Added

A second containment style alongside the policy flow: the FortiOS **Quarantine
Monitor** (runtime IP bans), exposed through FortiGate Cloud as three curated
operations:

- **Quarantine IP**: bans one or more IPv4 addresses in a single call. Each
  ban carries its own expiry (`1 Hour` … `1 Month`, a custom duration in
  seconds, or `Never`), touches no address objects or policies, and reverts on
  its own when it expires. Idempotent: already-banned addresses are reported,
  not re-banned.
- **Unquarantine IP**: releases bans; addresses that are not banned are
  reported as such instead of erroring.
- **List Banned IPs**: the current Quarantine Monitor entries, passed through
  verbatim (`ip_address`, `expiry`, `created`, `cause`).

Unlike Block IP / Unblock IP, a Quarantine IP that a playbook fails to clean
up cannot leave the device blocked permanently — the ban expires (and, unless
the device's banned-IP persistency is enabled, does not survive a reboot).

##### Notes

- The ban request is sent JSON-encoded with a form-urlencoded Content-Type —
  the wire shape proven live by the FortiGate v2 connector; the proxy's pass
  through of that shape is exercised by the live quarantine tests.
- The Quarantine Monitor maps to the FortiOS REST endpoints
  `monitor/user/banned/add_users`, `/select` and `/clear_users` (CLI:
  `diagnose user banned-ip`).

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
