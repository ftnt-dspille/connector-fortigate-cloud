# FortiGate Cloud connector for FortiSOAR

Manages devices provisioned to FortiGate Cloud and proxies FortiOS API calls to
managed FortiGates.

> FortiGate Cloud has been renamed **FortiManagement Cloud**. Per Fortinet's
> announcement no action is required: hosts, API paths and the `fortigatecloud`
> client id are unchanged, and this connector keeps its `fortigate-cloud` name
> so existing deployments upgrade in place.

## Operations

| Operation | Method / path |
| --- | --- |
| Get Devices | `GET /devices` (limit, offset, sort) |
| Get Device | `GET /devices/{sn}` |
| Add Device | `POST /devices` (`deviceKey`) |
| Update Device Management | `PUT /devices/{sn}/management` |
| Get Report Schedules | `GET /devices/{sn}/reportschedules` |
| Get Report Schedule | `GET /devices/{sn}/reportschedules/{oid}` |
| Add or Update Report Schedule | `POST /devices/{sn}/reportschedules` |
| Delete Report Schedule | `DELETE /devices/{sn}/reportschedules/{oid}` |
| Get Config Auto Backup Setting | `GET /devices/{sn}/configbackups/setting` |
| Update Config Auto Backup Setting | `PUT /devices/{sn}/configbackups/setting` |
| Get FortiGate System Status | proxy `GET api/v2/monitor/system/status` |
| List Firewall Addresses | proxy `GET api/v2/cmdb/firewall/address` |
| List Firewall Policies | proxy `GET api/v2/cmdb/firewall/policy` |
| Create Firewall Address | proxy `POST api/v2/cmdb/firewall/address` |
| Delete Firewall Address | proxy `DELETE api/v2/cmdb/firewall/address/{name}` |
| Block IP | create/reuse `FSR-BLOCK-<ip>` address + top-of-order deny policy |
| Unblock IP | delete exactly the objects Block IP created |
| Call FortiOS API | `{method} /fgt/{sn}/{FortiOS API path}` |
| Generic API Call | any endpoint under the API base path |

## Configuration

Authentication uses a FortiCloud IAM API user (password grant against
`https://customerapiauth.fortinet.com/api/v1/oauth/token/`) with
`client_id: fortigatecloud`.

The IAM API user **must be granted Admin permissions for FortiGate Cloud** in the
FortiCloud IAM portal. Without that permission the token grant still succeeds, but
every FortiGate Cloud API call is rejected with `401 invalid_client`. The
connector's health check probes `/devices` rather than only logging in, so this
misconfiguration is reported at config time instead of at playbook runtime.

`Region` selects the API host; a device is only visible from the region it was
provisioned into. `Server URL` optionally overrides the region.

## API notes

Facts established against the live API, where the published documentation is
misleading:

- The token URL **requires its trailing slash**. Without it the service answers
  301 and the redirected request arrives without its body, which surfaces as a
  confusing `400 Request is not valid JSON`.
- The base path is `<region host>/forticloudapi/v1`. The v25.3 spec declares
  `servers: /forticloudapi/v1` *and* `/v1`-prefixed paths; these do **not**
  concatenate. A request to `/v1/devices` without the `forticloudapi` prefix
  returns the FortiGate Cloud web application with HTTP 200 rather than an API
  error.
- The spec's curl examples use the legacy `www.forticloud.com` host; the regional
  hosts (`api|usapi|euapi|jpapi.fortigate.forticloud.com`) are current.
- **One account can hold devices in more than one region, and `/devices` only
  ever returns the region you asked.** A device missing from the Global listing
  is not necessarily absent from the account — the same credentials against the
  US host can return a device Global never mentions. When hunting for a serial,
  sweep every region the credentials authenticate against rather than trusting a
  single listing. Regions the account has no presence in answer `401
  invalid_client`, which is indistinguishable from a bad credential, so a 401 on
  one region says nothing about the others.
- Observed token lifetime is 3660s, not the 14400s the documentation states.
- `POST`, `PUT` and `DELETE` on the FortiOS proxy require a paid FortiGate; `GET`
  is available on free accounts. The proxy also requires the FortiGate to be
  online with its management tunnel up. The two gates are enforced at different
  layers and produce different errors: an unentitled device rejects a write with
  `403 {"error": "permission_deny"}` *before* the tunnel is consulted, while an
  entitled but offline device returns the same `500 tunnel not connected` for
  reads and writes alike. A `403` therefore means "wrong device", not "the proxy
  is read-only".
- `fos_api_path` must use the FortiOS CMDB path form, where the table family is
  dot-separated and only the final segment is a path segment. Firewall services
  are `api/v2/cmdb/firewall.service/custom`, **not**
  `api/v2/cmdb/firewall/service/custom` — the latter returns a bare
  `400 {"status": "error"}` with no `cli_error` to explain it, on reads as well
  as writes. Addresses and policies (`firewall/address`, `firewall/policy`) are
  already single-segment families and need no dot.
- The proxy forwards the FortiGate's own error body, so payload mistakes surface
  as FortiOS CLI errors rather than FortiGate Cloud errors. A create that names a
  not-yet-existing object fails with
  `cli_error: ["entry not found in datasource", ...]`, and an out-of-range
  enum value fails with a bare `error: -61`. Both arrive as HTTP 500 with
  `revision_changed: false`, which is the reliable signal that nothing was
  written. On success the response carries `revision`, `old_revision` and
  `revision_changed: true`.
- Repeated failed password grants trigger a FortiCloud `invalid_grant` lockout
  that applies to every `client_id` on the account and clears only after 15-30
  minutes. The connector caches tokens per (api_id, client_id, host) to avoid
  re-authenticating on every operation.
- Policy order changes go through the FortiOS CMDB move action:
  `PUT api/v2/cmdb/firewall/policy/{id}?action=move&before={other id}`. There is
  no "top" keyword, so moving a policy to the top means moving it before the
  policy that currently sits there, then re-reading the list to verify it
  actually landed first.
- The Block IP / Unblock IP pair is idempotent and self-contained. It only ever
  touches objects named `FSR-BLOCK-<ip>` (dots replaced with underscores, a
  `-INBOUND`/`-OUTBOUND` suffix on policies); the deny policy matches only the
  blocked address, so no other traffic path changes. Block IP refuses to reuse
  an existing `FSR-BLOCK-<ip>` object whose subnet differs from the request,
  and Unblock IP refuses to delete the address object while a policy it did
  not create still references it.

## Tests

```bash
pytest tests/ -q                                                 # unit; no network
RUN_LIVE_TESTS=1 pytest tests/test_live_fortigate_cloud.py -v    # live
```

Unit tests stub FortiSOAR's appliance-only runtime packages (see
`tests/conftest.py`) and assert on the requests the connector builds; both test
files share those fixtures.

Live tests read credentials from a gitignored `.env` at the repo root:

```
FGC_API_ID=<IAM API user id>
FGC_PASSWORD=<password>
FGC_REGION=Global
FGC_TEST_SN=<serial number of a FortiGate in the account>
```

Every live test is read-only except `test_live_block_unblock_ip_flow`, which
runs the containment flow against the configured device: it blocks the
documentation-only address 203.0.113.77 (the deny policy matches only that
address), verifies the policy landed at the top of the policy order, and then
removes everything it created. On a device without proxy write entitlement it
skips with the vendor's `403 permission_deny` reason instead of failing, so the
suite is safe against any account and lights up automatically once an entitled
device is configured.

## Status

- Unit tests: passing (64).
- Live validation: **device API verified** against the real FortiGate Cloud API —
  health check, get devices (incl. pagination), get device, report schedules and
  the config auto backup setting all return live data.
- Live validation: **FortiOS proxy verified**, against a paid FortiGate running
  FortiOS 7.6.6 with `tunnelAlive: true` and `cloudAccessMode: INLINE`. The full
  read/write lifecycle lands on the device: create a firewall address, create a
  custom service, create a policy referencing both, read the policy back, disable
  it with `PUT status=disable`, then delete all three. Every write returned
  HTTP 200 with `revision_changed: true` and a new config revision, and the
  read-backs confirmed the device state each time.

  Note that `management: false` on the device record does **not** block the
  proxy — the deciding fields are `tunnelAlive` and the paid entitlement, not the
  configuration-management flag.

  Offline or unentitled devices still cannot be used for this: see the two
  distinct gate errors under API quirks above.
- Live validation: **curated proxy reads verified** through the new operations
  against a connected FortiGate running FortiOS 7.4: Get FortiGate System
  Status, List Firewall Addresses and List Firewall Policies all return live
  device data, and the live block/unblock flow test confirms the write gate
  (`403 permission_deny`) on an unentitled device by skipping cleanly.
- Live write validation for **Block IP / Unblock IP is pending an entitled
  device**: the account's previously paid FortiGate is no longer available (its
  management contract lapsed), and the connected hardware unit answers proxy
  reads normally but rejects writes with `403 permission_deny`. The flow is
  fully covered by unit tests and runs automatically against the next
  write-entitled device configured in `.env`.
- Deployed and configured on FortiSOAR 8.0.0-6034; health check reports
  `Available`.

### On IAM permissions

Not every FortiCloud IAM API user can reach FortiGate Cloud, and the failure is
easy to misread. Two separate IAM users on this account obtain a valid token
(`HTTP 200`, `status: success`) yet are rejected by the device API with
`401 invalid_client` on every region. A third user reaches it normally. The token
grant is therefore no evidence of access — grant the API user Admin permissions
for FortiGate Cloud in the IAM portal, and rely on the connector's health check
(which probes `/devices`) rather than on a successful login.
