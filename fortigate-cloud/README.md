# FortiGate Cloud connector for FortiSOAR

Manages devices provisioned to FortiGate Cloud and proxies FortiOS API calls to
managed FortiGates.

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
- Observed token lifetime is 3660s, not the 14400s the documentation states.
- `POST`, `PUT` and `DELETE` on the FortiOS proxy require a paid FortiGate; `GET`
  is available on free accounts. The proxy also requires the FortiGate to be
  online with configuration management enabled and its management tunnel up.
- Repeated failed password grants trigger a FortiCloud `invalid_grant` lockout
  that applies to every `client_id` on the account and clears only after 15-30
  minutes. The connector caches tokens per (api_id, client_id, host) to avoid
  re-authenticating on every operation.

## Tests

```bash
pytest tests/test_fortigate_cloud.py -q          # unit; no network
RUN_LIVE_TESTS=1 pytest tests/test_live_fortigate_cloud.py -v   # live, read-only
```

Live tests read credentials from a gitignored `.env` at the repo root:

```
FGC_API_ID=<IAM API user id>
FGC_PASSWORD=<password>
FGC_REGION=Global
FGC_TEST_SN=<serial number of a FortiGate in the account>
```

The live tests are read-only: they never add a device, change management state,
write a schedule, or alter a backup setting.

## Status

- Unit tests: passing (40).
- Live validation: **device API verified** against the real FortiGate Cloud API —
  health check, get devices (incl. pagination), get device, report schedules and
  the config auto backup setting all return live data.
- Live validation: **FortiOS proxy unverified**. Every device in the test account
  reports `management=false` / `tunnelAlive=false` / `initialized=false`, and the
  proxy answers `HTTP 500 {"error_description": "tunnel not connected."}` for all
  of them. The live test skips with that state in its reason. Validating it needs
  a FortiGate actually deployed to FortiGate Cloud with configuration management
  enabled and its management tunnel online.
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
