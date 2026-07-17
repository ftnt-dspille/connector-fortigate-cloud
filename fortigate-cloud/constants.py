""" Copyright start
  Copyright (C) 2008 - 2026 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

CONNECTOR_NAME = "fortigate-cloud"

# The IAM token endpoint requires the trailing slash. Without it the service
# answers 301 and the redirected request arrives without its body, surfacing as
# a misleading 'Request is not valid JSON' 400.
TOKEN_URL = "https://customerapiauth.fortinet.com/api/v1/oauth/token/"

# FortiGate Cloud is region-partitioned; a device is only visible from the
# region it was provisioned into.
REGION_URLS = {
    "Global": "https://api.fortigate.forticloud.com",
    "US": "https://usapi.fortigate.forticloud.com",
    "EU": "https://euapi.fortigate.forticloud.com",
    "Japan": "https://jpapi.fortigate.forticloud.com",
}

API_BASE_PATH = "/forticloudapi/v1"

# Documented rate limits: 100 calls/sec and 15 errors/min.
ERROR_MESSAGES = {
    400: "Bad request: the FortiGate Cloud API rejected the request payload",
    401: "Authentication failed: the token was rejected. Confirm the IAM API user "
         "has Admin permissions for FortiGate Cloud and that the configured region "
         "matches the account.",
    403: "Access denied: the IAM API user lacks permission for this operation",
    404: "The requested resource was not found",
    429: "Rate limit exceeded (100 calls/sec, 15 errors/min)",
    "ssl_error": "SSL certificate validation failed",
    "time_out": "The request timed out while trying to connect to FortiGate Cloud",
}
