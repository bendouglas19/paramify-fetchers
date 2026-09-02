# ServiceNow Fetchers

Two fetchers pull evidence from ServiceNow REST APIs using a shared bearer token.

---

## Credentials and environment variables

### Shared

| Variable | Required | Description |
|---|---|---|
| `SERVICENOW_API_TOKEN` | Yes | Bearer token for authenticating to the ServiceNow REST API. Shared by both fetchers. |

### `servicenow_cases`

| Variable | Required | Description |
|---|---|---|
| `SERVICENOW_CASES_INSTANCE_URL` | Yes | Base URL of the ServiceNow instance that hosts the customer service cases API, e.g. `https://humanifygdev.servicenowservices.com` |
| `SERVICENOW_CASES_LAST_RUN` | No | Watermark timestamp in `YYYY-MM-DD HH:MM:SS` format. When set, the API returns only cases modified since this time. Omit to pull all cases (first run). |

Endpoint called: `GET {SERVICENOW_CASES_INSTANCE_URL}/api/sn_customerservice/paramify_evidence/cases`

### `servicenow_changes`

| Variable | Required | Description |
|---|---|---|
| `SERVICENOW_CHANGES_INSTANCE_URL` | Yes | Base URL of the ServiceNow instance that hosts the ITSM changes API, e.g. `https://humanifygdev.service-now.com` |
| `SERVICENOW_CHANGES_LAST_RUN` | No | Watermark timestamp in `YYYY-MM-DD HH:MM:SS` format. When set, the API returns only changes modified since this time. Omit to pull all changes (first run). |

Endpoint called: `GET {SERVICENOW_CHANGES_INSTANCE_URL}/api/g_ttec/paramify_itsm/changes`

---

## Output files

| Fetcher | Output file |
|---|---|
| `servicenow_cases` | `$EVIDENCE_DIR/servicenow_cases.json` |
| `servicenow_changes` | `$EVIDENCE_DIR/servicenow_changes.json` |

Both fetchers write the raw JSON response from the API without any transformation.

---

## Example `.env`

```dotenv
SERVICENOW_API_TOKEN=your-bearer-token-here

SERVICENOW_CASES_INSTANCE_URL=https://humanifygdev.servicenowservices.com
# SERVICENOW_CASES_LAST_RUN=2024-01-01 00:00:00

SERVICENOW_CHANGES_INSTANCE_URL=https://humanifygdev.service-now.com
# SERVICENOW_CHANGES_LAST_RUN=2024-01-01 00:00:00
```
