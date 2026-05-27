# ocsf-transformer

**Vendor Log → [OCSF](https://schema.ocsf.io) Schema Transformer**

A security-engineer utility that normalises raw vendor logs from Microsoft Entra ID, Wiz, and Palo Alto Networks PAN-OS into the [Open Cybersecurity Schema Framework (OCSF) 1.3.0](https://schema.ocsf.io) — the lingua franca for modern SIEMs and security data lakes.

---

## Table of Contents

1. [Why OCSF?](#why-ocsf)
2. [Supported Vendors & OCSF Classes](#supported-vendors--ocsf-classes)
3. [Quick Start](#quick-start)
4. [CLI Reference](#cli-reference)
5. [Mapping Logic & Schema Decisions](#mapping-logic--schema-decisions)
   - [Microsoft Entra ID → Authentication (3002)](#microsoft-entra-id--authentication-3002)
   - [Wiz → Configuration Finding (5019)](#wiz--configuration-finding-5019)
   - [Palo Alto PAN-OS → Network Activity (4001)](#palo-alto-pan-os--network-activity-4001)
6. [Sample Data](#sample-data)
7. [OCSF Envelope & Common Fields](#ocsf-envelope--common-fields)
8. [Downstream SIEM / Lakehouse Analytics](#downstream-siem--lakehouse-analytics)
9. [Extending with a New Vendor](#extending-with-a-new-vendor)
10. [Design Decisions & Trade-offs](#design-decisions--trade-offs)

---

## Why OCSF?

Every security vendor ships logs in its own proprietary schema. A sign-in failure looks different in Entra ID, Okta, and Duo; a misconfigured cloud asset looks different in Wiz, Prisma, and AWS Security Hub. This forces analysts to maintain brittle, per-source parsing rules and makes cross-vendor correlation expensive.

OCSF solves this by providing:

- **Stable class UIDs** — every event type has a permanent integer ID (e.g. `3002` = Authentication). Downstream queries never break when a vendor renames a field.
- **Normalised taxonomy** — `status_id`, `severity_id`, `user.name`, `src_endpoint.ip` mean the same thing regardless of source.
- **Extensibility via `unmapped`** — vendor-specific fields are preserved rather than dropped, so no signal is lost.
- **Schema URL in metadata** — every event carries `schema_url` so consumers can self-describe.

---

## Supported Vendors & OCSF Classes

| Key | Vendor | Log Type | OCSF Class | Class UID | Category UID |
|-----|--------|----------|------------|-----------|--------------|
| `entra` | Microsoft Entra ID | Sign-In logs | Authentication | 3002 | 3 (Identity & Access Mgmt) |
| `wiz` | Wiz | Issues / Findings | Configuration Finding | 5019 | 2 (Findings) |
| `pan` | Palo Alto Networks | PAN-OS Auth (JSON) | Network Activity | 4001 | 4 (Network Activity) |

---

## Quick Start

```bash
# Single file, explicit vendor
python ocsf_transformer.py --vendor entra --input sample_data/entra_signin_before.json --output out.json

# Auto-detect vendor from payload shape
python ocsf_transformer.py --input sample_data/wiz_finding_before.json --stdout

# Pipe mode
cat sample_data/pan_auth_before.json | python ocsf_transformer.py --vendor pan --stdin

# List all supported vendors
python ocsf_transformer.py --list-vendors
```

No external dependencies — standard library only.

---

## CLI Reference

```
usage: ocsf_transformer.py [-h] [--vendor {entra,wiz,pan}]
                           [--input PATH] [--output PATH]
                           [--stdin] [--stdout]
                           [--include-raw] [--include-failures]
                           [--list-vendors] [--verbose]
```

| Flag | Description |
|------|-------------|
| `--vendor` | Force a specific vendor parser. Omit to auto-detect. |
| `--input` | Path to raw JSON input (single event `{}` or array `[{},…]`). |
| `--output` | Path to write OCSF JSON. Defaults to stdout if omitted. |
| `--stdin` | Read raw JSON from stdin. |
| `--stdout` | Print OCSF JSON to stdout (useful for piping). |
| `--include-raw` | Preserve original event under `_raw` key in output. Stripped by default to reduce payload size. |
| `--include-failures` | Wrap output as `{"events": […], "failures": […]}` so failed events are visible. |
| `--list-vendors` | Print supported vendor keys and exit. |
| `--verbose` / `-v` | Enable DEBUG logging to stderr. |

**Exit codes:** `0` = all events transformed successfully; `1` = one or more events failed.

---

## Mapping Logic & Schema Decisions

### Microsoft Entra ID → Authentication (3002)

**Source:** Microsoft Graph API sign-in logs (`/auditLogs/signIns`).

**Activity ID selection:**

| Entra `authenticationRequirement` | OCSF `activity_id` | `activity_name` |
|-----------------------------------|--------------------|-----------------|
| contains `multiFactorAuthentication` | `4` | MFA Challenge |
| anything else | `1` | Logon |

**Status mapping:**

`status.errorCode == 0` → `SUCCESS (1)`. Any other error code → `FAILURE (2)`. Missing error code → `UNKNOWN (0)`.

**Severity mapping** (driven by `riskLevelDuringSignIn`):

| Entra risk level | OCSF `severity_id` |
|------------------|--------------------|
| `none` | `1` — Informational |
| `low` | `2` — Low |
| `medium` | `3` — Medium |
| `high` | `4` — High |
| `hidden` | `0` — Unknown |

**Key field mappings:**

| Entra field | OCSF path |
|-------------|-----------|
| `userPrincipalName` | `user.name` |
| `userId` | `user.uid` |
| `userDisplayName` | `user.full_name` |
| `appDisplayName` | `service.name` |
| `ipAddress` | `src_endpoint.ip` |
| `location.*` | `src_endpoint.location.*` |
| `deviceDetail.*` | `device.*` |
| `mfaDetail.authMethod` | `authentication.mfa_method` |
| `conditionalAccessStatus` | `authentication.conditional_access` |
| `tokenIssuanceType` | `authentication.token_issuance_type` |
| `riskLevelDuringSignIn` | `risk_details.level_during_signin` + `severity` |

**Schema decision:** Entra's `status.failureReason` is a human-readable string, not a stable code, so it is mapped to `status` (string) rather than `status_id`. The numeric `errorCode` goes to `status_code` for downstream parsing.

---

### Wiz → Configuration Finding (5019)

**Source:** Wiz Issues API or SIEM export.

**Activity ID selection** (driven by `status`):

| Wiz `status` | OCSF `activity_id` | `activity_name` |
|--------------|--------------------|-----------------|
| `OPEN` | `1` | Create |
| `IN_PROGRESS` | `2` | Update |
| `RESOLVED` | `3` | Close |
| `REJECTED` | `3` | Close |

**Severity mapping** (direct 1-to-1):

`INFORMATIONAL → 1`, `LOW → 2`, `MEDIUM → 3`, `HIGH → 4`, `CRITICAL → 5`.

**Key field mappings:**

| Wiz field | OCSF path |
|-----------|-----------|
| `name` | `finding.title` |
| `description` | `finding.description` |
| `remediation` | `finding.remediation.desc` |
| `type.name` | `finding.type` |
| `rule.id / .name / .shortId` | `rule.*` |
| `resource.id / .name / .type` | `resource.*` |
| `resource.cloudProvider` | `resource.cloud.provider` |
| `resource.region` | `resource.cloud.region` |
| `resource.subscription.externalId` | `resource.cloud.account.uid` |
| `frameworks` | `compliance.requirements` |
| `note` | `comment` |
| `resolvedAt` | `end_time` |

**Schema decision:** Wiz `status` values (`OPEN`, `RESOLVED`, etc.) don't map cleanly to OCSF `status_id` (which is oriented toward success/failure). `OPEN` and `IN_PROGRESS` are mapped to `OTHER (99)` rather than `FAILURE`, because an open finding is not a failed operation — it is a state. `RESOLVED` maps to `SUCCESS` to indicate the finding lifecycle completed successfully.

---

### Palo Alto PAN-OS → Network Activity (4001)

**Source:** PAN-OS 10.1+ JSON syslog (AUTH log type). Requires `type == "AUTH"` + `device_name` in the payload for auto-detection.

**Design rationale for class selection:** PAN-OS auth logs represent a *network-layer authentication attempt* (VPN, GlobalProtect, Captive Portal) rather than an identity-provider sign-in. OCSF Network Activity (4001) better models the firewall's role as a network enforcement point. The `connection_info` object carries auth-specific context.

**Activity ID selection** (driven by `event`):

| PAN-OS `event` | OCSF `activity_id` | `activity_name` | `status_id` |
|----------------|---------------------|-----------------|-------------|
| `auth-success` | `1` — Open | Open | `1` Success |
| `sso-logon` | `1` — Open | Open | `1` Success |
| `auth-challenge` | `1` — Open | Open | `99` Other |
| `auth-fail` | `4` — Fail | Fail | `2` Failure |
| `auth-timeout` | `4` — Fail | Fail | `2` Failure |
| `logout` | `2` — Close | Close | `1` Success |
| `sso-logoff` | `2` — Close | Close | `1` Success |

**MFA detection:** `factorno > 1` sets `connection_info.is_mfa = true`. PAN-OS uses `factorno` to indicate which authentication factor step is being reported.

**Timestamp handling:** Prefers `high_res_timestamp` (ISO-8601 with microseconds and TZ offset, PAN-OS 10.1+) over `time_generated` (local time string `YYYY/MM/DD HH:MM:SS`). Both are normalised to epoch milliseconds UTC.

**Severity mapping:**

| Outcome | OCSF `severity_id` |
|---------|--------------------|
| `FAILURE` | `2` — Low |
| All other outcomes | `1` — Informational |

Auth failures are Low rather than Medium/High because a single failure is expected noise. Consumers should apply their own thresholding/aggregation rules upstream for brute-force detection.

**Key field mappings:**

| PAN-OS field | OCSF path |
|--------------|-----------|
| `normalize_user` / `user` | `user.name` / `user.uid` |
| `ip` | `src_endpoint.ip` |
| `clienttype` | `src_endpoint.type` |
| `device_name` | `dst_endpoint.name` + `device.name` |
| `serial` | `dst_endpoint.uid` + `device.uid` |
| `authproto` / `vendor` | `connection_info.auth_protocol` |
| `authpolicy` | `connection_info.auth_policy` + `policy.name` |
| `object` | `connection_info.auth_object` (e.g. `GlobalProtect`) |
| `factorno` | `connection_info.factor_no` + `connection_info.is_mfa` |
| `vsys` / `vsys_name` | `device.vsys` |
| `rule_uuid` | `policy.uid` |

---

## Sample Data

The `sample_data/` directory contains before/after pairs for all three vendors:

```
sample_data/
├── entra_signin_before.json    # Raw Entra ID sign-in log
├── entra_signin_after.json     # Normalised OCSF Authentication (3002)
├── wiz_finding_before.json     # Raw Wiz HIGH finding
├── wiz_finding_after.json      # Normalised OCSF Config Finding (5019)
├── pan_auth_before.json        # Raw PAN-OS auth logs (success + fail)
└── pan_auth_after.json         # Normalised OCSF Network Activity (4001)
```

---

## OCSF Envelope & Common Fields

Every transformed event carries these top-level fields regardless of vendor:

| Field | Type | Description |
|-------|------|-------------|
| `ocsf_version` | string | Always `"1.3.0"` |
| `class_uid` | int | OCSF class identifier |
| `category_uid` | int | OCSF category identifier |
| `activity_id` | int | Activity within the class |
| `activity_name` | string | Human-readable activity label |
| `time` | int | Event time as epoch milliseconds UTC |
| `metadata.uid` | string | Deterministic UUID (SHA-256 of vendor + source ID) — idempotent on re-ingestion |
| `metadata.product.vendor_name` | string | Source vendor |
| `metadata.processed_time` | int | Transform time as epoch milliseconds UTC |
| `metadata.schema_url` | string | `https://schema.ocsf.io` |
| `status` | string | Human-readable status |
| `status_id` | int | Normalised status (0=Unknown, 1=Success, 2=Failure, 99=Other) |
| `severity` | string | Human-readable severity |
| `severity_id` | int | Normalised severity (0–6) |
| `unmapped` | object | Vendor fields not covered by the OCSF mapping |

**Idempotent UIDs:** `metadata.uid` is a deterministic UUID derived from `sha256(vendor | source_event_id)`. Re-ingesting the same raw event always produces the same UID, which allows upsert semantics in a data lakehouse without deduplication scans.

---

## Downstream SIEM / Lakehouse Analytics

### Why this accelerates analytics

**1. Schema-on-write, not schema-on-read.**
Without normalisation, a query like "show me all failed authentications in the last hour" requires a `UNION` across Entra, Okta, PAN-OS, and Duo tables, each with a different field name for "failure." With OCSF, the query is:

```sql
SELECT time, user.name, src_endpoint.ip, metadata.product.vendor_name
FROM security_events
WHERE class_uid = 3002        -- Authentication
  AND status_id = 2           -- Failure
  AND time > (UNIX_MILLIS(CURRENT_TIMESTAMP()) - 3600000)
ORDER BY time DESC;
```

This query works identically whether the event came from Entra or PAN-OS.

**2. Partitioning strategy.**
Because `class_uid` and `category_uid` are stable integers present on every event, a lakehouse can partition by `(class_uid, date)` — giving optimal partition pruning for class-specific queries without vendor-specific table sprawl.

```
s3://security-lake/
  class_uid=3002/date=2024-05-01/   ← all authentication events
  class_uid=4001/date=2024-05-01/   ← all network activity events
  class_uid=5019/date=2024-05-01/   ← all config findings
```

**3. Cross-vendor correlation.**
`metadata.uid` enables deduplication. `user.name` (always UPN form where available) enables joining authentication events across Entra and PAN-OS on a single identity key without bespoke normalisation logic.

**4. Severity-based alerting.**
`severity_id` is a normalised integer across all vendors — a single alerting rule fires on `severity_id >= 4` (High/Critical) regardless of whether the source is Wiz, Entra, or a future vendor.

**5. Preserving raw signal.**
The `unmapped` object retains all vendor-specific fields not covered by OCSF. In a lakehouse context, `unmapped` can be stored as a JSON column, ensuring no signal is lost while keeping the normalised columns queryable without schema churn.

### Recommended ingestion pattern

```
Vendor API / Syslog
      │
      ▼
ocsf_transformer.py   (this tool — stateless, pipeable)
      │
      ▼
Kafka / Kinesis topic  (partitioned by class_uid)
      │
      ▼
Parquet / Delta Lake   (partitioned by class_uid + date)
      │
      ├──► SIEM correlation rules  (query normalised fields)
      └──► Notebook / BI layer     (ad-hoc investigation)
```

---

## Extending with a New Vendor

1. **Subclass `BaseTransformer`:**

```python
class MyVendorTransformer(BaseTransformer):
    VENDOR_NAME = "My Vendor"

    def can_handle(self, raw: dict) -> bool:
        # Return True if the payload looks like a MyVendor event
        return bool(raw.get("myvendor_specific_field"))

    def transform(self, raw: dict) -> dict:
        envelope = self._base_envelope(
            class_uid=OCSFClassID.AUTHENTICATION,   # pick the right class
            category_uid=OCSFCategory.IDENTITY_ACCESS,
            activity_id=OCSFActivityID.AUTH_LOGON,
            activity_name="Logon",
            time_ms=_iso_to_epoch_ms(raw.get("timestamp")) or _now_epoch_ms(),
            uid=_stable_uid("myvendor", raw.get("id", "")),
            raw=raw,
        )
        # populate OCSF fields …
        return envelope
```

2. **Register it:**

```python
TRANSFORMERS["myvendor"] = MyVendorTransformer()
```

3. **Add sample data** to `sample_data/` and document mappings in this README.

---

## Design Decisions & Trade-offs

| Decision | Rationale |
|----------|-----------|
| **No external dependencies** | `ocsf_transformer.py` runs anywhere Python 3.10+ is available — no pip install, no virtualenv friction. |
| **Deterministic UIDs** | SHA-256–derived UUIDs make re-ingestion safe and enable upsert semantics in Iceberg/Delta without a full deduplication scan. |
| **`_raw` stripped by default** | Storing the original event doubles payload size. `--include-raw` opts back in for debugging or full-fidelity archival. |
| **`unmapped` catch-all** | OCSF compliance does not require every vendor field to have a named mapping. Preserving unmapped fields as a JSON blob avoids schema churn while keeping all signal available. |
| **Failures are non-fatal** | `ingest()` continues processing the batch even if individual events fail. Use `--include-failures` to surface failures without aborting the pipeline. |
| **Auto-detection by payload shape** | `can_handle()` fingerprints are deliberately conservative (require multiple distinctive fields) to avoid false positives when mixing vendor feeds in a single batch. |
| **PAN-OS → Network Activity, not Authentication** | PAN-OS is a network enforcement point. Authentication (3002) is more appropriate for IdP-sourced events. Network Activity (4001) better reflects firewall-mediated access control. |
| **Auth failures → Low severity** | A single auth failure is expected noise. Severity escalation (brute force) is a higher-level detection concern best handled by the SIEM's aggregation layer, not the transformer. |
