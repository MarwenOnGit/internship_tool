# Fix Consumption Plan Detection + Debug Token Extraction

## Problem
1. Flex Consumption and regular Consumption both show `kind="functionapp,linux"` — detection via kind is wrong.
2. `consumption-func-app` (regular Consumption) returns Kudu 200 but no IMDS token — need to see raw output.

## Changes

### 1. `arm_enum.py` — `AppService` dataclass
Add `server_farm_id: str | None = None`

### 2. `arm_enum.py` — `list_app_services()`
```python
apps.append(AppService(
    ...
    site_url=props.get("defaultHostName"),
    server_farm_id=props.get("serverFarmId"),
))
```

### 3. `arm_enum.py` — `enrich_app_service_capabilities()`
Replace the `kind`-based detection with an ARM query to the server farm:

```python
# Query server farm to detect plan type
if app.server_farm_id:
    try:
        plan_resp = _arm_get(token, app.server_farm_id, api_version="2023-12-01")
        if plan_resp and isinstance(plan_resp, dict):
            sku = plan_resp.get("sku", {}) or {}
            tier = (sku.get("tier") or "").lower()
            if "flexconsumption" in tier:
                app.plan_tier = "Flex Consumption"
                app.kudu_command_supported = False
            elif "dynamic" in tier:
                app.plan_tier = "Consumption"
                app.kudu_command_supported = True
            elif "premium" in tier or "elastic" in tier:
                app.plan_tier = "Premium"
                app.kudu_command_supported = True
            else:
                app.plan_tier = tier or "Unknown"
                app.kudu_command_supported = True
    except Exception:
        log.debug("Failed to query server farm %s", app.server_farm_id)
```

Keep the existing `kind`-based fallback for apps without a serverFarmId.

### 4. `resource_exploit.py` — Debug logging
In `exploit_app_service_kudu()`, change the no-token log from `DEBUG` to `INFO` so the user can see the raw Output:

```python
log.info(
    "Kudu curl output did not contain an IMDS token. "
    "Raw output (first 300 chars): %.300s; parsed: %s",
    output, parsed,
)
```

Same for the PowerShell fallback.

## Verification
1. Run `fenrir exploit` — the output should now:
   - Show `[TOKEN-X\]` (cyan) instead of `[TOKEN\]` for Flex Consumption apps
   - Attempt token extraction only on regular Consumption apps
   - Log the raw Kudu Output for `consumption-func-app` so we can see what the identity endpoint returns
