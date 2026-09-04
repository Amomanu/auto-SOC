"""
Microsoft Sentinel & Defender MCP Server
Surfaces: Sentinel, Entra ID, Email Remediation, AIR
Multi-tenant support via tenants.json config file.
"""

import os
import json
import uuid
import httpx
from pathlib import Path
from time import time
from mcp.server.fastmcp import FastMCP

from azure.identity import ClientSecretCredential

mcp = FastMCP("sentinel-security")

# ---------------------------------------------------------------------------
# Multi-tenant configuration
# ---------------------------------------------------------------------------

_CONFIG_PATH = Path(__file__).parent / "tenants.json"
_config = None
_credentials = {}
_token_cache = {}

MGMT_SCOPE         = "https://management.azure.com/.default"
LOG_ANALYTICS_SCOPE = "https://api.loganalytics.io/.default"
GRAPH_SCOPE         = "https://graph.microsoft.com/.default"

SENTINEL_API_VERSION = "2024-03-01"
GRAPH_V1             = "https://graph.microsoft.com/v1.0"
GRAPH_BETA           = "https://graph.microsoft.com/beta"


def _load_config() -> dict:
    global _config
    if _config is not None:
        return _config
    if not _CONFIG_PATH.exists():
        raise RuntimeError(
            f"tenants.json not found at {_CONFIG_PATH}. "
            "Copy tenants.json.example to tenants.json and fill in your credentials."
        )
    _config = json.loads(_CONFIG_PATH.read_text())
    return _config


def _resolve_tenant(tenant: str = "") -> dict:
    cfg = _load_config()
    name = tenant or cfg.get("default_tenant", "")
    if not name:
        raise ValueError(
            "No tenant specified and no default_tenant set in tenants.json."
        )
    tenants = cfg.get("tenants", {})
    if name not in tenants:
        available = ", ".join(tenants.keys())
        raise ValueError(f"Tenant '{name}' not found. Available: {available}")
    return tenants[name]


# ---------------------------------------------------------------------------
# Auth helpers (per-tenant)
# ---------------------------------------------------------------------------

def _get_credential(tenant: str = "") -> ClientSecretCredential:
    t = _resolve_tenant(tenant)
    key = t["tenant_id"]
    if key not in _credentials:
        if not all([t.get("tenant_id"), t.get("client_id"), t.get("client_secret")]):
            raise RuntimeError(
                f"Incomplete credentials for tenant. "
                "Ensure tenant_id, client_id, and client_secret are set."
            )
        _credentials[key] = ClientSecretCredential(
            tenant_id=t["tenant_id"],
            client_id=t["client_id"],
            client_secret=t["client_secret"],
        )
    return _credentials[key]


def _get_token(scope: str, tenant: str = "") -> str:
    t = _resolve_tenant(tenant)
    cache_key = f"{t['tenant_id']}:{scope}"
    cached = _token_cache.get(cache_key)
    if cached and cached["expires_on"] > time() + 60:
        return cached["token"]
    cred = _get_credential(tenant)
    token = cred.get_token(scope)
    _token_cache[cache_key] = {"token": token.token, "expires_on": token.expires_on}
    return token.token


def _headers(scope: str, tenant: str = "") -> dict:
    return {
        "Authorization": f"Bearer {_get_token(scope, tenant)}",
        "Content-Type": "application/json",
    }


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------

async def _call(method: str, url: str, scope: str, tenant: str = "", *,
                body: dict = None, params: dict = None) -> dict:
    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.request(
            method, url,
            headers=_headers(scope, tenant),
            json=body,
            params=params,
        )
        if resp.status_code == 204:
            return {"status": "success", "http_status": 204}
        if not resp.is_success:
            return {
                "error": True,
                "http_status": resp.status_code,
                "detail": resp.text[:2000],
            }
        return resp.json()


def _sentinel_base(tenant: str = "") -> str:
    t = _resolve_tenant(tenant)
    sub = t.get("sentinel_subscription_id", "")
    rg  = t.get("sentinel_resource_group", "")
    ws  = t.get("sentinel_workspace_name", "")
    if not all([sub, rg, ws]):
        raise ValueError(
            "sentinel_subscription_id, sentinel_resource_group, and "
            "sentinel_workspace_name must be set in tenants.json for this tenant."
        )
    return (
        f"https://management.azure.com/subscriptions/{sub}"
        f"/resourceGroups/{rg}"
        f"/providers/Microsoft.OperationalInsights/workspaces/{ws}"
        f"/providers/Microsoft.SecurityInsights"
    )


def _workspace_id(tenant: str = "") -> str:
    t = _resolve_tenant(tenant)
    ws_id = t.get("sentinel_workspace_id", "")
    if not ws_id:
        raise ValueError("sentinel_workspace_id must be set in tenants.json for this tenant.")
    return ws_id


# =========================================================================
#  UTILITY
# =========================================================================

@mcp.tool()
async def list_tenants() -> str:
    """List all configured tenants and which one is the default."""
    cfg = _load_config()
    default = cfg.get("default_tenant", "")
    tenants = []
    for name, t in cfg.get("tenants", {}).items():
        tenants.append({
            "name": name,
            "is_default": name == default,
            "tenant_id": t.get("tenant_id", "")[:8] + "...",
            "has_sentinel": bool(t.get("sentinel_workspace_id")),
        })
    return json.dumps(tenants, indent=2)


# =========================================================================
#  SENTINEL — KQL, Incidents, Alerts, Entities
# =========================================================================

@mcp.tool()
async def run_kql_query(
    query: str,
    tenant: str = "",
    timespan: str = "P1D",
) -> str:
    """Run a KQL query against a Log Analytics workspace.

    Args:
        query: KQL query string
        tenant: Tenant name from tenants.json (uses default if empty)
        timespan: ISO 8601 duration — P1D (1 day), PT1H (1 hour), P7D (7 days)
    """
    ws_id = _workspace_id(tenant)
    result = await _call(
        "POST",
        f"https://api.loganalytics.io/v1/workspaces/{ws_id}/query",
        LOG_ANALYTICS_SCOPE, tenant,
        body={"query": query, "timespan": timespan},
    )
    if result.get("error"):
        return json.dumps(result, indent=2)

    tables = result.get("tables", [])
    if not tables:
        return "No results."

    output = []
    for table in tables:
        columns = [c["name"] for c in table.get("columns", [])]
        rows = table.get("rows", [])
        output.append(f"Columns: {', '.join(columns)}")
        output.append(f"Rows: {len(rows)}")
        for row in rows[:100]:
            output.append(json.dumps(dict(zip(columns, row))))
        if len(rows) > 100:
            output.append(f"... {len(rows) - 100} more rows truncated")
    return "\n".join(output)


@mcp.tool()
async def list_incidents(
    tenant: str = "",
    status: str = "",
    severity: str = "",
    top: int = 25,
) -> str:
    """List Sentinel incidents.

    Args:
        tenant: Tenant name from tenants.json (uses default if empty)
        status: New, Active, or Closed (optional filter)
        severity: High, Medium, Low, or Informational (optional filter)
        top: Max results (default 25)
    """
    base = _sentinel_base(tenant)
    filters = []
    if status:
        filters.append(f"properties/status eq '{status}'")
    if severity:
        filters.append(f"properties/severity eq '{severity}'")

    params = {
        "api-version": SENTINEL_API_VERSION,
        "$top": str(top),
        "$orderby": "properties/createdTimeUtc desc",
    }
    if filters:
        params["$filter"] = " and ".join(filters)

    result = await _call("GET", f"{base}/incidents", MGMT_SCOPE, tenant, params=params)
    if result.get("error"):
        return json.dumps(result, indent=2)

    incidents = []
    for inc in result.get("value", []):
        p = inc.get("properties", {})
        incidents.append({
            "id": inc.get("name"),
            "number": p.get("incidentNumber"),
            "title": p.get("title"),
            "severity": p.get("severity"),
            "status": p.get("status"),
            "created": p.get("createdTimeUtc"),
            "owner": p.get("owner", {}).get("userPrincipalName"),
        })
    return json.dumps(incidents, indent=2)


@mcp.tool()
async def get_incident(
    incident_id: str,
    tenant: str = "",
) -> str:
    """Get full details of a Sentinel incident.

    Args:
        incident_id: Incident ID (GUID)
        tenant: Tenant name from tenants.json (uses default if empty)
    """
    base = _sentinel_base(tenant)
    result = await _call(
        "GET", f"{base}/incidents/{incident_id}", MGMT_SCOPE, tenant,
        params={"api-version": SENTINEL_API_VERSION},
    )
    return json.dumps(result, indent=2)


@mcp.tool()
async def update_incident(
    incident_id: str,
    tenant: str = "",
    status: str = "",
    severity: str = "",
    classification: str = "",
    classification_reason: str = "",
    classification_comment: str = "",
) -> str:
    """Update a Sentinel incident.

    Args:
        incident_id: Incident ID (GUID)
        tenant: Tenant name from tenants.json (uses default if empty)
        status: New, Active, or Closed
        severity: High, Medium, Low, or Informational
        classification: BenignPositive, FalsePositive, TruePositive, Undetermined
        classification_reason: InaccurateData, IncorrectAlertLogic, SuspiciousActivity, SuspiciousButExpected
        classification_comment: Free-text explanation
    """
    base = _sentinel_base(tenant)
    api_params = {"api-version": SENTINEL_API_VERSION}

    current = await _call(
        "GET", f"{base}/incidents/{incident_id}", MGMT_SCOPE, tenant, params=api_params,
    )
    if current.get("error"):
        return json.dumps(current, indent=2)

    props = current.get("properties", {})
    if status:
        props["status"] = status
    if severity:
        props["severity"] = severity
    if classification:
        props["classification"] = classification
    if classification_reason:
        props["classificationReason"] = classification_reason
    if classification_comment:
        props["classificationComment"] = classification_comment

    current["properties"] = props
    result = await _call(
        "PUT", f"{base}/incidents/{incident_id}", MGMT_SCOPE, tenant,
        body=current, params=api_params,
    )
    if result.get("error"):
        return json.dumps(result, indent=2)
    return json.dumps({"status": "updated", "incident_id": incident_id})


@mcp.tool()
async def close_incident(
    incident_id: str,
    classification: str,
    tenant: str = "",
    classification_reason: str = "",
    classification_comment: str = "",
) -> str:
    """Close a Sentinel incident with a classification.

    Args:
        incident_id: Incident ID (GUID)
        classification: BenignPositive, FalsePositive, TruePositive, Undetermined
        tenant: Tenant name from tenants.json (uses default if empty)
        classification_reason: InaccurateData, IncorrectAlertLogic, SuspiciousActivity, SuspiciousButExpected
        classification_comment: Free-text explanation
    """
    return await update_incident(
        incident_id=incident_id,
        tenant=tenant,
        status="Closed",
        classification=classification,
        classification_reason=classification_reason,
        classification_comment=classification_comment,
    )


@mcp.tool()
async def add_incident_comment(
    incident_id: str,
    message: str,
    tenant: str = "",
) -> str:
    """Add a comment to a Sentinel incident.

    Args:
        incident_id: Incident ID (GUID)
        message: Comment text (supports markdown)
        tenant: Tenant name from tenants.json (uses default if empty)
    """
    base = _sentinel_base(tenant)
    comment_id = str(uuid.uuid4())
    result = await _call(
        "PUT",
        f"{base}/incidents/{incident_id}/comments/{comment_id}",
        MGMT_SCOPE, tenant,
        body={"properties": {"message": message}},
        params={"api-version": SENTINEL_API_VERSION},
    )
    if result.get("error"):
        return json.dumps(result, indent=2)
    return json.dumps({"status": "comment_added", "incident_id": incident_id})


@mcp.tool()
async def get_incident_alerts(
    incident_id: str,
    tenant: str = "",
) -> str:
    """Get alerts associated with a Sentinel incident.

    Args:
        incident_id: Incident ID (GUID)
        tenant: Tenant name from tenants.json (uses default if empty)
    """
    base = _sentinel_base(tenant)
    result = await _call(
        "POST", f"{base}/incidents/{incident_id}/alerts", MGMT_SCOPE, tenant,
        params={"api-version": SENTINEL_API_VERSION},
    )
    return json.dumps(result, indent=2)


@mcp.tool()
async def get_incident_entities(
    incident_id: str,
    tenant: str = "",
) -> str:
    """Get entities (users, IPs, hosts, files) linked to a Sentinel incident.

    Args:
        incident_id: Incident ID (GUID)
        tenant: Tenant name from tenants.json (uses default if empty)
    """
    base = _sentinel_base(tenant)
    result = await _call(
        "POST", f"{base}/incidents/{incident_id}/entities", MGMT_SCOPE, tenant,
        params={"api-version": SENTINEL_API_VERSION},
    )
    return json.dumps(result, indent=2)


# =========================================================================
#  ENTRA ID — Users, Sign-ins, Risk, MFA, Remediation
# =========================================================================

@mcp.tool()
async def get_user(user_id: str, tenant: str = "") -> str:
    """Get Entra ID user details.

    Args:
        user_id: UPN (email) or object ID
        tenant: Tenant name from tenants.json (uses default if empty)
    """
    result = await _call(
        "GET", f"{GRAPH_V1}/users/{user_id}", GRAPH_SCOPE, tenant,
        params={
            "$select": (
                "id,displayName,userPrincipalName,mail,accountEnabled,"
                "createdDateTime,jobTitle,department,officeLocation,"
                "mobilePhone,userType"
            )
        },
    )
    return json.dumps(result, indent=2)


@mcp.tool()
async def get_user_sign_in_logs(
    tenant: str = "",
    user_principal_name: str = "",
    top: int = 25,
) -> str:
    """Get Entra ID sign-in logs, optionally filtered by user.

    Args:
        tenant: Tenant name from tenants.json (uses default if empty)
        user_principal_name: UPN to filter by (optional)
        top: Max results (default 25)
    """
    params = {"$top": str(top), "$orderby": "createdDateTime desc"}
    if user_principal_name:
        params["$filter"] = f"userPrincipalName eq '{user_principal_name}'"

    result = await _call(
        "GET", f"{GRAPH_BETA}/auditLogs/signIns", GRAPH_SCOPE, tenant, params=params,
    )
    if result.get("error"):
        return json.dumps(result, indent=2)

    logs = []
    for e in result.get("value", []):
        logs.append({
            "createdDateTime": e.get("createdDateTime"),
            "userPrincipalName": e.get("userPrincipalName"),
            "appDisplayName": e.get("appDisplayName"),
            "ipAddress": e.get("ipAddress"),
            "location": e.get("location"),
            "status": e.get("status"),
            "conditionalAccessStatus": e.get("conditionalAccessStatus"),
            "riskLevelDuringSignIn": e.get("riskLevelDuringSignIn"),
            "riskDetail": e.get("riskDetail"),
        })
    return json.dumps(logs, indent=2)


@mcp.tool()
async def get_risky_users(tenant: str = "", top: int = 25) -> str:
    """Get users flagged as risky by Identity Protection.

    Args:
        tenant: Tenant name from tenants.json (uses default if empty)
        top: Max results (default 25)
    """
    result = await _call(
        "GET", f"{GRAPH_BETA}/identityProtection/riskyUsers", GRAPH_SCOPE, tenant,
        params={"$top": str(top), "$orderby": "riskLastUpdatedDateTime desc"},
    )
    if result.get("error"):
        return json.dumps(result, indent=2)

    users = []
    for u in result.get("value", []):
        users.append({
            "id": u.get("id"),
            "userPrincipalName": u.get("userPrincipalName"),
            "displayName": u.get("userDisplayName"),
            "riskLevel": u.get("riskLevel"),
            "riskState": u.get("riskState"),
            "riskDetail": u.get("riskDetail"),
            "riskLastUpdated": u.get("riskLastUpdatedDateTime"),
        })
    return json.dumps(users, indent=2)


@mcp.tool()
async def get_risky_sign_ins(tenant: str = "", top: int = 25) -> str:
    """Get risky sign-in detections from Identity Protection.

    Args:
        tenant: Tenant name from tenants.json (uses default if empty)
        top: Max results (default 25)
    """
    result = await _call(
        "GET", f"{GRAPH_BETA}/identityProtection/riskDetections", GRAPH_SCOPE, tenant,
        params={"$top": str(top), "$orderby": "activityDateTime desc"},
    )
    if result.get("error"):
        return json.dumps(result, indent=2)

    detections = []
    for d in result.get("value", []):
        detections.append({
            "id": d.get("id"),
            "userPrincipalName": d.get("userPrincipalName"),
            "riskType": d.get("riskEventType"),
            "riskLevel": d.get("riskLevel"),
            "riskState": d.get("riskState"),
            "ipAddress": d.get("ipAddress"),
            "location": d.get("location"),
            "activityDateTime": d.get("activityDateTime"),
        })
    return json.dumps(detections, indent=2)


@mcp.tool()
async def get_user_groups(user_id: str, tenant: str = "") -> str:
    """Get group and role memberships for a user.

    Args:
        user_id: UPN (email) or object ID
        tenant: Tenant name from tenants.json (uses default if empty)
    """
    result = await _call(
        "GET", f"{GRAPH_V1}/users/{user_id}/memberOf", GRAPH_SCOPE, tenant,
        params={"$select": "id,displayName,groupTypes,securityEnabled,mailEnabled"},
    )
    if result.get("error"):
        return json.dumps(result, indent=2)

    groups = []
    for g in result.get("value", []):
        groups.append({
            "id": g.get("id"),
            "displayName": g.get("displayName"),
            "type": g.get("@odata.type"),
            "securityEnabled": g.get("securityEnabled"),
        })
    return json.dumps(groups, indent=2)


@mcp.tool()
async def get_user_auth_methods(user_id: str, tenant: str = "") -> str:
    """Get MFA / authentication methods registered for a user.

    Args:
        user_id: UPN (email) or object ID
        tenant: Tenant name from tenants.json (uses default if empty)
    """
    result = await _call(
        "GET", f"{GRAPH_BETA}/users/{user_id}/authentication/methods",
        GRAPH_SCOPE, tenant,
    )
    if result.get("error"):
        return json.dumps(result, indent=2)

    methods = []
    for m in result.get("value", []):
        methods.append({
            "id": m.get("id"),
            "type": m.get("@odata.type", "").rsplit(".", 1)[-1],
            "displayName": m.get("displayName"),
            "phoneNumber": m.get("phoneNumber"),
            "emailAddress": m.get("emailAddress"),
        })
    return json.dumps(methods, indent=2)


@mcp.tool()
async def disable_user(user_id: str, tenant: str = "") -> str:
    """Disable an Entra ID user account (blocks sign-in).

    Args:
        user_id: UPN (email) or object ID
        tenant: Tenant name from tenants.json (uses default if empty)
    """
    result = await _call(
        "PATCH", f"{GRAPH_V1}/users/{user_id}", GRAPH_SCOPE, tenant,
        body={"accountEnabled": False},
    )
    if result.get("error"):
        return json.dumps(result, indent=2)
    return json.dumps({"status": "disabled", "user": user_id})


@mcp.tool()
async def enable_user(user_id: str, tenant: str = "") -> str:
    """Enable an Entra ID user account (unblocks sign-in).

    Args:
        user_id: UPN (email) or object ID
        tenant: Tenant name from tenants.json (uses default if empty)
    """
    result = await _call(
        "PATCH", f"{GRAPH_V1}/users/{user_id}", GRAPH_SCOPE, tenant,
        body={"accountEnabled": True},
    )
    if result.get("error"):
        return json.dumps(result, indent=2)
    return json.dumps({"status": "enabled", "user": user_id})


@mcp.tool()
async def revoke_user_sessions(user_id: str, tenant: str = "") -> str:
    """Revoke all sessions and refresh tokens, forcing re-authentication.

    Args:
        user_id: UPN (email) or object ID
        tenant: Tenant name from tenants.json (uses default if empty)
    """
    result = await _call(
        "POST", f"{GRAPH_V1}/users/{user_id}/revokeSignInSessions",
        GRAPH_SCOPE, tenant,
    )
    if result.get("error"):
        return json.dumps(result, indent=2)
    return json.dumps({"status": "sessions_revoked", "user": user_id})


# =========================================================================
#  EMAIL REMEDIATION — Advanced Hunting + Purge
# =========================================================================

@mcp.tool()
async def search_emails(query: str, tenant: str = "") -> str:
    """Search for emails using advanced hunting KQL via Microsoft Graph Security.

    Args:
        query: KQL query for EmailEvents table, e.g.:
               EmailEvents | where SenderFromAddress == "bad@evil.com" | take 25
               EmailEvents | where Subject contains "invoice" and DeliveryAction == "Delivered" | take 50
        tenant: Tenant name from tenants.json (uses default if empty)
    """
    result = await _call(
        "POST", f"{GRAPH_V1}/security/runHuntingQuery", GRAPH_SCOPE, tenant,
        body={"Query": query},
    )
    if result.get("error"):
        return json.dumps(result, indent=2)

    schema = result.get("schema", [])
    columns = [c["Name"] for c in schema]
    rows = result.get("results", [])

    output = {
        "columns": columns,
        "row_count": len(rows),
        "results": rows[:100],
    }
    if len(rows) > 100:
        output["truncated"] = True
        output["total_rows"] = len(rows)
    return json.dumps(output, indent=2)


@mcp.tool()
async def purge_emails(
    network_message_ids: str,
    tenant: str = "",
    action: str = "SoftDelete",
) -> str:
    """Purge emails by network message IDs. Use search_emails first to find them.

    Args:
        network_message_ids: Comma-separated NetworkMessageId values
        tenant: Tenant name from tenants.json (uses default if empty)
        action: SoftDelete (recoverable, default) or HardDelete (permanent)
    """
    ids = [mid.strip() for mid in network_message_ids.split(",") if mid.strip()]
    if not ids:
        return json.dumps({"error": "No message IDs provided"})

    result = await _call(
        "POST",
        f"{GRAPH_BETA}/security/collaboration/analyzedemails/remediate",
        GRAPH_SCOPE, tenant,
        body={
            "displayName": f"MCP Purge - {action}",
            "severity": "high",
            "remediateBy": action.lower(),
            "analyzedemails": [{"networkMessageId": mid} for mid in ids],
        },
    )
    return json.dumps(result, indent=2)


@mcp.tool()
async def search_email_by_message_id(
    internet_message_id: str,
    tenant: str = "",
) -> str:
    """Look up email details by Internet-Message-Id header.

    Args:
        internet_message_id: The Message-ID header value
        tenant: Tenant name from tenants.json (uses default if empty)
    """
    query = (
        f'EmailEvents | where InternetMessageId == "{internet_message_id}" | take 10'
    )
    return await search_emails(query, tenant)


# =========================================================================
#  AIR — Automated Investigation and Response
# =========================================================================

@mcp.tool()
async def list_security_incidents(
    tenant: str = "",
    status: str = "",
    severity: str = "",
    top: int = 25,
) -> str:
    """List Microsoft 365 Defender security incidents (includes AIR investigations).

    Args:
        tenant: Tenant name from tenants.json (uses default if empty)
        status: active, resolved, redirected (optional)
        severity: high, medium, low, informational (optional)
        top: Max results (default 25)
    """
    params = {"$top": str(top), "$orderby": "createdDateTime desc"}
    filters = []
    if status:
        filters.append(f"status eq '{status}'")
    if severity:
        filters.append(f"severity eq '{severity}'")
    if filters:
        params["$filter"] = " and ".join(filters)

    result = await _call(
        "GET", f"{GRAPH_V1}/security/incidents", GRAPH_SCOPE, tenant, params=params,
    )
    if result.get("error"):
        return json.dumps(result, indent=2)

    incidents = []
    for inc in result.get("value", []):
        incidents.append({
            "id": inc.get("id"),
            "displayName": inc.get("displayName"),
            "status": inc.get("status"),
            "severity": inc.get("severity"),
            "createdDateTime": inc.get("createdDateTime"),
            "classification": inc.get("classification"),
            "assignedTo": inc.get("assignedTo"),
        })
    return json.dumps(incidents, indent=2)


@mcp.tool()
async def get_security_incident(incident_id: str, tenant: str = "") -> str:
    """Get full details of a Microsoft 365 Defender security incident.

    Args:
        incident_id: Incident ID
        tenant: Tenant name from tenants.json (uses default if empty)
    """
    result = await _call(
        "GET", f"{GRAPH_V1}/security/incidents/{incident_id}", GRAPH_SCOPE, tenant,
    )
    return json.dumps(result, indent=2)


@mcp.tool()
async def list_security_alerts(
    tenant: str = "",
    incident_id: str = "",
    severity: str = "",
    top: int = 25,
) -> str:
    """List security alerts from Microsoft 365 Defender.

    Args:
        tenant: Tenant name from tenants.json (uses default if empty)
        incident_id: Filter to alerts for a specific incident (optional)
        severity: high, medium, low, informational (optional)
        top: Max results (default 25)
    """
    if incident_id:
        url = f"{GRAPH_V1}/security/incidents/{incident_id}/alerts"
    else:
        url = f"{GRAPH_V1}/security/alerts_v2"

    params = {"$top": str(top), "$orderby": "createdDateTime desc"}
    if severity:
        params["$filter"] = f"severity eq '{severity}'"

    result = await _call("GET", url, GRAPH_SCOPE, tenant, params=params)
    if result.get("error"):
        return json.dumps(result, indent=2)

    alerts = []
    for a in result.get("value", []):
        alerts.append({
            "id": a.get("id"),
            "title": a.get("title"),
            "status": a.get("status"),
            "severity": a.get("severity"),
            "category": a.get("category"),
            "serviceSource": a.get("serviceSource"),
            "createdDateTime": a.get("createdDateTime"),
            "incidentId": a.get("incidentId"),
        })
    return json.dumps(alerts, indent=2)


@mcp.tool()
async def resolve_security_incident(
    incident_id: str,
    classification: str,
    tenant: str = "",
    determination: str = "",
    comment: str = "",
) -> str:
    """Resolve a Microsoft 365 Defender incident.

    Args:
        incident_id: Incident ID
        classification: informationalExpectedActivity, truePositive, falsePositive, unknown
        tenant: Tenant name from tenants.json (uses default if empty)
        determination: apt, malware, phishing, compromisedAccount, other, securityTesting,
                       unwantedSoftware, multiStagedAttack, lineOfBusinessApplication,
                       confirmedActivity, notMalicious, notEnoughDataToValidate (optional)
        comment: Resolution comment (optional)
    """
    body = {"status": "resolved", "classification": classification}
    if determination:
        body["determination"] = determination
    if comment:
        body["customTags"] = [comment]

    result = await _call(
        "PATCH", f"{GRAPH_V1}/security/incidents/{incident_id}", GRAPH_SCOPE, tenant,
        body=body,
    )
    if result.get("error"):
        return json.dumps(result, indent=2)
    return json.dumps({"status": "resolved", "incident_id": incident_id})


@mcp.tool()
async def run_advanced_hunting(query: str, tenant: str = "") -> str:
    """Run any advanced hunting KQL query across Microsoft 365 Defender data.
    Covers: DeviceEvents, EmailEvents, IdentityLogonEvents, CloudAppEvents, etc.

    Args:
        query: KQL query string
        tenant: Tenant name from tenants.json (uses default if empty)
    """
    return await search_emails(query, tenant)


# =========================================================================
#  Entry point
# =========================================================================

if __name__ == "__main__":
    mcp.run()
