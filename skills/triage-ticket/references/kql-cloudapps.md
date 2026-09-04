# KQL — MDCA OAuth-app anomaly detections (`kql-cloudapps.md`)

For Sentinel rules sourced from Microsoft Defender for Cloud Apps: OAuth app anomalies, unusual
app consent grants, suspicious app activity, and app governance alerts. Core tables:
`CloudAppEvents`, `SecurityAlert`. `CloudAppEvents` may live in **Defender Advanced Hunting**
only (check the ingestion map); `SecurityAlert` is in the Sentinel workspace.

> Universal KQL conventions (validate every zero-row negative, `ago()`-scope-then-narrow, KQL mode,
> terminal KQL conventions) live in the skill body. This file carries only the cloud-apps-family
> patterns, traps, and reference tables.

## The decisive cut: is the app legitimate?

OAuth-app alerts measure *novelty*, not malice. A newly consented app with broad permissions
fires the same way whether it's a sanctioned SaaS vendor or a credential-harvesting phish
consent. The triage question is: **is this app known, expected, and appropriately scoped?**

1. **Identify the app**: name, publisher, app ID, redirect URI.
2. **Verify it with the client**: is this an app they procured or recognise?
3. **Check the permissions**: are they proportional to what the app does?
4. **Check the consent actor**: who granted consent, and was it admin or user consent?

## Query patterns

### 1. Characterise the OAuth app consent event
```kusto
CloudAppEvents
| where TimeGenerated > ago(7d)
| where ActionType has_any ("Consent to application", "Add app role assignment",
    "Add OAuth2PermissionGrant", "Add service principal")
| where RawEventData has "<app_name>" or RawEventData has "<app_id>"
| project TimeGenerated, AccountDisplayName, ActionType,
    Application, RawEventData, IPAddress, City, CountryCode
| order by TimeGenerated asc
```

### 2. App activity after consent — what did the app do?
```kusto
CloudAppEvents
| where TimeGenerated > ago(7d)
| where Application has "<app_name>" or AccountObjectId == "<app_service_principal_id>"
| summarize Count=count(), First=min(TimeGenerated), Last=max(TimeGenerated)
    by ActionType, Application, AccountDisplayName, IPAddress
| order by Count desc
```

### 3. Permissions granted to the app
Check AuditLogs for the permission grant details (app roles and delegated permissions).
```kusto
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has_any ("Add app role assignment to service principal",
    "Add delegated permission grant", "Consent to application")
| where tostring(TargetResources) has "<app_name>" or tostring(TargetResources) has "<app_id>"
| extend Actor = tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName)
| mv-expand tr = TargetResources
| project TimeGenerated, OperationName, Result, Actor,
    TDisplay = tostring(tr.displayName),
    TType = tostring(tr.type),
    ModifiedProps = tostring(tr.modifiedProperties)
| order by TimeGenerated asc
```

### 4. Who consented — admin vs. user consent
```kusto
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName == "Consent to application"
| where tostring(TargetResources) has "<app_name>"
| extend Actor = tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName),
         ConsentType = tostring(parse_json(tostring(
             parse_json(tostring(TargetResources))[0].modifiedProperties
         )))
| project TimeGenerated, Actor, ConsentType, Result
| order by TimeGenerated asc
```

### 5. App registration details via AuditLogs
```kusto
AuditLogs
| where TimeGenerated > ago(14d)
| where OperationName has_any ("Add application", "Update application",
    "Add service principal", "Update service principal")
| where tostring(TargetResources) has "<app_name>" or tostring(TargetResources) has "<app_id>"
| extend Actor = tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName)
| mv-expand tr = TargetResources
| project TimeGenerated, OperationName, Result, Actor,
    TDisplay = tostring(tr.displayName), TId = tostring(tr.id),
    ModifiedProps = tostring(tr.modifiedProperties)
| order by TimeGenerated asc
```

### 6. Redirect URI check — where do tokens go?
The redirect URI in the app registration determines where auth tokens are sent. Extract from
the registration event's modified properties.
```kusto
AuditLogs
| where TimeGenerated > ago(14d)
| where OperationName has "application"
| where tostring(TargetResources) has "<app_id>"
| mv-expand tr = TargetResources
| mv-expand mp = tr.modifiedProperties
| where tostring(mp.displayName) has "Reply" or tostring(mp.displayName) has "Redirect"
| project TimeGenerated, OperationName,
    PropName = tostring(mp.displayName),
    NewValue = tostring(mp.newValue),
    OldValue = tostring(mp.oldValue)
| order by TimeGenerated asc
```

### 7. Cross-tenant app consent (multi-tenant apps)
Did the same app get consented across multiple tenants you manage?
```kusto
SecurityAlert
| where TimeGenerated > ago(14d)
| where AlertName has "OAuth" or AlertName has "app" or AlertName has "consent"
| where Entities has "<app_name>" or Entities has "<app_id>"
| summarize Count=count(), First=min(TimeGenerated), Last=max(TimeGenerated)
    by AlertName, AlertSeverity, ProviderName
| order by Last desc
```

### 8. User activity around consent time
What was the consenting user doing before and after? An illicit consent often follows a
phishing click.
```kusto
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (datetime(<consent_time_minus_1h>) .. datetime(<consent_time_plus_1h>))
| where UserPrincipalName == "<consenting_user_upn>"
| project TimeGenerated, AppDisplayName, IPAddress,
    ResultType, RiskLevelDuringSignIn, Type
| order by TimeGenerated asc
```

### 9. Breadth sweep — other apps consented by the same user
A user who consented to one suspicious app may have consented to others in the same session.
```kusto
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has "Consent"
| extend Actor = tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName)
| where Actor has "<consenting_user_name>"
| mv-expand tr = TargetResources
| project TimeGenerated, OperationName, Result, Actor,
    AppName = tostring(tr.displayName), AppId = tostring(tr.id)
| order by TimeGenerated asc
```

## Traps (cloud-apps-specific)

| Trap | Symptom | Workaround |
|------|---------|------------|
| `CloudAppEvents` not in Sentinel | Zero rows from Log Analytics | Check ingestion map — table may be in Defender AH only |
| App name ≠ publisher | A malicious app can name itself anything ("Microsoft Support") | Always check the app ID and publisher domain, not just the display name |
| User consent vs. admin consent | User consent is scoped to the user; admin consent is tenant-wide | `ConsentType` in the audit log distinguishes them — admin consent is higher impact |
| `RawEventData` is a string | Looks like JSON but KQL doesn't auto-parse it | Use `parse_json(RawEventData)` then extract fields |
| Multi-tenant app confusion | App registered in another tenant, consented into this one | The `appOwnerOrganizationId` in the service principal shows the home tenant |
| Stale consent | App was consented months ago but alert fires now | Some MDCA rules have delayed detection; check the actual consent timestamp, not the alert time |
| Legitimate app with broad permissions | App requests Mail.ReadWrite, Files.ReadWrite.All — looks excessive | Some LOB apps genuinely need broad permissions; verify with the client before escalating |

## Reusable classification logic (OAuth-app anomaly type)

**Lean benign positive when:** the app is a recognised SaaS product the client uses (verify
with the client, not by name alone); the publisher domain matches the vendor; the consent was
admin-granted as part of a procurement process; the permissions are proportional to the app's
function; the redirect URI points to the vendor's known domain; no risky sign-ins surround the
consent event; the app has been active in the tenant for an extended period without alerts.

**Escalate when:** the app name mimics a well-known product but the publisher/app ID don't
match; the redirect URI points to a suspicious or unrelated domain; the consent was user-level
(not admin) and the user doesn't recognise the app; the consent followed a phishing email or
risky sign-in; the permissions are disproportionate (a "calculator" app requesting
Mail.ReadWrite.All); the app was registered in a suspicious tenant (`appOwnerOrganizationId`
is unknown); the app immediately began reading mail, files, or directory data after consent.

> OAuth-app alerts measure novelty and permission scope. A new consent is not an attack — it's
> a question: was this intentional? The triage question is: does the client know this app, and
> are the permissions appropriate?
