# KQL cookbook — Cloud Apps (Microsoft Defender for Cloud Apps)

Detection family: **Microsoft Defender for Cloud Apps (MDCA) / "Microsoft Application Protection"**
activity & OAuth-app anomalies. Covers alerts where the fired product is an MDCA counter on an
**OAuth application** or on **user activity**, e.g.:

- **"Increase in app activity on Exchange"** — an OAuth-app anomaly (volume + distinct-user counter
  on the app's Graph→Exchange calls). *(CLTB-4798 — Benign Positive.)*
- (Existing MDCA activity-policy detections — "Multiple failed user log on attempts to an app",
  "Mass delete involving one user", "Impossible travel", "Multiple failed logon to a service" — have
  their own IIRR pages; they are volume/activity counters on **user** activity rather than on an app.)

**All KQL runs via terminal `az rest`** against the Log Analytics workspace (see SKILL.md §0 for
workspace IDs and the `az rest` pattern). Apply the all-family KQL conventions from the skill intro
(validate every zero-row negative; resolve the account/app to its real identifier first; scope by
`ago()` then narrow; use KQL mode).

---

## Core tables

| Table | What it holds | Key columns |
|---|---|---|
| `OAuthAppInfo` | Daily snapshot of every registered/consented OAuth app | `OAuthAppId`, `ServicePrincipalId`, `AppName`, `VerifiedPublisher`, `IsAdminConsented`, `AppOrigin`, `AppOwnerTenantId`, `AddedOnTime`, `RiskScore`, `PrivilegeLevel`, `Permissions[]` (`.PermissionType` Delegated/Application, `.PermissionValue`, `.TargetAppDisplayName`) |
| `GraphAPIAuditEvents` | Every Microsoft Graph API request | **`ApplicationId`** (the app — NOT `AppId`), `AccountObjectId` (the user acted for), `RequestMethod`, `RequestUri`, `ResponseStatusCode`, `Scopes`, `IPAddress`, `Location`, `ApiVersion` |
| `IdentityInfo` | User directory attributes | `AccountObjectId`, `AccountUpn`, `AccountDisplayName`, `Department`, `JobTitle`, `City`, `Country` |
| `SigninLogs` | Interactive Entra sign-ins & app consents | `UserPrincipalName`, `AppDisplayName`, `IPAddress`, `Location`, `ResultType`, `RiskLevelDuringSignIn` |
| `EmailEvents` | Mail flow (sent/received) | `SenderFromAddress`, `RecipientEmailAddress`, `EmailDirection`, `ThreatTypes`, `DeliveryAction` |
| `SecurityAlert` | All product alerts (breadth sweep) | `AlertName`, `ProductName`, `AlertSeverity`, `Entities` |
| `EntraIdSpnSignInEvents` / `AADServicePrincipalSignInLogs` | Service-principal (app-only) sign-ins | for **Application**-permission apps: which tenant/app authenticated with client credentials |

---

## Query patterns — OAuth-app anomaly ("Increase in app activity on Exchange")

Substitute `<OAUTH_APP_ID>`, `<ACCOUNT_ID>`, `<UPN>`.

### 1. Characterize the app (this sets the ceiling)
```kql
OAuthAppInfo
| where OAuthAppId == "<OAUTH_APP_ID>"
| top 1 by TimeGenerated desc
```
Expand `Permissions[]`: **Delegated** ⇒ app reaches only the signed-in user's own mailbox;
**Application** ⇒ app-only token, can reach any mailbox — much higher blast radius. Note
`VerifiedPublisher`, `IsAdminConsented`, `AppOrigin`, `AppOwnerTenantId`, `RiskScore`.

### 2. Volume + breadth over time (is the "increase" volume or new users?)
```kql
GraphAPIAuditEvents
| where Timestamp > ago(30d)
| where ApplicationId == "<OAUTH_APP_ID>"
| summarize Calls=count(), Accounts=dcount(AccountObjectId) by bin(Timestamp, 1d)
| sort by Timestamp asc
```
Accounts stepping up in proportion to volume = onboarding. Volume spiking with accounts flat =
single-mailbox burst (the exfil shape).

### 3. Per-account / per-method breakdown (disconfirming test — run early)
```kql
GraphAPIAuditEvents
| where Timestamp > ago(10d)
| where ApplicationId == "<OAUTH_APP_ID>"
| summarize Calls=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by AccountObjectId, RequestMethod
```
`FirstSeen` pinpoints the newly-onboarded account.

### 4. Classify the POSTs — draft-then-send aware
```kql
GraphAPIAuditEvents
| where Timestamp > ago(10d)
| where ApplicationId == "<OAUTH_APP_ID>"
| where RequestMethod == "POST"
| extend Kind = case(
    RequestUri contains "sendMail", "sendMail",
    RequestUri contains "send", "draft-send",
    RequestUri contains "batch", "batch",
    RequestUri contains "move", "move",
    RequestUri contains "Reply", "reply",
    RequestUri contains "Forward", "forward",
    "other")
| summarize Calls=count() by AccountObjectId, Kind
| sort by Calls desc
```
Then sample raw URIs for the `other`/`draft-send` bucket:
```kql
GraphAPIAuditEvents
| where Timestamp > ago(10d)
| where ApplicationId == "<OAUTH_APP_ID>"
| where RequestMethod == "POST"
| where AccountObjectId == "<ACCOUNT_ID>"
| distinct RequestUri
| take 15
```
`/me/messages` + `/me/messages/{id}/send` = draft-then-send (both are **sends**). `/me/` = own
mailbox. `/users/{other}/…` under an application token = cross-mailbox — escalate.

### 5. Persistence / exfil-rule check (MailboxSettings.ReadWrite)
```kql
GraphAPIAuditEvents
| where Timestamp > ago(10d)
| where ApplicationId == "<OAUTH_APP_ID>"
| where RequestUri contains "mailboxSettings" or RequestUri contains "MessageRule"
    or RequestUri contains "inboxRule" or RequestUri contains "forward"
| summarize Count=count() by AccountObjectId, RequestMethod, RequestUri
```
**Validate the zero** — the same app returns thousands of rows in query #2/#3, so an empty result
here is a true absence of forwarding/inbox-rule persistence, not an empty table.

### 6. Resolve accounts → UPNs
```kql
IdentityInfo
| where AccountObjectId == "<ACCOUNT_ID_1>" or AccountObjectId == "<ACCOUNT_ID_2>"
| distinct AccountObjectId, AccountUpn, AccountDisplayName, Department, JobTitle, City, Country
```

### 7. Authorization — the consent + the user's sign-in risk
```kql
SigninLogs
| where TimeGenerated > ago(6d)
| where UserPrincipalName == "<UPN>"
| summarize Count=count() by AppDisplayName, IPAddress, Location, ResultType, RiskLevelDuringSignIn
| sort by Count desc
```
The app appears by name (e.g. `Marblism`) with a successful sign-in (`ResultType 0`) and often a
`90095` admin-consent interrupt — that is the self-service consent event. Low-risk, on the user's
normal network = benign adoption; risky/foreign/impossible-travel consent = account takeover.

### 8. Sent-mail pattern (rules out BEC/spam/exfil-by-send)
```kql
EmailEvents
| where Timestamp > ago(4d)
| where SenderFromAddress == "<UPN>"
| summarize Emails=count(), Recipients=dcount(RecipientEmailAddress) by EmailDirection, ThreatTypes, DeliveryAction
```
Emails ≈ Recipients (1:1) with no `ThreatTypes` = personalized outreach. A large recipient fan-out
per message, or phish/malware ThreatTypes, escalates.

### 9. Breadth sweep
```kql
SecurityAlert
| where TimeGenerated > ago(14d)
| where Entities contains "<UPN_LOCALPART>" or Entities contains "<APP_NAME>"
| summarize Count=count() by AlertName, ProductName, AlertSeverity
| sort by Count desc
```
A domain-substring filter matches the whole brand — read for *entity-specific* identity-compromise
alerts (risky sign-in, AiTM, impossible travel, anomalous token); don't over-attribute brand-wide DLP
/ inbound-ZAP noise.

---

## Sign-in ResultType quick reference (seen in this family)

| Code | Meaning |
|---|---|
| `0` | Success (incl. successful app consent / sign-in) |
| `90095` | Admin-consent-required interrupt (part of a consent flow) |
| `50140` | "Keep me signed in" interrupt (benign) |
| `50126` | Invalid credentials (single bad password — benign in isolation) |
| `7000112` | Application disabled by tenant |

---

## Traps

| Trap | Symptom | Workaround |
|---|---|---|
| Wrong app column | `Failed to resolve column 'AppId'` on `GraphAPIAuditEvents` | Filter on **`ApplicationId`** |
| Draft-then-send missed | `sendMail`-only classifier reports "no sends" while the account is sending | Count `POST /me/messages` + `POST /me/messages/{id}/send` as sends |
| Volume read as breadth | ~2× call jump assumed to be exfiltration | `dcount(AccountObjectId)` over time — onboarding steps accounts up with volume |
| Delegated vs Application ignored | Assuming tenant-wide mailbox exposure | Read `OAuthAppInfo.Permissions[].PermissionType`; delegated = own mailbox only |
| Empty Sentinel incident mistaken for "nothing to see" | No entities/insights/similar incidents | Expected for MDCA app anomalies — the case is built from `GraphAPIAuditEvents` etc., not the incident |
| `OAuthAppInfo` daily snapshots | 30d query returns ~1 row/day per app | `top 1 by TimeGenerated desc` for the current state |
| Large dynamic columns in `az rest` | JSON response is huge or truncated when projecting `Entities`, `Permissions[]`, etc. | Project only needed columns; for large results, dump to file and parse with PowerShell or the Read tool |

---

## Classification logic

- **Benign Positive** — Delegated permissions; own-mailbox (`/me/…`) access; verified-publisher
  and/or admin-consented app; the "increase" resolves to new-user onboarding; sends 1:1 with no
  ThreatTypes; no forwarding/inbox-rule created; low-risk on-network consent sign-ins. *(CLTB-4798.)*
- **True Positive (OAuth-app compromise / exfiltration)** — Application permissions reading
  multiple/other mailboxes; a bulk read/download burst on one mailbox; mass external sending or a
  per-message recipient fan-out; a new auto-forward/inbox rule; unverified/unknown publisher or
  suspicious `AppOwnerTenantId`; or consent granted during a risky/foreign/impossible-travel sign-in.
  → revoke the app grant, revoke sessions/refresh tokens, remove rules, reset, sweep other consenters.
- **Awaiting customer confirmation** — technical picture settled and access is own-mailbox, but tenant
  authorization is undeterminable (not admin-consented, unknown publisher, no clean self-service
  consent trail). Conditional: confirmed sanctioned → Benign Positive + close; denied → contain.

See the IIRR page **"Incident Investigation & Response Record: Increase in App Activity on Exchange
(OAuth App Anomaly)"** (Confluence, Claude Decisions History → Cloud Apps) for the full playbook and
the case ledger.

---

## Query patterns — Anonymous proxy activity ("Activity from an anonymous proxy")

This detection fires when MDCA observes user activity from an IP classified as an anonymous proxy.
The IP reputation classification drives the alert — not a behavioral anomaly. The critical pivot is
the user's IP baseline: chronic VPN/proxy users generate hundreds of these alerts.

Substitute `<USER_OBJECT_ID>`, `<DISPLAY_NAME>`, `<FLAGGED_IP>`, `<UPN>`, `<UPN_LOCAL>`,
`<KNOWN_PREFIX_1>`, etc.

### 1. Check CloudAppEvents for the flagged activity
```kql
CloudAppEvents
| where TimeGenerated > ago(7d)
| where AccountObjectId == "<USER_OBJECT_ID>" or AccountDisplayName == "<DISPLAY_NAME>"
| where IPAddress == "<FLAGGED_IP>"
| summarize Count=count(), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated)
    by ActionType, Application, IPAddress, CountryCode, City
| sort by Count desc
```
The `CompromisedSignIn` ActionType reflects IP reputation, not confirmed compromise.

### 2. Baseline the user's IP pattern (the key step — decides the alert)
```kql
SigninLogs
| where TimeGenerated > ago(14d)
| where UserPrincipalName == "<UPN>"
| summarize Count=count(), DistinctIPs=dcount(IPAddress)
    by ResultType, AppDisplayName, IPAddress, Location
| sort by Count desc
| take 30
```
Look for /24-range clustering on Outlook Mobile. If the flagged IP is one of dozens in the same /24
the user routinely uses → Benign Positive.

### 3. Check alert volume for the user (chronic vs. novel)
```kql
SecurityAlert
| where TimeGenerated > ago(30d)
| where Entities contains "<UPN_LOCAL>" or Entities contains "<USER_OBJECT_ID>"
| summarize Count=count() by AlertName, ProductName, AlertSeverity
| sort by Count desc
```
100+ "Anonymous IP address" alerts in 30 days → habitual VPN user, not novel.

### 4. Disconfirming test — sign-ins from outside known IP ranges
```kql
SigninLogs
| where TimeGenerated > ago(14d)
| where UserPrincipalName == "<UPN>"
| where ResultType == "0"
| where IPAddress !startswith "<KNOWN_PREFIX_1>" and IPAddress !startswith "<KNOWN_PREFIX_2>"
| project TimeGenerated, AppDisplayName, IPAddress, Location, DeviceDetail, ClientAppUsed
| sort by TimeGenerated desc
| take 20
```
If all sign-ins from outside known ranges are from the same geography and device → no anomaly.

### Anonymous proxy — classification logic

- **Benign Positive** — User has dozens/hundreds of anonymous IP alerts from the same /24 ranges;
  flagged IP is in a /24 already in the user's baseline; all geolocate to the same US city; device
  fingerprint consistent; no sign-ins from foreign/unknown locations; account recently confirmed safe
  and same pattern resumed. *(CLTA-39495.)*
- **True Positive** — Proxy IP is novel (not in any known /24); geolocates to a foreign country;
  post-compromise indicators present (anomalous mailbox rules, unusual app consents, mass email);
  other alert types fire alongside (impossible travel, AiTM, password spray success); user has no
  history of anonymous IP alerts.

### Anonymous proxy — traps

| Trap | Symptom | Workaround |
|---|---|---|
| IP "Attacker" role label | Alert entities `Roles: ["Attacker"]` — reads as confirmed | MDCA default label for the flagged IP; assess by baseline, not label |
| Single-IP filter | Filtering on the one flagged IP shows 1 sign-in — looks novel | Filter on the /24 prefix to see the full rotation pattern |
| Automated "confirm compromised" | Risk state shows `confirmedCompromised` (high) | Check AuditLogs; no audit trail = likely Sentinel automation on `aiCompoundAccountRisk` |
| ResultType 70043 flood | Dozens of "failed" sign-ins look like credential attacks | 70043 = session re-auth / CAE — normal for mobile behind rotating proxies |

See the IIRR page **"Incident Investigation & Response Record: Activity from an Anonymous Proxy
(MDCA)"** (Confluence, Claude Decisions History → Cloud Apps) for the full playbook and case ledger.
