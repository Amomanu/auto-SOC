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

---

## Query patterns — Mass delete involving one user (MDCA volume policy)

Detector `MCAS_ALERT_ANUBIS_DETECTION_REPEATED_ACTIVITY_DELETE`. The alert is a delete-count
threshold in one session. The decisive question is **scope** (own OneDrive vs shared / other user)
and the second is **shape** (destruction vs the delete half of a copy/move). *(CLTB-6310.)*

**Table choice:** `CloudAppEvents` where ingested; **CLTB `<CLTB_WORKSPACE_NAME>` has no `CloudAppEvents` —
use `OfficeActivity`** (OneDrive / SharePoint / Exchange workloads). Validate with
`union withsource=T CloudAppEvents, OfficeActivity | where TimeGenerated > ago(7d) | summarize count() by T`.

Substitute `<UPN>` (the OneDrive/SharePoint `UserId` — on CLTB this is the `.co` UPN, not the `.com`
mail address), `<START>`, `<END>`.

### 1. All operations for the user around the alert window (find the burst, learn the identifiers)
```kql
OfficeActivity
| where TimeGenerated between (datetime(<START>) .. datetime(<END>))
| where UserId has "<SURNAME>"
| summarize Count=count(), First=min(TimeGenerated), Last=max(TimeGenerated) by UserId, Operation, OfficeWorkload
| sort by Count desc
```
Run this *before* filtering on operation names. It shows every `UserId` spelling the audit uses and
every operation type in play.

### 2. Deletion scope — decisive
```kql
OfficeActivity
| where TimeGenerated between (datetime(<START>) .. datetime(<END>))
| where UserId =~ "<UPN>"
| where Operation in ("FileDeleted","FileRecycled","FolderRecycled","FileDeletedFirstStageRecycleBin","FileDeletedSecondStageRecycleBin","FileVersionsAllDeleted")
| extend Ext = tolower(extract(@"\.([A-Za-z0-9]+)$", 1, SourceFileName)),
         Top3 = strcat_array(array_slice(split(SourceRelativeUrl, "/"), 0, 3), "/")
| summarize Count=count(), Distinct=dcount(SourceFileName), First=min(TimeGenerated), Last=max(TimeGenerated),
            Exts=make_set(Ext, 8) by Operation, Site_Url, Top3
| sort by Count desc
```
`Site_Url` under `<tenant>-my.sharepoint.com/personal/<user>/` = own OneDrive. Anything under
`<tenant>.sharepoint.com/sites/...` or another user's `personal/` path escalates on its own.

### 3. Shape — copy/move versus destruction
```kql
OfficeActivity
| where TimeGenerated between (datetime(<START>) .. datetime(<END>))
| where UserId =~ "<UPN>"
| where Operation in ("FileDeleted","FileCopied","FolderCopied","FileMoved","FileUploaded")
| summarize Deleted=countif(Operation=="FileDeleted"), Copied=countif(Operation in ("FileCopied","FolderCopied")),
            Moved=countif(Operation=="FileMoved") by bin(TimeGenerated, 5m)
| sort by TimeGenerated asc
```
Deletes and copies tracking each other bin-for-bin = a copy/move job. Confirm the trees match:
```kql
OfficeActivity
| where TimeGenerated between (datetime(<START>) .. datetime(<END>))
| where UserId =~ "<UPN>" and Operation in ("FileCopied","FolderCopied")
| extend Top = strcat_array(array_slice(split(tostring(OfficeObjectId), "/"), 0, 7), "/")
| summarize Count=count() by Operation, Top
```
**On copy rows the path lives in `OfficeObjectId`** — `SourceRelativeUrl`, `SourceFileName`,
`Site_Url`, `ClientIP`, `UserAgent` are all empty. A same-second `FileAccessed` burst on a second
library (also with empty IP/UA) is the job reading its source; that library still holds the data.

### 4. Where the data came from / went (SharePoint side)
```kql
OfficeActivity
| where TimeGenerated between (datetime(<START>) .. datetime(<END>))
| where UserId =~ "<UPN>" and OfficeWorkload == "SharePoint"
| extend Top = strcat_array(array_slice(split(tostring(OfficeObjectId), "/"), 0, 7), "/")
| summarize Count=count(), First=min(TimeGenerated), Last=max(TimeGenerated) by Operation, Site_Url, Top
| sort by Count desc
```
Widen to the preceding days: a `FileSyncDownloadedFull` (SharePoint) + `FileSyncUploadedFull`
(OneDrive) pair of similar size is a drive-archive migration and explains a later re-copy.

### 5. Client fingerprint of the burst (expect blanks on server-side jobs)
```kql
OfficeActivity
| where TimeGenerated between (datetime(<START>) .. datetime(<END>))
| where UserId =~ "<UPN>"
| summarize Count=count() by Operation, IP=coalesce(tostring(Client_IPAddress), tostring(ClientIP)), UserAgent
| sort by Count desc
```
Interactive rows (`FileAccessed` from the Nucleus/OneDrive desktop client, Edge, Excel) carry the
IP; those should match the `SigninLogs` baseline.

### 6. Mailbox persistence (validate the zero)
```kql
OfficeActivity
| where TimeGenerated > ago(14d)
| where UserId has "<SURNAME>" and OfficeWorkload == "Exchange"
| where Operation in ("New-InboxRule","Set-InboxRule","UpdateInboxRules","Set-Mailbox","Add-MailboxPermission","Remove-InboxRule")
| summarize Count=count(), Last=max(TimeGenerated) by Operation
```
Companion (drop the `UserId` filter) must return rows or the zero is unvalidated.

### 7. Spread — other accounts deleting in the same window
```kql
OfficeActivity
| where TimeGenerated between (datetime(<START>) .. datetime(<END>))
| where Operation in ("FileDeleted","FileRecycled","FolderRecycled")
| summarize Count=count(), Users=dcount(UserId), Top=make_set(UserId, 5) by Operation, OfficeWorkload
| sort by Count desc
```
Doubles as the ingestion validation for step 2.

Sign-in sweep, `SecurityAlert` breadth and sibling `SecurityIncident` queries: as in the family
patterns above (`SigninLogs` uses `DeviceDetail.operatingSystem` directly; on
`AADNonInteractiveUserSignInLogs` wrap with `parse_json()` — and query the two tables separately,
a `union` with `extend DeviceDetail.…` fails to resolve).

### Mass delete — traps

| Trap | Symptom | Workaround |
|---|---|---|
| `Operation has "Delete"` | Zero rows although thousands of `FileDeleted` exist | `has` is whole-term; use `in (...)` or `contains` |
| Copy rows look empty | `FileCopied` with blank `Site_Url`/`SourceFileName`/IP | Path is in `OfficeObjectId`; join on that, not `SourceFileName` |
| Blank IP read as evasion | Delete/copy rows have no `ClientIP`/`UserAgent` | Server-side SharePoint job; fingerprint via `SigninLogs` |
| UPN vs mail address | `UserId =~ "<mail>"` finds only Exchange rows | OneDrive/SharePoint rows use the UPN suffix (`.co` on CLTB) |
| `CloudAppEvents` empty | No rows for anyone | Not ingested in CLTB `<CLTB_WORKSPACE_NAME>`; use `OfficeActivity` |
| `IdentityInfo` column | `Failed to resolve 'AccountUpn'` | Column is `AccountUPN` |

### Mass delete — classification logic

- **Benign Positive** — own OneDrive only; concurrent copy/move of the same tree or a tight
  single-folder cleanup; source library intact; sign-ins at baseline (one egress or one `/64`,
  AAD-joined device, no risk, no failures); no identity alerts; no inbox rules; role fits the data;
  **user confirms**. Deleted items sit in the OneDrive recycle bin.
- **Awaiting customer confirmation** — all of the above except the confirmation. Ticket stays in
  progress with the question drafted. *(CLTB-6310.)*
- **Escalate** — deletions in shared/group/other-user libraries; sign-in anomalies in the window;
  post-compromise companions; the same pattern on several accounts; encryption/rename alongside.

See the IIRR page **"Incident Investigation & Response Record: Mass delete involving one user"**
(Confluence, Claude Decisions History → Cloud Apps) for the playbook and case ledger.
