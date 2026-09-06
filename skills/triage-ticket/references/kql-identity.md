# KQL — Entra identity / sign-in detections (`kql-identity.md`)

For sign-in-sourced Sentinel rules: failed-logon / brute-force / password-spray, risky sign-in,
impossible travel, and privileged-role (PIM / role-assignment) alerts. Core tables live in the
Sentinel workspace: `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AuditLogs`,
`SecurityAlert`. **Run all queries via terminal `az rest`** against the Log Analytics workspace
(see SKILL.md §0 for workspace IDs and the `az rest` pattern). Resolve every account to its
`UserPrincipalName` first and key downstream queries on it.

> Universal KQL conventions (validate every zero-row negative, `ago()`-scope-then-narrow, KQL mode,
> terminal KQL conventions, SMTP≠UPN) live in the skill body. This file carries only the
> identity-family patterns, traps, and reference tables.

## Query patterns

### Characterise a sign-in burst (failed-logon / brute-force / spray)
```kusto
SigninLogs
| where TimeGenerated > ago(3d)
| where UserDisplayName has "<name>" or UserPrincipalName has "<name>"
| summarize Count=count(), First=min(TimeGenerated), Last=max(TimeGenerated)
    by UserPrincipalName, ResultType, ResultDescription, IPAddress, AppDisplayName
| order by Count desc
```

### Characterise a wide burst (group by code alone)
When the burst spans many IPs, group by result code so code spread and IP breadth read in one
row per code.
```kusto
SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName == "<upn>"
| summarize Count=count(), DistinctIPs=dcount(IPAddress),
    First=min(TimeGenerated), Last=max(TimeGenerated)
    by ResultType, ResultDescription
| order by Count desc
```

### The disconfirming test — did ANYTHING succeed, across both tables
Run this early. Token refreshes and background client auth land in the non-interactive table, so
"zero successes" from `SigninLogs` alone is a dangerous false conclusion.
```kusto
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(2d)
| where UserPrincipalName == "<upn>"
| summarize Count=count(), Fail=countif(ResultType != 0), Ok=countif(ResultType == 0),
    First=min(TimeGenerated), Last=max(TimeGenerated)
    by Type, IPAddress, ResultType, AppDisplayName
| order by Last desc
```

### Successes only, pinned to the burst
Answers "did any attacker source get in" without successes buried among thousands of failure
rows.
```kusto
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > datetime(<burst_start_utc>)
| where UserPrincipalName == "<upn>"
| where ResultType == "0"
| summarize Count=count(), First=min(TimeGenerated), Last=max(TimeGenerated)
    by IPAddress, AppDisplayName
| order by Last desc
```

### Bin the timeline to prove concurrency
A success *inside the same bin* as the failures proves one process failed while another on the
same host held a valid token. `make_set` names the successful apps inline so a row is self-proving.
```kusto
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (datetime(<start>) .. datetime(<end>))
| where UserPrincipalName == "<upn>"
| where IPAddress startswith "<prefix>"
| summarize Fail=countif(ResultType != 0), Ok=countif(ResultType == 0),
    Apps=make_set(AppDisplayName, 5)
    by bin(TimeGenerated, 5m)
| order by TimeGenerated asc
```

### Fingerprint every source the account used (SigninLogs ONLY — see traps)
```kusto
SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName == "<upn>"
| extend Loc = strcat(tostring(LocationDetails.countryOrRegion), " / ",
                      tostring(LocationDetails.state), " / ", tostring(LocationDetails.city)),
         OS = tostring(DeviceDetail.operatingSystem),
         Br = tostring(DeviceDetail.browser),
         Trust = tostring(DeviceDetail.trustType)
| summarize Count=count(), Fail=countif(ResultType != 0), Last=max(TimeGenerated)
    by IPAddress, Loc, OS, Br, Trust
| order by Count desc
```
Compare the IPv6 **`/64`** (e.g. `2603:3003:1db7:8100::/64`), not the full address — privacy
addressing rotates the host portion on the same subscriber line, so a "new" address in a known
`/64` is normally the same machine.

### Breadth sweep across alert types for an account
```kusto
SecurityAlert
| where TimeGenerated > ago(14d)
| where Entities has "<name>"
| summarize Count=count(), First=min(TimeGenerated), Last=max(TimeGenerated)
    by AlertName, AlertSeverity, ProviderName
| order by Last desc
```

### Tenant-wide spray check
Spray is defined by breadth and cannot be ruled out from one user's data. OR'd equalities, not
`in (...)` — avoids escaping and bracket issues.
```kusto
SigninLogs
| where TimeGenerated > datetime(<burst_start_utc>)
| where ResultType == "50053" or ResultType == "50126"
| summarize Fails=count(), DistinctIPs=dcount(IPAddress), Last=max(TimeGenerated)
    by UserPrincipalName
| order by Fails desc
```

### Role operations for an account (privileged-role alerts)
```kusto
AuditLogs
| where TimeGenerated > ago(3d)
| where OperationName has "role"
| where tostring(TargetResources) has "<name>" or tostring(InitiatedBy) has "<name>"
| extend Actor = tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName)
| project TimeGenerated, OperationName, Result, Actor
| order by TimeGenerated asc
```

### Read full operation names — the decisive cut for role alerts
The grid truncates `OperationName`, and these all start identically. Summarising by that column
alone renders it full-width and separates PIM activity from a permanent grant.
```kusto
AuditLogs
| where TimeGenerated > ago(3d)
| where OperationName has "role"
| where tostring(TargetResources) has "<name>"
| summarize Count=count() by OperationName
| order by Count desc
```

### Isolate a permanent (outside-PIM) grant and resolve actor / target / role
```kusto
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has "outside of PIM"
| extend Actor = tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName)
| mv-expand tr = TargetResources
| project TimeGenerated, Actor, Result,
          TType = tostring(tr.type), TDisplay = tostring(tr.displayName),
          TUPN = tostring(tr.userPrincipalName)
| order by TimeGenerated asc
```

### Sweep an actor's full session (not just role ops)
A lone role grant tells you little; one accompanied by CA changes or an OAuth consent is an
attack chain. Note `contains`, not `has` (trap below).
```kusto
AuditLogs
| where TimeGenerated > ago(1d)
| extend Actor = tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName)
| where Actor contains "<surname>"
| project TimeGenerated, OperationName, Result, Category
| order by TimeGenerated asc
```

### Verify whether an account is actually disabled
"Attack disruption" in a Sentinel title does not mean the account was disabled — it may only
revoke sessions. Zero rows = **not disabled**; containment is immediate.
```kusto
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(1d)
| where UserPrincipalName == "<upn>"
| where ResultType == "50057" or ResultType == "53003" or ResultType == "530003"
| summarize Count=count(), First=min(TimeGenerated), Last=max(TimeGenerated)
    by ResultType, ResultDescription, IPAddress, AppDisplayName
| order by Count desc
```

### Sign-in risk baseline for actor and target (privileged-role / multi-account alerts)
A privileged change made from a compromised session turns a policy question into an incident.
```kusto
SigninLogs
| where TimeGenerated > ago(2d)
| where UserPrincipalName contains "<actor_name_fragment>"
    or UserPrincipalName contains "<target_name_fragment>"
| extend City = tostring(LocationDetails.city)
| summarize Count=count(), Fail=countif(ResultType != 0)
    by UserPrincipalName, IPAddress, City, RiskLevelDuringSignIn, RiskState
| order by Count desc
```

### Account lifecycle — create-then-delete (short-lived-account alerts)

For "Account Created and Deleted in Short Timeframe" (Sentinel scheduled rule over `AuditLogs`).
Resolve the Add/Delete user events, keyed on the target **objectId** — after soft-delete the target
UPN is masked to a dashless GUID, so match the delete's `TId` to an Add event's `TId` to learn which
of any near-identical accounts (`name` vs `name1` from a UPN collision) was actually removed.
```kusto
AuditLogs
| where TimeGenerated > ago(6d)
| where OperationName == "Add user" or OperationName == "Delete user"
| extend Actor = tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName),
         ActorApp = tostring(parse_json(tostring(InitiatedBy)).app.displayName),
         ActorIP = tostring(parse_json(tostring(InitiatedBy)).user.ipAddress)
| mv-expand tr = TargetResources
| extend TUPN = tostring(parse_json(tostring(tr)).userPrincipalName),
         TName = tostring(parse_json(tostring(tr)).displayName),
         TId  = tostring(parse_json(tostring(tr)).id)
| where TUPN contains "<name_token>" or TName contains "<display_name_token>"
| project TimeGenerated, OperationName, Result, Actor, ActorApp, ActorIP, TUPN, TName, TId
| order by TimeGenerated asc
```
`ActorApp` names a non-human initiator — a sanctioned HR/IGA SCIM connector (e.g. **Aquera**)
creating a duplicate on a UPN collision is the benign shape. The **disconfirming test for this
family** is whether the *deleted* object ever authenticated: run the sign-in-burst query above keyed
on the display-name token and confirm the deleted UPN has **zero** sign-ins (an adversary provisions a
throwaway account to use it). A `0`-result success on the deleted object from an unfamiliar source
flips the case to escalation.

### Authentication-method / security-info changes (privileged-account persistence alerts)

For "Authentication Methods Changed for Privileged Account" (Sentinel scheduled rule over `AuditLogs`,
`loggedByService` in *Authentication Methods* / *Azure MFA* / *Device Registration Service*). The rule
flags **any** auth-method change on a privileged account — it measures *change*, not intrusion. The
decisive cut is **who initiated the change and from where**: a self-service enrollment by the account
owner from a baseline IP is benign; an admin-initiated reset, a foreign/hosting-IP registration, or a
change on the heels of a risky sign-in is persistence.

On **CLTA**, pull these through the MS Graph Enterprise MCP (directory-audit identity info), not
Defender AH. `microsoft_graph_suggest_queries` first, then:
```
/v1.0/auditLogs/directoryAudits?$filter=(loggedByService eq 'Authentication Methods' or loggedByService eq 'Azure MFA' or loggedByService eq 'Device Registration Service') and targetResources/any(tr:tr/id eq '<USER_OBJECT_ID>')&$select=id,activityDisplayName,loggedByService,result,initiatedBy,targetResources,activityDateTime&$orderBy=activityDateTime desc&$top=20
```
For non-CLTA clients the same data is in `AuditLogs`:
```kusto
AuditLogs
| where TimeGenerated > ago(14d)
| where Category == "UserManagement"
| where OperationName has_any ("security info", "passwordless", "security key", "authentication method")
| extend Actor = tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName),
         ActorIP = tostring(parse_json(tostring(InitiatedBy)).user.ipAddress),
         ActorApp = tostring(parse_json(tostring(InitiatedBy)).app.displayName)
| mv-expand tr = TargetResources
| extend TUPN = tostring(parse_json(tostring(tr)).userPrincipalName)
| where TUPN contains "<name_token>"
| project TimeGenerated, OperationName, Result, Actor, ActorIP, ActorApp, TUPN
| order by TimeGenerated asc
```

**Confirm the "privileged" premise and rule out compromise (three reads):**
- Roles (active + PIM-eligible): `/roleManagement/directory/roleAssignmentScheduleInstances?$filter=principalId eq '<ID>'&$expand=roleDefinition($select=id,displayName)` and `/roleEligibilityScheduleInstances?...`.
- Risk state: `/identityProtection/riskyUsers?$filter=id in ('<ID1>','<ID2>')&$select=id,userDisplayName,riskLevel,riskState,riskDetail`.
- Baseline the source IP: `/beta/auditLogs/signIns?$filter=userId eq '<ID>'&$select=createdDateTime,appDisplayName,ipAddress,location,riskState,riskLevelDuringSignIn&$orderby=createdDateTime desc` — confirm the registration-time sign-ins are non-risky and from the account's habitual geography.

**Found (CLTA-38623):** two privileged accounts (`jetringerx@` Global Admin, `clinnerx@` User/Groups/
Power Platform Admin) each registered a FIDO2 passkey via Microsoft Authenticator; **every** audit row
was self-initiated (`initiatedBy.user == target`), from the owner's baseline Wisconsin residential IP,
risk state `none`/confirmedSafe. Corey also deleted an old iPhone-XS Authenticator + a software-OATH
token in the same session. → Benign Positive.

## Traps (identity-specific)

| Trap | Symptom | Workaround |
|------|---------|------------|
| `union` drops dynamic columns | Referencing `LocationDetails` / `DeviceDetail` after `union SigninLogs, AADNonInteractiveUserSignInLogs` → *"Failed to resolve scalar expression"* / `SEM0139` | Query `SigninLogs` alone for device/location, or `extend` / `project` the fields inside each table before unioning |
| `LocationDetails` is a **string** in `AADNonInteractiveUserSignInLogs` | `tostring(LocationDetails.countryOrRegion)` on that table → `SEM0070 … source must be scalar of type 'dynamic'` | `extend L = parse_json(LocationDetails)` first, then `tostring(L.countryOrRegion)` — the non-interactive table stores it as a JSON string, not a dynamic |
| MFA sub-status misread as access | `userPassedMFADrivenByRiskBasedPolicy` read as "logged in" | Read the final `ResultType`; a non-zero result (e.g. `70045`) means no token was issued despite the MFA pass |
| `has` misses substrings in a UPN | `Actor has "mischlich"` returns **zero rows** — `has` matches whole tokens, and `bmischlich@…` tokenises to `bmischlich`/`contoso`/`com` | Use `contains` for partial matches inside UPNs/emails; reserve `has` for whole-word matches (e.g. a display name in `TargetResources`) |
| `OperationName` truncates | Truncated column can't distinguish a PIM activation from a permanent assignment | `summarize count() by OperationName` on its own so it renders full width |
| Role name not in `modifiedProperties` | PIM role events carry only `TemplateId` / `RoleDefinitionOriginId` / `RoleDefinitionOriginType` | Expand `TargetResources`, read the entry where `type == "Role"`; resolve template GUIDs from the data, never from memory |
| `InitiatedBy` needs double conversion | `InitiatedBy.user.userPrincipalName` may not resolve | `tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName)` |
| Domain-wide over-match on shared mailbox | `UserPrincipalName contains "<domain-word>"` matches every account at the domain | Key on the distinctive display-name token, then confirm the exact UPN |
| Fixed `±Nh` windows clip the burst | ±2h anchored on alert time missed both onset and baseline | Scope by `ago()` over days first; narrow once the true burst edges are known |
| IPv6 read as a new source | A second address differing only in the host portion looks like a second device | Compare the `/64` — privacy addressing rotates the host portion on the same line |
| PowerShell escaping | Single quotes inside KQL break PowerShell `@{ query = '...' }` | Use a here-string (`@'...'@`) for the query value, or escape inner single quotes by doubling (`''`) |
| Deleted user's UPN is masked | A `Delete user` target UPN is a dashless GUID, not the real UPN | Match the delete's `TargetResources.id` (`TId`) to an `Add user` event's `TId` to identify the account |
| Near-identical UPNs from a collision | `name@dom` and `name1@dom` look like one account | Key on **objectId**; a `UserPrincipalName contains "<token>"` sign-in query separates them one row per UPN |

## Entra result codes — was a credential actually evaluated?

The fastest triage cut on sign-in alerts. If no credential was evaluated, brute force is ruled
out regardless of volume.

| Code | Meaning | Class | Implication |
|------|---------|-------|-------------|
| `0` | Success | Success | Check the source. Success from an unfamiliar source after failures = escalation trigger |
| `50126` | Invalid username or password | Credential | A password was submitted and rejected — the code brute force/spray actually produce |
| `50053` | Account locked / smart lockout | Credential | Repeated credential failures crossed lockout. Strong brute-force indicator |
| `50055` | Password expired | Credential | Credentials were correct. Usually benign, but confirms a valid known password |
| `50057` | Account disabled | Credential | Attempts against a disabled account. Review if volume high or source unknown |
| `50076`/`50079` | MFA required / enrolment required | Credential | Primary auth **succeeded**, MFA gated it. Treat as a near-miss, not a clean failure |
| `50074` | Strong auth required | Credential | MFA challenge on a stolen session; blocks some apps, not all |
| `50078` | MFA session expired | Credential | An MFA claim aged out. Ordinary on the user's own device |
| `500121` | MFA authentication failed | Credential | MFA attempted, not satisfied. Ordinary friction on known device; suspicious from unfamiliar one |
| `50140` | KMSI interrupt | Token | Session cookie under evaluation — consistent with replay |
| `50133` | Session expired/invalid | Token | May indicate attack disruption revoked the session |
| `50173` | Token expired/malformed | Token | May indicate token revocation by attack disruption |
| `70043` | Refresh token expired | Token | Background refresh aged out. Not a credential event |
| `70045` | Refresh token invalid — CA sign-in-frequency | Token | Refresh-token replay rejected at issuance; **no session granted**, and the token is now dead ("will never be usable"). Seen on TOR/anonymized-IP token replay (CLTB-5524) |
| `500111` | Reply URI has invalid scheme | Config | OAuth redirect rejected before any credential check. App misconfiguration |
| `700016` | Application not found in directory | Config | App registration / consent problem. Not a credential event |

**Risk-detail discriminator.** On anonymized-IP / risky sign-ins, read `RiskDetail` alongside the code:
`userPassedMFADrivenByRiskBasedPolicy` (with `RiskState=remediated`) means the **MFA step passed** — but
if the row's `ResultType` is non-zero (e.g. `70045`), the sign-in **still failed at a later gate and no
token was issued**. Read the final `ResultType`, not the MFA sub-status: a passed MFA on a failed sign-in
is a *near-miss* (contain), not access (CLTB-5524).

## Reusable classification logic (sign-in / failed-logon type)

**Lean false-positive / benign when:** failures dominated by a **config** code (`500111`,
`700016`); the same source shows **successful** auth in the same window (esp. non-interactive);
failures are **monolithic** (one code, one app, one source); geography/OS/browser build **match
baseline**; the source sits in a `/64` the account already uses; no other alert types fired; the
target is a **first-party Microsoft service principal**.

**Escalate when:** failures carry `50126`/`50053`; a **success follows failures from the same
unfamiliar source** (either table); `50076`/`50079` appear (primary auth succeeded, only MFA
blocked); source is a **hosting/VPS ASN** or geography off-baseline; the same pattern spans
**multiple accounts** (spray); device/browser characteristics **don't match** history; any
impossible-travel, risky-user, mailbox-rule, or OAuth-consent alert fires nearby.

> A failed-logon alert measures noise; compromise is measured by success. The volume of failures
> tells you why the rule fired — almost nothing about whether anyone got in.

### Auth-method-change type (privileged-account persistence)

**Lean benign positive when:** every event is **self-initiated** (`initiatedBy.user == target`); the
apps are first-party (*Microsoft Authenticator* / *My Signins*); the source IP is the account's
**baseline geography** and non-risky; **old methods are removed alongside** new ones (device
migration); user risk state is `none`/`confirmedSafe`/`dismissed`. **Escalate when:** the change is
initiated by a **different principal** (admin/app) not expected to manage that account; registration
comes from an **unfamiliar / hosting / foreign** IP; it follows risky sign-ins or a password reset
from an unfamiliar source; or the account is `atRisk`/`confirmedCompromised`.

> This rule measures *change*, not intrusion. Read the initiator and the source IP before the volume:
> a privileged user re-enrolling MFA on a new phone from home is the common benign shape (CLTA-38623),
> and the My-Sign-Ins service IP on a self-service row is not a second actor.
