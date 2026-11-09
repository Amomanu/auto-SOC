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
Compare the IPv6 **`/64`** (e.g. `2001:db8:1234:5600::/64`), not the full address — privacy
addressing rotates the host portion on the same subscriber line, so a "new" address in a known
`/64` is normally the same machine.

### Long baseline + registered device ID per source block (off-baseline IP / VPN egress)
Answers "is this off-baseline IP block the account's normal operator?" A VPN egress (e.g. a US
hosting range on an account whose baseline is PH) that carries the **same `DeviceDetail.deviceId`**
as the baseline is the same operator, not a second actor. Only Azure AD registered/joined devices
populate `deviceId`; unregistered browsers come back empty — fall back to OS + browser build (CLTB-7211).
```kusto
SigninLogs
| where TimeGenerated > ago(60d)
| where UserPrincipalName =~ "<upn>"
| extend DevId = tostring(DeviceDetail.deviceId), DevName = tostring(DeviceDetail.displayName),
         OS = tostring(DeviceDetail.operatingSystem), Trust = tostring(DeviceDetail.trustType)
| extend Block = case(IPAddress startswith "<baseline_prefix>", "baseline",
                      IPAddress startswith "<other_prefix>", "other-block", "other")
| summarize Count=count(), Ok=countif(ResultType == "0"),
    First=min(TimeGenerated), Last=max(TimeGenerated)
    by Block, DevId, DevName, OS, Trust
| order by Block asc, Count desc
```

### Geo-block + VPN hopping — name the blocking CA policy, tie sources without a deviceId
For a `53003` burst from one offshore IP while the account succeeds from rotating US VPN/hosting
exits. First name the policy that blocked it. A country-block policy (CLTB: *Block Restricted Countries*)
firing on the operator's home ISP means the operator is using a VPN to get past the geo-block:
```kusto
SigninLogs
| where TimeGenerated > ago(3d)
| where UserPrincipalName =~ "<upn>" and ResultType == "53003"
| mv-expand p = ConditionalAccessPolicies
| where tostring(p.result) == "failure"
| summarize Count=count() by Policy=tostring(p.displayName), IPAddress
```
Unregistered browsers leave `deviceId` empty, so tie the sources together in two ways. First, group
by country + OS + browser build over 60d: one operator's Chrome build moves 152→153→154 on the same
days across the home IP and every VPN exit. Second, check that the Authenticator device stays the
same. A new `DeviceName` or a newly registered method near the alert is the compromise signal:
```kusto
AuditLogs
| where TimeGenerated > ago(30d)
| where TargetResources has "<upn_fragment>"
| mv-expand t = TargetResources
| mv-expand m = t.modifiedProperties
| project TimeGenerated, OperationName, Prop=tostring(m.displayName),
    Old=substring(tostring(m.oldValue),0,160), New=substring(tostring(m.newValue),0,160)
| order by TimeGenerated asc
```
**Found (CLTB-7415):** `user@<CLTB_SUBBRAND_DOMAIN>` from PH Globe `198.51.100.x` was blocked ×51 by *Block Restricted
Countries* and succeeded only via `203.0.113.x` / `192.0.2.x` / `198.18.0.x` VPN exits. Windows10/Chrome
build moved in lockstep and Authenticator `RMX5101` was unchanged throughout → False Positive for the
failed-logon alert, and a separate customer finding about the geo-block bypass.

### Does the managed device itself report the flagged IP? (impossible travel / off-baseline IP)
When a flagged IP shows an **interactive** success from the user's AADJ/compliant device, confirm
from the endpoint side: Defender `DeviceInfo.PublicIP` is the device's own view of its egress. The
device (user logged on) reporting the flagged IP + a **Windows Hello for Business** credential in
`AuthenticationDetails` = the corporate laptop is on that network, not a replayed token. Pair with a
tenant-wide "who else uses this IP" check — concurrent colleagues = shared network / VPN exit
(CLTA-39857). `DeviceName` is lowercase in `DeviceInfo`.
```kusto
DeviceInfo
| where TimeGenerated > ago(3d)
| where DeviceName startswith "<device name, lowercase>"
| summarize First=min(TimeGenerated), Last=max(TimeGenerated) by DeviceName, PublicIP, LoggedOnUsers=tostring(LoggedOnUsers)
| order by Last desc
```
```kusto
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(30d)
| where IPAddress in ("<ip1>","<ip2>")
| summarize Count=count(), Ok=countif(ResultType == "0"), First=min(TimeGenerated), Last=max(TimeGenerated)
    by IPAddress, UserPrincipalName
```

### Flagged IP in neither sign-in table? Check app audit for impersonation (impossible travel)
MDCA also scores application audit activity, so an impossible-travel IP can be missing from both
`SigninLogs` and `AADNonInteractiveUserSignInLogs` for the user. Search `CloudAppEvents` by the IP.
For Dynamics 365 / Dataverse rows, `RawEventData.UserKey` stays with the acting session even when
`UserId` shows the impersonated user. If the key on the remote-IP rows differs from the user's own
key on their baseline IPs and matches another account that signs in from that IP, that account is
impersonating the user (admin / XrmToolBox tooling). The user was never there (CLTA-41790). The Dynamics
`UserId` can be an alias of the Entra UPN, so match on both.
```kusto
CloudAppEvents
| where TimeGenerated > ago(7d)
| where IPAddress startswith "<ip /64 prefix>" or tostring(RawEventData.UserId) =~ "<user D365 UPN>"
| extend UserKey=tostring(RawEventData.UserKey), Who=tolower(tostring(RawEventData.UserId))
| summarize Count=count(), First=min(TimeGenerated), Last=max(TimeGenerated), IPs=make_set(IPAddress, 6) by Application, UserKey, Who
| order by UserKey
```

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

### Legacy SMTP AUTH spray — size the campaign and test every campaign IP for success
When the burst is `ClientAppUsed == "Authenticated SMTP"` / `UserAgent == "BAV2ROPC"` (password-only,
no MFA), the single-user alert is one target of a tenant-wide spray. One pass sizes it and runs the
both-tables success test against every campaign IP (CLTB-7213: 4,847 blocked attempts, 2,106 IPs,
55 accounts, 0 successes).
```kusto
let bad = SigninLogs
| where TimeGenerated > ago(3d)
| where ClientAppUsed == "Authenticated SMTP" and ResultType == "50053"
| distinct IPAddress;
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(3d)
| where IPAddress in (bad)
| summarize Total=count(), Ok=countif(ResultType == "0"),
    IPs=dcount(IPAddress), Users=dcount(UserPrincipalName),
    OkUsers=dcountif(UserPrincipalName, ResultType == "0")
```
Hardening recommendation for this vector: block SMTP AUTH / legacy authentication (MFA does not cover it).

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

**Found (CLTA-38623):** two privileged accounts (`admin1@` Global Admin, `admin2@` User/Groups/
Power Platform Admin) each registered a FIDO2 passkey via Microsoft Authenticator; **every** audit row
was self-initiated (`initiatedBy.user == target`), from the owner's baseline home residential IP,
risk state `none`/confirmedSafe. One of them also deleted an old iPhone-XS Authenticator + a software-OATH
token in the same session. → Benign Positive.

### Conditional Access policy exclusion change (CA-exclusion-change alerts)

For "Conditional Access - A Conditional Access user/group/role exclusion has changed" (Sentinel
scheduled rule over `AuditLogs`, `OperationName == "Update conditional access policy"`). The rule
diffs `excludeUsers`/`excludeGroups`/`excludeRoles` and fires on any change. **The alert entity is the
initiator** (`InitiatedBy.user.userPrincipalName`), *not* the account added to the exclusion — resolve
the delta separately. Full IIRR: "Incident Investigation & Response Record: Conditional Access
user/group/role exclusion has changed" (Identity folder).

Pull the source event and diff old vs new — `oldVal`/`newVal` are full CA-policy JSON blobs:
```kusto
AuditLogs
| where TimeGenerated > ago(2d)
| where OperationName == "Update conditional access policy"
| extend initiator = tostring(InitiatedBy.user.userPrincipalName),
         initiatorApp = tostring(InitiatedBy.app.displayName),
         initiatorIp = tostring(InitiatedBy.user.ipAddress),
         policy = tostring(TargetResources[0].displayName),
         oldVal = tostring(TargetResources[0].modifiedProperties[0].oldValue),
         newVal = tostring(TargetResources[0].modifiedProperties[0].newValue)
| project TimeGenerated, Result, initiator, initiatorApp, initiatorIp, policy, oldVal, newVal
| order by TimeGenerated desc
```
Diff the `conditions.users.excludeUsers` arrays between `oldVal` and `newVal` to get the added/removed
GUIDs, resolve them via `IdentityInfo` (account-lookup query above), then run **two disconfirming
tests**: (a) the initiator's sign-in session at change time (compromised-admin check — fingerprint
query above), and (b) whether any newly-excluded account then signed in from the condition the policy
blocks (for a country-block policy, a post-change rogue-country sign-in). **Found (CLTB-6127):**
`admin@<CLTB_DOMAIN>` (authorized IT admin) added himself + `user@<CLTB_SUBBRAND_DOMAIN>` to "Block
Restricted Countries" `excludeUsers`; clean US session, no post-change foreign sign-ins → Benign Positive.

### Service-principal token used from a different IP than its sign-in (token-IP-mismatch alerts)

For "Activity from different IP then the one used at authentication" (CLTA Sentinel scheduled rule
`70ddb21a-…`). The rule joins `AzureActivity` (SP callers only) to `AADServicePrincipalSignInLogs` /
`AADManagedIdentitySignInLogs` on the token id (`Claims_d.uti` = `UniqueTokenIdentifier`) and fires
when `CallerIpAddress` differs from the sign-in `IPAddress`. **The only alert entity is the sign-in
IP** — no app or account. Re-run the rule logic over the alert's query window to name the SP:
```kusto
AzureActivity
| where TimeGenerated between (datetime(<QUERY_START>) .. datetime(<QUERY_END>))   // from ExtendedProperties
| where parse_json(tostring(Authorization_d.evidence)).principalType == "ServicePrincipal"
| project TimeGenerated, OperationNameValue, ActivityStatusValue, _ResourceId, ActivityIpAddress = CallerIpAddress,
          AppId = tostring(Claims_d.appid), Uti = tostring(Claims_d.uti), Role = tostring(parse_json(tostring(Authorization_d.evidence)).role)
| join kind=inner (union AADServicePrincipalSignInLogs, AADManagedIdentitySignInLogs
    | project SignInTime = TimeGenerated, SignInIpAddress = IPAddress, UniqueTokenIdentifier, ServicePrincipalName, ServicePrincipalId, ServicePrincipalCredentialKeyId, ResultType
    ) on $left.Uti == $right.UniqueTokenIdentifier
| where ActivityIpAddress != SignInIpAddress and SignInIpAddress != ""
```
Then baseline the SP — every sign-in IP and credential key it has used, and every caller IP in
`AzureActivity`:
```kusto
AADServicePrincipalSignInLogs
| where TimeGenerated > ago(14d)
| where AppId == "<APP_ID>"
| summarize n = count(), firstSeen = min(TimeGenerated), lastSeen = max(TimeGenerated), keys = make_set(ServicePrincipalCredentialKeyId) by ServicePrincipalName, IPAddress, ResultType
```
```kusto
AzureActivity
| where TimeGenerated > ago(14d)
| where tostring(Claims_d.appid) == "<APP_ID>"
| summarize n = count(), ops = make_set(OperationNameValue, 6), firstSeen = min(TimeGenerated), lastSeen = max(TimeGenerated) by CallerIpAddress
```
A sign-in on IPv6 with the call on IPv4 (or the reverse) from one dual-stack host is the common
benign shape: the token endpoint and ARM are reached over different address families. Benign when
both IPs are in the SP's baseline (same `/64` for IPv6), there is one known credential key, and the
operations fit the SP's role. Found (CLTA-39968): the flagged SP was SOC-Triage-IncidentLifecycle
(this triage host). Sign-in IPv6 was in `2001:db8:abcd:1200::/64`, the incident write came from
IPv4 `198.51.100.23`, and both matched the host's own egress.

### Token replay / Anomalous Token — where was the flagged session born?
For IPC "Anomalous Token" (often XDR-merged with "Unfamiliar sign-in properties" into "Initial access
incident involving one user"; look the incident up by `IncidentName` = GUID, the title changes).
Pull the interactive rows around the first flagged sign-in with `SessionId` and the auth-step methods,
then every row for the flagged `SessionId` by IP. A session ID seen on the **baseline first** and then
on the new IP = cookie replay. A session that only ever exists on the new IP was born there (second
device or AiTM-proxied login; still not settled).
```kusto
SigninLogs
| where TimeGenerated between (datetime(<first_flagged_minus_8h>) .. datetime(<first_flagged_plus_15m>))
| where UserId == "<object_id>"
| extend Br = tostring(DeviceDetail.browser), M = tostring(parse_json(AuthenticationDetails)[0].authenticationMethod), M2 = tostring(parse_json(AuthenticationDetails)[1].authenticationMethod)
| project TimeGenerated, IPAddress, ResultType, AppDisplayName, Br, M, M2, SessionId, RiskLevelDuringSignIn
| order by TimeGenerated asc
```
```kusto
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(10d)
| where UserId == "<object_id>" and SessionId == "<flagged_session_id>"
| summarize Count=count(), Ok=countif(ResultType == "0"), firstSeen=min(TimeGenerated), lastSeen=max(TimeGenerated), Apps=make_set(AppDisplayName, 8) by Type, IPAddress
```
`SecurityAlert.ExtendedProperties["Request Id"]` = `SigninLogs.OriginalRequestId`, which pins the exact flagged rows.
**Reading `StrongAuthenticationPhoneAppDetail`** (AuditLogs `Update user` at sign-in time): diff old vs
new. If only `LastAuthenticatedTimestamp` moved, an MFA push was approved on an **existing** device.
A new `DeviceToken`/`Id` means a **new** Authenticator. "User registered security info" with no
`Fido2AuthenticationMethod.*` / `SearchableDeviceKey` properties does not prove a passkey was added
(CLTB-7583).

### Post-auth mailbox actions from a flagged session (CLTB — `OfficeActivity` is ingested)
Sends, deletes, inbox rules and mailbox permissions by the user. `ClientIP` may carry a `:port` suffix,
so match with `startswith`. Pair with `EmailEvents` (sender = UPN) for subject/recipients and
`EmailUrlInfo` for the links.
```kusto
OfficeActivity
| where TimeGenerated > ago(3d)
| where UserId =~ "<upn>"
| where Operation in ("Send", "Create", "MoveToDeletedItems", "SoftDelete", "HardDelete", "New-InboxRule", "Set-InboxRule", "UpdateInboxRules", "Set-Mailbox", "Add-MailboxPermission")
| project TimeGenerated, Operation, ClientIP, Item=substring(tostring(Item),0,300), AffectedItems=substring(tostring(AffectedItems),0,300), Parameters=substring(Parameters,0,300)
| order by TimeGenerated asc
```
**Source IP owner:** `curl -s https://rdap.arin.net/registry/ip/<ip>` returns the netblock name and
org. Use it to tell hotel/resort/residential networks from hosting space (CLTB-7583: AT&T,
resort guest network).

### Did the actor enter the CURRENT password? Read the auth-step time, not the row time

Use on a re-alert after a containment password reset, where the attacker's rows show
"Correct password". `SigninLogs` rows from one interrupted flow (same `CorrelationId`) carry the
original first-factor step forward. The row's `TimeGenerated` can be hours after the reset while the
password check itself predates it.

```kusto
SigninLogs
| where TimeGenerated > datetime(<LAST_RESET_UTC>)
| where UserPrincipalName =~ "<UPN>" and IPAddress == "<SOURCE_IP>"
| mv-expand A = parse_json(AuthenticationDetails)
| project TimeGenerated, StepTime = tostring(A.authenticationStepDateTime), Method = tostring(A.authenticationMethod),
          Ok = tostring(A.succeeded), Detail = tostring(A.authenticationStepResultDetail), CorrelationId
| order by TimeGenerated asc
```
If `StepTime` is before the reset, the attacker does not have the new password. If it is after, the
new password leaked, so treat the reset-delivery channel as compromised (CLTB-7685: all four
post-reset "Correct password" rows had a step time of 15:11Z, before the 20:48Z re-reset).

### Identity Protection risk detections from the workspace (Graph 403 fallback)

Use when the Graph MCP `riskyUsers` / `riskDetections` read returns 403 (PIM role not active).
`AADUserRiskEvents` is ingested in CLTA `<CLTA_WORKSPACE_NAME>` and carries the same detections.

```kusto
AADUserRiskEvents
| where TimeGenerated > ago(14d)
| where UserPrincipalName =~ "<UPN>"
| summarize Count=count(), Last=max(TimeGenerated) by RiskEventType, IpAddress, RiskLevel, RiskState, RiskDetail
```
A detection that is `dismissed` with `aiConfirmedSigninSafe`, plus an `aiCompoundAccountRisk` with no
IP raised from it, is derived risk, not a second signal (CLTA-40099). Weigh only detections that carry
their own IP or evidence.

### App registration credential added: new app or planted secret? (first-credential-added alerts)

The rule fires on `Certificates and secrets management` where `KeyDescription` old value is `[]`. First decide whether the app was created in the same session (benign build) or is an established app that just got a secret (T1550 persistence). Then check whether the secret has been used. Get the appId from the application object ID via Graph MCP (`/v1.0/applications?$filter=id eq '<APP_OBJECT_ID>'`). Consent is checked with `/v1.0/oauth2PermissionGrants?$filter=clientId eq '<SP_OBJECT_ID>'`.

```kusto
// Lifecycle of the app + everything the actor did (30d)
AuditLogs
| where TimeGenerated > ago(30d)
| where tostring(InitiatedBy.user.userPrincipalName) =~ "<ACTOR_UPN>" or tostring(TargetResources) has "<APP_OBJECT_ID>" or tostring(TargetResources) has "<SP_OBJECT_ID>"
| extend Actor = coalesce(tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName)), ActorIP = tostring(InitiatedBy.user.ipAddress)
| summarize n=count(), firstSeen=min(TimeGenerated), lastSeen=max(TimeGenerated), Targets=make_set(tostring(TargetResources[0].displayName), 10) by OperationName, Actor, ActorIP, Result
| order by firstSeen asc
```

```kusto
// Disconfirming test: has the new credential been used? Validate zero rows with AADServicePrincipalSignInLogs | take 1
let aid = "<APP_ID>";
union isfuzzy=true
  (AADServicePrincipalSignInLogs | where TimeGenerated > ago(2d) | where AppId == aid | extend Src="SPSignin", Who=ServicePrincipalName),
  (SigninLogs | where TimeGenerated > ago(2d) | where AppId == aid | extend Src="UserSignin", Who=UserPrincipalName),
  (AADNonInteractiveUserSignInLogs | where TimeGenerated > ago(2d) | where AppId == aid | extend Src="NonIntSignin", Who=UserPrincipalName)
| summarize n=count(), firstSeen=min(TimeGenerated), lastSeen=max(TimeGenerated) by Src, Who, IPAddress, ResultType
```
Trap: `first` / `last` are reserved words in KQL. Use `firstSeen=min(...)` and `lastSeen=max(...)`, or the query fails with `SYN0002` (CLTA-40108).

## Traps (identity-specific)

| Trap | Symptom | Workaround |
|------|---------|------------|
| `union` drops dynamic columns | Referencing `LocationDetails` / `DeviceDetail` after `union SigninLogs, AADNonInteractiveUserSignInLogs` → *"Failed to resolve scalar expression"* / `SEM0139` | Query `SigninLogs` alone for device/location, or `extend` / `project` the fields inside each table before unioning. To keep one union, rebuild the split column: `extend L = parse_json(coalesce(tostring(column_ifexists("LocationDetails_dynamic", dynamic(null))), column_ifexists("LocationDetails_string", "")))` then `tostring(L.countryOrRegion)` — same for `DeviceDetail` (CLTB-7433) |
| `LocationDetails` is a **string** in `AADNonInteractiveUserSignInLogs` | `tostring(LocationDetails.countryOrRegion)` on that table → `SEM0070 … source must be scalar of type 'dynamic'` | `extend L = parse_json(LocationDetails)` first, then `tostring(L.countryOrRegion)` — the non-interactive table stores it as a JSON string, not a dynamic |
| MFA sub-status misread as access | `userPassedMFADrivenByRiskBasedPolicy` read as "logged in" | Read the final `ResultType`; a non-zero result (e.g. `70045`) means no token was issued despite the MFA pass |
| `has` misses substrings in a UPN | `Actor has "smith"` returns **zero rows** — `has` matches whole tokens, and `jsmith@example.com` tokenises to `jsmith`/`example`/`com` | Use `contains` for partial matches inside UPNs/emails; reserve `has` for whole-word matches (e.g. a display name in `TargetResources`) |
| `==` on a UPN is case-sensitive | `where UserPrincipalName == "Svc_Report_Admin@…"` returns **zero rows** though the account is highly active — `SigninLogs`/`AADNonInteractiveUserSignInLogs` store the UPN lowercased, while `AuditLogs`/`IdentityInfo` preserve the original casing (so a UPN that matches there still misses in the sign-in tables) | Key sign-in queries on the **object id** (`UserId == "<guid>"`) resolved from `IdentityInfo`, or use `=~`. An unvalidated empty "no sign-ins" here reads as "no baseline / can't confirm origin" and can wrongly push a benign self-service change toward escalation (CLTB-6525) |
| `OperationName` truncates | Truncated column can't distinguish a PIM activation from a permanent assignment | `summarize count() by OperationName` on its own so it renders full width |
| Role name not in `modifiedProperties` | PIM role events carry only `TemplateId` / `RoleDefinitionOriginId` / `RoleDefinitionOriginType` | Expand `TargetResources`, read the entry where `type == "Role"`; resolve template GUIDs from the data, never from memory |
| `InitiatedBy` needs double conversion | `InitiatedBy.user.userPrincipalName` may not resolve | `tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName)` |
| Domain-wide over-match on shared mailbox | `UserPrincipalName contains "<domain-word>"` matches every account at the domain | Key on the distinctive display-name token, then confirm the exact UPN |
| Fixed `±Nh` windows clip the burst | ±2h anchored on alert time missed both onset and baseline | Scope by `ago()` over days first; narrow once the true burst edges are known |
| `first` / `last` are reserved words | `summarize first = min(TimeGenerated)` → `SYN0002 Query could not be parsed at 'first'` | Alias as `firstSeen` / `lastSeen` (CLTA-39968) |
| IPv6 read as a new source | A second address differing only in the host portion looks like a second device | Compare the `/64` — privacy addressing rotates the host portion on the same line |
| PowerShell escaping | Single quotes inside KQL break PowerShell `@{ query = '...' }` | Use a here-string (`@'...'@`) for the query value, or escape inner single quotes by doubling (`''`) |
| Deleted user's UPN is masked | A `Delete user` target UPN is a dashless GUID, not the real UPN | Match the delete's `TargetResources.id` (`TId`) to an `Add user` event's `TId` to identify the account |
| Near-identical UPNs from a collision | `name@dom` and `name1@dom` look like one account | Key on **objectId**; a `UserPrincipalName contains "<token>"` sign-in query separates them one row per UPN |
| Row time read as password time | "Correct password" on a `50074` row hours after a containment reset looks like the attacker has the new password | Expand `AuthenticationDetails` and read `authenticationStepDateTime`. A step before the reset (same `CorrelationId`) is a carried-over claim (CLTB-7685) |

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
| `50203` | User has not registered the authenticator app | MFA gate | Primary auth **succeeded**; registration prompt. Not a credential failure. On a shared mailbox = hygiene finding (no MFA method registered) (CLTB-7211) |
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
