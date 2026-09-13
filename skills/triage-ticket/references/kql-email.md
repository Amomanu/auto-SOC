# KQL — Microsoft Defender for Office 365, post-delivery / ZAP email detections (`kql-email.md`)

For MDO alerts of the *"Messages containing malicious entity not removed after delivery"* /
Zero-hour Auto Purge (ZAP) family. **Run all queries via terminal `az rest`** against the Log
Analytics workspace (see SKILL.md §0 for workspace IDs and the `az rest` pattern). On **CLTA**,
all email tables (`EmailEvents`, `UrlClickEvents`, `EmailPostDeliveryEvents`, `EmailUrlInfo`,
`CloudAppEvents`) are ingested into `<CLTA_WORKSPACE_NAME>` and fully queryable from the terminal. The join
key is the **`NetworkMessageId`**, taken from the `SecurityAlert.Entities` JSON (query via terminal
— the ticket often lists it in a column that reads like a user object ID — it is not). An incident
may bundle **more than one** message; enumerate every Mail Message entity and OR all their IDs.

> Universal KQL conventions (validate every zero-row negative, `ago()`-scope-then-narrow, KQL mode,
> terminal KQL conventions, SMTP≠UPN) live in the skill body. This file is otherwise
> self-contained — it carries its own copy of the identity/mailbox follow-on queries, because those
> checks are part of the email playbook and differ from the sign-in family (mailboxes here often
> have no interactive sign-ins).

**The decision rests on two facts, in order: *where did it land* (`DeliveryLocation`) and *did anyone
click* (`UrlClickEvents`).** `Junked`/`Quarantine` + zero clicks = no-impact cleanup; `Inbox/folder`
+ still present raises exposure; any `UrlClickEvents` row (esp. `IsClickedThrough`) converts it to a
credential-compromise investigation. See the CLTB-3374 (junked/no-impact) and CLTB-3496
(inbox-delivered/remediation-required) IIRR pages in the Claude Decision History for worked examples.

## Query patterns

### 1. Delivery outcome + verdict + authentication (the severity cut)
Key on all NetworkMessageIds the incident carries. OR the IDs rather than using `in (...)` — avoids
escaping issues and keeps the query straightforward.
```kusto
EmailEvents
| where NetworkMessageId == "<nmid1>" or NetworkMessageId == "<nmid2>"
| project Timestamp, Subject, SenderFromAddress, SenderMailFromAddress, SenderIPv4,
          RecipientEmailAddress, EmailDirection, DeliveryAction, DeliveryLocation,
          LatestDeliveryAction, LatestDeliveryLocation, ThreatTypes, DetectionMethods,
          ConfidenceLevel, AuthenticationDetails, NetworkMessageId
```
`DeliveryLocation = Inbox/folder` with `LatestDeliveryLocation = Unknown` / `LatestDeliveryAction =
None` means the message reached the inbox and nothing relocated it — it is still there. All four of
SPF/DKIM/DMARC/CompAuth `pass` = attacker owns the sending domain (brand impersonation), not spoofing.

### 2. ZAP outcome + click check + URL enumeration in one pass (the decisive query)
```kusto
union EmailPostDeliveryEvents, UrlClickEvents, EmailUrlInfo
| where NetworkMessageId == "<nmid1>" or NetworkMessageId == "<nmid2>"
| project Timestamp, Type, Action, ActionType, ActionResult, ActionTrigger,
          RecipientEmailAddress, AccountUpn, Url, IsClickedThrough, ThreatTypes,
          NetworkMessageId
| sort by Timestamp asc
```
`EmailPostDeliveryEvents` rows with `ActionType` = `Phish ZAP`/`Malware ZAP`, `Action = None`,
`ActionResult = Error` confirm the ZAP failure. **Zero `UrlClickEvents` rows is the decisive
negative** — but validate it (pattern 4). `UrlDomain` resolves only for the `EmailUrlInfo` rows.

### 3. Enumerate payload URLs
Legitimate-brand links in the body are **decoys** included to raise the reputation score. A
responder who reads "links to intuit.com" and stops will misjudge the message. `UrlDomain`
resolves only on `EmailUrlInfo`, not on `UrlClickEvents`.
```kusto
EmailUrlInfo
| where NetworkMessageId == "<nmid1>" or NetworkMessageId == "<nmid2>"
| distinct UrlDomain, Url
| sort by UrlDomain asc
```

### 4. Validate the zero-click negative against a populated table
A zero-click result is not evidence until you show clicks *are* recorded in the tenant. First look
for the recipient's own click history / campaign-domain clicks; if empty, prove the table is live.
```kusto
// (a) recipient + campaign-domain clicks — note: UrlClickEvents has NO UrlDomain column
UrlClickEvents
| where Timestamp > ago(30d)
| where AccountUpn has "<surname>" or Url has "<campaign-domain>"
| project Timestamp, AccountUpn, Url, ActionType, IsClickedThrough, NetworkMessageId
| sort by Timestamp desc
// (b) populated-table proof if (a) is empty
UrlClickEvents | where Timestamp > ago(30d)
| project Timestamp, AccountUpn, Url, ActionType, IsClickedThrough | take 5
```

### 5. Resolve email → real UPN + account state (when sign-in search returns nothing)
Run this when `EntraIdSignInEvents | search "<name>"` is empty: it confirms the account exists, is
enabled, and whether the SMTP address is the UPN. An enabled mailbox with **no** sign-ins is itself
a valid (validated) negative for the identity question — there is no interactive logon surface.
```kusto
IdentityInfo
| where EmailAddress has "<localpart>" or AccountUpn has "<localpart>"
      or AccountName has "<localpart>"
| distinct AccountDisplayName, AccountUpn, AccountName, EmailAddress, IsAccountEnabled
```

### 6. Identity baseline / risk for the recipient (Defender side)
```kusto
EntraIdSignInEvents
| where Timestamp > ago(30d)
| where AccountUpn =~ "<upn>"          // if empty, first: | search "<surname>" to find the account
| project Timestamp, Application, IPAddress, Country, City,
          RiskLevelDuringSignIn, RiskState, ErrorCode
| sort by Timestamp desc | take 50
```

### 7. Mailbox tampering — inbox rules / forwarding / delegation / consent (+ validate)
Put the cheap `ActionType` filter first; a leading `search`/`RawEventData` scan over 30d is
expensive (one run here consumed 21% of the 15-min allocation).
```kusto
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType contains "Rule" or ActionType contains "Forward"
     or ActionType contains "Delegate" or ActionType contains "Consent"
| where AccountDisplayName has "<surname>"
| project Timestamp, ActionType, AccountDisplayName, IPAddress, Application
| sort by Timestamp desc | take 50
// validation — prove UpdateInboxRules is recorded for other accounts
CloudAppEvents | where Timestamp > ago(30d)
| where ActionType contains "InboxRule" or ActionType contains "Forward"
| project Timestamp, ActionType, AccountDisplayName | take 5
```

### 8. Campaign scope tenant-wide, then narrow to inbox deliveries
Establishes breadth and surfaces control cases (identical infra handled differently).
```kusto
EmailEvents
| where Timestamp > ago(30d)
| where SenderIPv4 == "<ip>" or SenderFromDomain == "<dom1>" or SenderFromDomain == "<dom2>"
| project Timestamp, RecipientEmailAddress, SenderFromAddress, SenderIPv4, Subject,
          DeliveryAction, DeliveryLocation, LatestDeliveryLocation, ThreatTypes
| sort by Timestamp desc
// add  | where DeliveryLocation == "Inbox/folder"  to count how many actually reached inboxes
```

## Traps (email-specific)

| Trap | Symptom | Workaround |
|------|---------|------------|
| Email tables not in every workspace | Some workspaces do not ingest `EmailEvents` / `EmailPostDeliveryEvents` / `UrlClickEvents` — a `| take 5` returns zero | Validate the table is populated in the workspace before trusting a zero result. CLTA `<CLTA_WORKSPACE_NAME>` has them all; CLTB `<CLTB_WORKSPACE_NAME>` has `EmailEvents` / `EmailPostDeliveryEvents` / `UrlClickEvents` / `EmailUrlInfo` since 2026-09-09 but **not** `CloudAppEvents` |
| Joining through `AlertInfo`/`AlertEvidence` on the alert window | Zero rows even though message telemetry is fully present | Filter directly on `NetworkMessageId` from the incident entity panel; don't derive it from alert joins |
| Ticket GUID ≠ user object ID | The incident lists a GUID in a user-looking column | It is the `NetworkMessageId`. Also: an incident can bundle several — enumerate every Mail Message entity and OR all IDs |
| SMTP address is not the UPN | `EntraIdSignInEvents \| search "<name>"` returns zero despite an active user | The SMTP alias may differ from the UPN; use `IdentityInfo` (pattern 5) to resolve, then key on the real UPN. Also confirm `AccountDisplayName` to avoid surname collisions |
| Zero rows treated as evidence | Empty click / rule / sign-in result read as "nothing happened" | Pair every negative with a companion query proving the table is populated (patterns 4b, 7-validation) |
| Enabled mailbox, zero sign-ins | `EntraIdSignInEvents` empty for an enabled account over 30d | Valid *validated* negative (no logon surface), not an error — but state it explicitly; you cannot present a clean sign-in baseline that doesn't exist |
| `UrlClickEvents` has no `UrlDomain` | `project ... UrlDomain` → *"Failed to resolve scalar expression named 'UrlDomain'"* | `UrlClickEvents` carries `Url` only; drop `UrlDomain` (it exists on `EmailUrlInfo`) |
| `first` / `last` as summarize aliases | `Query could not be parsed at 'first'` | Reserved words in KQL. Use `firstSeen=min(...)`, `lastSeen=max(...)` |
| `IdentityInfo` column names differ in CLTB `<CLTB_WORKSPACE_NAME>` | `Failed to resolve scalar expression named 'AccountUpn'` / `'EmailAddress'` | CLTB `IdentityInfo` uses `AccountUPN` (capital UPN), `MailAddress` (often empty) and `AccountName`; there is no `EmailAddress`. When unsure, `IdentityInfo \| search "<local part>" \| take 2` and read the columns back |
| `union` of `SigninLogs` + `AADNonInteractiveUserSignInLogs` fails | `Failed to resolve expression 'LocationDetails.countryOrRegion'` / `'LocationDetails'` | Schema mismatch (dynamic vs string). Query the tables separately; `parse_json(LocationDetails)` on the non-interactive table (pattern 10) |
| Incident `Closed / Undetermined` by "Microsoft XDR", empty `AlertIds` | Looks like a prior resolution; step-5 short-circuit would close the Jira ticket | XDR alert-correlation merge, alert still live in another incident. Run pattern 9, then investigate normally |
| XDR-owned shell incident ignores Sentinel classification writes | PUT to the Sentinel incidents API returns 200, etag advances, but `classification` stays `Undetermined` | The shell has `providerName = Microsoft XDR` and was closed by alert correlation; classification lives on the XDR incident that now holds the alert. Always GET after PUT to confirm; record the verdict in Jira and never state the Sentinel classification was updated without that GET (CLTB-6311) |
| Costly leading scan | `CloudAppEvents \| search "..."` / `RawEventData has` over 30d eats a large share of the 15-min query allocation | Put the indexed `where ActionType contains ...` first, then narrow by account |

### 9. Incident closed by "Microsoft XDR" with `Classification = Undetermined` — check for an alert-correlation merge before short-circuiting
A Sentinel incident that shows `Status = Closed`, `ModifiedBy = "Microsoft XDR"`, `Classification =
Undetermined` and an **empty `AlertIds`** on its latest row was not resolved by anyone — Defender XDR
alert correlation moved the alert into a different (usually multi-user "Initial access") incident and
closed the now-empty shell. The alert itself is still live. **Do not apply the step-5 short-circuit**;
find where the alert went and investigate normally. (CLTB-6311: alert moved 20397 → 20393 → 20230.)
```kusto
let ids = SecurityIncident | where IncidentName == "<incident-guid>"
  | mv-expand AlertIds | extend AlertId = tostring(AlertIds) | where isnotempty(AlertId) | distinct AlertId;
union
 (SecurityIncident | where IncidentName == "<incident-guid>"
   | project TimeGenerated, Kind="history", IncidentNumber, Status, Classification, ModifiedBy, AlertIds=tostring(AlertIds)
   | sort by TimeGenerated asc),
 (SecurityIncident | where TimeGenerated > ago(3d) | mv-expand AlertIds | extend AlertId = tostring(AlertIds)
   | where AlertId in (ids) and IncidentName != "<incident-guid>"
   | summarize arg_max(TimeGenerated, Status, Classification, ModifiedBy, Title) by IncidentNumber, IncidentName),
 (SecurityAlert | where TimeGenerated > ago(3d) | where SystemAlertId in (ids)
   | project TimeGenerated, Kind="alert", Status, AlertName, ProductName, SystemAlertId)
```
When closing out, re-classify the merged-away shell incident (PUT, see SKILL.md guardrails) so the
sibling-classification history stays consistent; leave the multi-user correlation incident alone
unless the ticket covers it.

### 10. Post-delivery sign-ins across interactive + non-interactive tables (CLTB terminal)
`union SigninLogs, AADNonInteractiveUserSignInLogs` fails on `LocationDetails` (dynamic in one table,
string in the other) — query the two tables **separately** and `parse_json(LocationDetails)` on the
non-interactive one. Both are ingested in CLTB `<CLTB_WORKSPACE_NAME>`.
```kusto
AADNonInteractiveUserSignInLogs
| where TimeGenerated > datetime(<delivery-time>)
| where UserPrincipalName has "<recipient local part>"
| extend loc = parse_json(LocationDetails)
| summarize n=count(), firstSeen=min(TimeGenerated), lastSeen=max(TimeGenerated), apps=make_set(AppDisplayName, 6)
        by UserPrincipalName, IPAddress, Country=tostring(loc.countryOrRegion), State=tostring(loc.state), ResultType
| sort by n desc
```
Mobile-carrier IPv6 (`2600:1005:` Verizon, `2601:` Comcast) with `Outlook Mobile` / `Microsoft
Authentication Broker` in the same state as the office IP is the user's phone, not off-baseline.

## Reusable classification logic (MDO post-delivery / ZAP type)

**True Positive — no impact (cleanup) when:** `DeliveryLocation` is **Junk/Quarantine**;
`UrlClickEvents` is **zero** (validated); recipient sign-in geo/risk clean (or no sign-in surface,
validated); no inbox-rule/forward/delegation/consent; the ZAP failure is the only adverse finding.

**True Positive — remediation required (still no compromise) when:** `DeliveryLocation` is
**Inbox/folder** and `LatestDeliveryLocation` shows it is still there, **but** clicks are zero
(validated) and identity/mailbox baselines are clean. Malicious verdict + inbox exposure make the
"manual action required" legitimate (purge the message via Explorer), yet no identity containment is
warranted. Classify on the **combination** of delivery location and interaction — inbox delivery
alone does not mean identity IR.

**Escalate to phished/compromised-account workflow when:** any `UrlClickEvents` row (esp.
`IsClickedThrough = true`); post-delivery sign-ins from off-baseline geo / hosting ASN /
impossible-travel; inbox-rule / forwarding / delegation / new MFA / OAuth-consent after delivery;
the campaign reached many recipients at inbox level.

> A failed purge is only as serious as the exposure it failed to remove. Establish where the message
> landed and whether anyone touched it before deciding what the failure cost — and treat Defender's
> Malware/Phish verdict as authoritative even when the content reads like bulk marketing/graymail.

## Sub-type: "Mail bombing activity detected" (M365 Defender / XDR volume detection)

A **different animal** from ZAP — a *volume* alarm, not a payload alarm (`MicrosoftThreatProtection`,
T1566/InitialAccess). Defender clusters a burst of inbound mail to one mailbox into a `mailCluster`
entity; the messages are almost always **legitimate ESP newsletter "Please Confirm Subscription"
double-opt-in** emails (Mailchimp/Mandrill `mcsignup.com`, Brevo `brevosend.com`) — i.e. an attacker
subscription-bombed the address. **Nothing to ZAP/purge; the mail content is not the attack.** The
detection is a **precursor** — it precedes MFA-fatigue/takeover or a help-desk **vishing** call.

- **Decision axis = follow-on impact, not the mail.** It's a True Positive on the *activity*; the
  split is whether an account compromise followed. Ignore delivery/click; pivot to identity + audit.
- **Get the mail picture from `SecurityAlert.Entities`** (the `mailCluster` + sampled `mailMessage`
  entities) — the GUIDs in the ticket entity table are `NetworkMessageId`s, not user ids.
- **Disconfirming test (run early):** sign-ins over `ago(10d)` from established vs. off-baseline
  sources, and audit for account changes the flood might hide.
  - **CLTB / terminal:** `SigninLogs`, `AADNonInteractiveUserSignInLogs` — both ingested, query separately per pattern 10 (geo/IP/risk/off-baseline
    success), `AuditLogs` (password reset, MFA/auth-method registration, inbox forwarding/delegation,
    OAuth consent). `Update StsRefreshTokenValidFrom Timestamp` in `AuditLogs` = a **session
    revocation** (defensive), often the customer admin — don't misread it as attacker activity.
  - **CLTA / Defender AH:** the family's patterns 6–7 (`EntraIdSignInEvents`, `CloudAppEvents`).
- **Classification:** clean identity/audit → **True Positive, no compromise** (close; advise the user
  on the vishing follow-on — no unsolicited "IT" remote-access). Off-baseline sign-in / MFA-fatigue
  success / post-burst password-MFA-forwarding-consent change → **escalate to account-compromise IR**.
  Not Benign Positive — the activity is malicious/unwanted even when no compromise follows.
- **CLTB constraint (updated 2026-09-11):** `EmailEvents`/`UrlClickEvents`/`EmailPostDeliveryEvents`/
  `EmailUrlInfo`, `SigninLogs`, `AADNonInteractiveUserSignInLogs` and `AuditLogs` **are** ingested in
  `<CLTB_WORKSPACE_NAME>`; only `CloudAppEvents` is not. The direct `api.loganalytics.io` endpoint works for the
  analyst account (CLTB-6119, CLTB-6311); if it ever 403s, fall back to the **ARM-proxied**
  `management.azure.com/.../workspaces/<CLTB_WORKSPACE_NAME>/query?api-version=2017-10-01` path.
  Full flood volume is Defender-portal only.

See the **"Mail Bombing Activity Detected"** IIRR page (Claude Decisions History → Email) for the
full parameterized playbook. First case: CLTB-6098 / incident 19791 (True Positive, no compromise).
