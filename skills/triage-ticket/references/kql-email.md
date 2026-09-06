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
| Email tables not in every workspace | Some workspaces do not ingest `EmailEvents` / `EmailPostDeliveryEvents` / `UrlClickEvents` — a `| take 5` returns zero | Validate the table is populated in the workspace before trusting a zero result. CLTA `<CLTA_WORKSPACE_NAME>` has them all; CLTB `<CLTB_WORKSPACE_NAME>` does not |
| Joining through `AlertInfo`/`AlertEvidence` on the alert window | Zero rows even though message telemetry is fully present | Filter directly on `NetworkMessageId` from the incident entity panel; don't derive it from alert joins |
| Ticket GUID ≠ user object ID | The incident lists a GUID in a user-looking column | It is the `NetworkMessageId`. Also: an incident can bundle several — enumerate every Mail Message entity and OR all IDs |
| SMTP address is not the UPN | `EntraIdSignInEvents \| search "<name>"` returns zero despite an active user | The SMTP alias may differ from the UPN; use `IdentityInfo` (pattern 5) to resolve, then key on the real UPN. Also confirm `AccountDisplayName` to avoid surname collisions |
| Zero rows treated as evidence | Empty click / rule / sign-in result read as "nothing happened" | Pair every negative with a companion query proving the table is populated (patterns 4b, 7-validation) |
| Enabled mailbox, zero sign-ins | `EntraIdSignInEvents` empty for an enabled account over 30d | Valid *validated* negative (no logon surface), not an error — but state it explicitly; you cannot present a clean sign-in baseline that doesn't exist |
| `UrlClickEvents` has no `UrlDomain` | `project ... UrlDomain` → *"Failed to resolve scalar expression named 'UrlDomain'"* | `UrlClickEvents` carries `Url` only; drop `UrlDomain` (it exists on `EmailUrlInfo`) |
| Costly leading scan | `CloudAppEvents \| search "..."` / `RawEventData has` over 30d eats a large share of the 15-min query allocation | Put the indexed `where ActionType contains ...` first, then narrow by account |

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
