# KQL — MDO post-delivery / ZAP email detections (`kql-email.md`)

For Sentinel rules sourced from Microsoft Defender for Office 365:
post-delivery detections (phish/malware delivered then retroactively flagged), ZAP actions,
and URL-click alerts. Core tables: `EmailEvents`, `EmailUrlInfo`, `UrlClickEvents`,
`EmailPostDeliveryEvents`. These tables live in the **Defender Advanced Hunting** console
(`security.microsoft.com` → Hunting → Advanced Hunting), **not** in the Sentinel Log Analytics
workspace — check the ingestion map for your client before running.

> Universal KQL conventions (validate every zero-row negative, `ago()`-scope-then-narrow, KQL mode,
> terminal KQL conventions, SMTP≠UPN) live in the skill body. This file carries only the
> email-family patterns, traps, and reference tables.

## Query patterns

### 1. Delivery outcome for a message
Start here. Shows what Defender's stack verdict was, whether it was delivered, and the action
chain that followed.
```kusto
EmailEvents
| where TimeGenerated > ago(3d)
| where NetworkMessageId == "<message_id>"
| project TimeGenerated, SenderFromAddress, RecipientEmailAddress,
    Subject, DeliveryAction, DeliveryLocation,
    ThreatTypes, ThreatNames, DetectionMethods,
    AuthenticationDetails, ConfidenceLevel
```

### 2. ZAP and post-delivery actions
Did ZAP remove it after delivery? The `Action` column is the decisive field — `"ZAP"` means
the message was retroactively moved.
```kusto
EmailPostDeliveryEvents
| where TimeGenerated > ago(3d)
| where NetworkMessageId == "<message_id>"
| project TimeGenerated, RecipientEmailAddress,
    Action, ActionType, ActionTrigger, ActionResult,
    DeliveryLocation
```

### 3. URL click check — did anyone click?
The single highest-value question after a phish delivery. Zero rows = **no click recorded by
SafeLinks**. Note: SafeLinks only tracks clicks through wrapped URLs; a direct paste or a client
that strips wrapping produces no row.
```kusto
UrlClickEvents
| where TimeGenerated > ago(3d)
| where NetworkMessageId == "<message_id>"
| project TimeGenerated, AccountUpn, Url,
    ActionType, IsClickedThrough, UrlChain,
    IPAddress, ThreatTypes
```

### 4. URL enumeration — what URLs were in the message?
```kusto
EmailUrlInfo
| where TimeGenerated > ago(3d)
| where NetworkMessageId == "<message_id>"
| project Url, UrlDomain, UrlLocation
```

### 5. Zero-click validation — confirm no click across all recipients
When the alert fires on a message sent to multiple recipients, check breadth.
```kusto
UrlClickEvents
| where TimeGenerated > ago(3d)
| where Url has "<domain_or_url_fragment>"
| summarize Clicks=count(), Clickers=dcount(AccountUpn)
    by Url, ActionType, IsClickedThrough
```

### 6. Resolve SMTP → UPN for identity pivot
Email tables key on SMTP address; identity tables key on UPN. They may differ. Resolve before
pivoting to sign-in or audit queries.
```kusto
IdentityInfo
| where TimeGenerated > ago(14d)
| where AccountUpn has "<name>" or EmailAddress has "<name>"
| summarize arg_max(TimeGenerated, *) by AccountObjectId
| project AccountUpn, EmailAddress, AccountDisplayName,
    Department, JobTitle, AccountObjectId
```

### 7. Mailbox-rule / forwarding tampering
Post-compromise persistence check. An inbox rule created shortly after a phish click is an
escalation trigger.
```kusto
CloudAppEvents
| where TimeGenerated > ago(7d)
| where AccountDisplayName has "<name>"
    or AccountId has "<upn>"
| where ActionType has_any ("New-InboxRule", "Set-InboxRule",
    "Set-Mailbox", "New-TransportRule", "UpdateInboxRules")
| project TimeGenerated, AccountDisplayName, ActionType,
    RawEventData, IPAddress
```

### 8. Campaign scope — same sender / subject across the tenant
How many recipients got the same campaign? Breadth determines whether response is per-user or
tenant-wide.
```kusto
EmailEvents
| where TimeGenerated > ago(3d)
| where SenderFromAddress == "<sender>"
    or Subject has "<subject_token>"
| summarize Recipients=dcount(RecipientEmailAddress),
    Messages=count(),
    First=min(TimeGenerated), Last=max(TimeGenerated)
    by SenderFromAddress, Subject, DeliveryAction, DeliveryLocation
| order by Recipients desc
```

## Traps (email-specific)

| Trap | Symptom | Workaround |
|------|---------|------------|
| Tables not in Sentinel workspace | `EmailEvents` / `UrlClickEvents` return zero rows in Log Analytics | These tables live in Defender AH only for some tenants — check the ingestion map |
| SMTP ≠ UPN | Pivoting from email to sign-in on SMTP address returns zero | Resolve via `IdentityInfo` or Graph; key identity queries on UPN |
| SafeLinks wrapping gap | No `UrlClickEvents` row despite a known click | Client may have pasted URL directly, or SafeLinks wasn't applied (internal/allow-listed sender) |
| ZAP timing | Alert fires after ZAP already removed the message | Check `EmailPostDeliveryEvents` for the ZAP action — "delivered" in `EmailEvents` may already be remediated |
| `NetworkMessageId` format | Some alerts surface the ID with angle brackets, some without | Strip `<>` before querying; the tables store it without brackets |
| Shared / distribution-list delivery | One message ID, multiple recipients | Always check campaign scope to catch breadth; a single-recipient check undercounts |

## Reusable classification logic (email / post-delivery type)

**Lean benign positive when:** ZAP removed the message before any click; zero `UrlClickEvents`
rows for the message ID and URL domain; the threat type is bulk/spam rather than phish/malware;
the sender is a known vendor whose messages are routinely flagged; no mailbox-rule changes
follow the delivery.

**Escalate when:** `UrlClickEvents` shows `IsClickedThrough == true`; a mailbox rule was
created or modified after the delivery timestamp; the same campaign hit multiple recipients and
any of them clicked; the threat type is credential-phish or malware; the URL domain is a known
phishing infrastructure domain; sign-in anomalies appear for the clicking user after the click
timestamp.

> Post-delivery alerts measure what Defender learned *after* delivery. The alert does not mean
> the user was compromised — it means Defender now believes the message was malicious. The triage
> question is: did anyone interact with it, and if so, what happened next?
