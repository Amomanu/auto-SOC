# KQL — AWS CloudTrail (`AWSCloudTrail`) cloud API-activity detections (`kql-aws.md`)

For AWS-sourced Sentinel rules (IAM privilege escalation, security-group changes, CloudTrail
tampering, etc.). The involved entity in these tickets is often just a generic account like
`AWSCloudFormation` — the real evidence (who called the API, from where, on what) is in
`AWSCloudTrail`, keyed on the **`EventName`** and the **caller identity**.

> Universal KQL conventions (validate every zero-row negative, `ago()`-scope-then-narrow, KQL mode,
> terminal KQL conventions) live in the skill body. This file carries only the AWS-family
> patterns, traps, and classification logic.

**The decisive cut for AWS is *who called it*, not *how many times*.** The disconfirming test here
is: was the actor a **human IAM principal** or an **AWS service principal** doing automation?
`UserIdentityInvokedBy` names the calling service (`cloudformation.amazonaws.com`,
`ssm.amazonaws.com`, …); `SourceIpAddress` shows that same service name (not an IP) for
service-initiated calls; `UserIdentityType` is typically `AssumedRole`. Actions performed by AWS
services provisioning infrastructure (IaC) are benign automation, not privilege escalation —
regardless of how alarming the `EventName` looks.

## Query patterns

### Characterise the flagged API events (e.g. Attach*Policy privilege-escalation rule)
```kusto
AWSCloudTrail
| where TimeGenerated > ago(3d)
| where EventName startswith "Attach"          // or the exact EventName(s) the rule keys on
| project TimeGenerated, EventName, UserIdentityArn, UserIdentityType, SourceIpAddress,
          AWSRegion, RequestParameters, ErrorCode
| order by TimeGenerated asc
```

### Roll up by caller, source, and target — parse RequestParameters
`RequestParameters` is JSON; `parse_json` it to read `roleName` / `policyArn` / `userName` etc.
```kusto
AWSCloudTrail
| where TimeGenerated > ago(3d)
| where EventName startswith "Attach"
| extend rp = parse_json(RequestParameters)
| extend RoleName = tostring(rp.roleName), PolicyArn = tostring(rp.policyArn)
| summarize Count=count(), First=min(TimeGenerated), Last=max(TimeGenerated),
    Accounts=dcount(RecipientAccountId), Errors=countif(isnotempty(ErrorCode))
    by EventName, SourceIpAddress, RoleName, PolicyArn
| order by Count desc
```

### The disconfirming test — human principal vs. AWS service automation
If every event is invoked by an AWS service (`cloudformation.amazonaws.com`, `ssm.amazonaws.com`)
as an `AssumedRole`, and none originate from a human/off-service IP, it's automation → benign.
```kusto
AWSCloudTrail
| where TimeGenerated > ago(3d)
| where EventName startswith "Attach"
| summarize Count=count() by ErrorCode, UserIdentityInvokedBy, UserIdentityType
```

### Pin the alert-time event and confirm success/failure
Sentinel/incident times are usually **local (EDT)**; `AWSCloudTrail.TimeGenerated` is **UTC**
(EDT = UTC−4). Widen to the whole day to catch it regardless of TZ, then match the second.
```kusto
AWSCloudTrail
| where TimeGenerated between (datetime(<yyyy-mm-dd>) .. datetime(<next-day>))
| where EventName startswith "Attach"
| extend rp = parse_json(RequestParameters)
| project TimeGenerated, EventName, SourceIpAddress, UserIdentityType, UserIdentityInvokedBy,
          RoleName=tostring(rp.roleName), PolicyArn=tostring(rp.policyArn), ErrorCode
| order by TimeGenerated asc
```

## Traps (AWS-specific)

| Trap | Symptom | Workaround |
|------|---------|------------|
| `SourceIpAddress` isn't an IP | Value is `cloudformation.amazonaws.com` / `ssm.amazonaws.com` | That's a **service principal** — the call is AWS-initiated automation, not a human. This is the key benign signal, not a data error |
| `RequestParameters` is JSON text | Can't filter on `roleName` / `policyArn` directly | `extend rp = parse_json(RequestParameters)` then `tostring(rp.<field>)` |
| Local vs UTC time | Incident says 15:10 but rows are at 19:10 | Incident time is EDT (UTC−4); CloudTrail is UTC. Convert or query the whole day |
| Generic entity | Ticket entity is just `AWSCloudFormation` | Ignore it as an identifier; pivot on `EventName` + caller identity in `AWSCloudTrail` |

## Reusable classification logic (AWS API-activity type)

**Lean Benign Positive when:** every event is invoked by an **AWS service principal**
(`UserIdentityInvokedBy` = `cloudformation.amazonaws.com`, `ssm.amazonaws.com`, …) as an
`AssumedRole`; the roles/policies are **AWS-managed or IaC-provisioned** (e.g.
`AmazonSSMRoleForInstancesQuickSetup`, `use1-*` CloudFormation stack roles — `use1` = us-east-1
region prefix); **no `AdministratorAccess`/wildcard** policy; **no human or off-service source IP**;
events **succeeded** (no `ErrorCode`) as routine provisioning; sibling incidents in the same family
were previously closed benign.

**Escalate when:** the caller is a **human IAM user / assumed-role with a real `SourceIpAddress`**
(especially a hosting/VPS ASN or off-baseline geography); the policy attached is **`AdministratorAccess`
or a broad wildcard**; the action targets a **user/group the actor shouldn't touch**; it pairs with
other AWS alerts (access-key creation, CloudTrail tampering, security-group opening) in the same
session; or the same principal chains several privilege-affecting calls.

> An IAM "privilege escalation" rule fires on the API verb (`AttachRolePolicy`, …), blind to *who*
> called it. CloudFormation and SSM attach policies constantly as normal IaC — the verb is the
> alarm, the **caller identity** is the answer.
