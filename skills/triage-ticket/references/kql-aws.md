# KQL — AWS CloudTrail API-activity detections (`kql-aws.md`)

For Sentinel rules sourced from the AWS CloudTrail connector: unusual API calls, root-account
usage, IAM changes, S3 public-access modifications, security-group changes, and GuardDuty
findings forwarded to Sentinel. Core table: `AWSCloudTrail`. Run via terminal `az rest` against
the Log Analytics workspace.

> Universal KQL conventions (validate every zero-row negative, `ago()`-scope-then-narrow, KQL mode,
> terminal KQL conventions) live in the skill body. This file carries only the AWS-family patterns,
> traps, and reference tables.

## The decisive cut: who called it

CloudTrail logs every API call. The first question is never *what* was called — it's *who*
called it.

- **Human (console or CLI):** `UserIdentityType == "IAMUser"` or `"Root"` or
  `"AssumedRole"` with a recognisable session name. Evaluate intent, geography, time-of-day.
- **AWS service principal:** `UserIdentityType == "AWSService"` or the `invokedBy` field names
  an AWS service (e.g. `elasticmapreduce.amazonaws.com`, `config.amazonaws.com`). Almost always
  benign automation — the service is calling its own APIs as part of normal operation.
- **Cross-account assumed role:** `UserIdentityType == "AssumedRole"` with an ARN from a
  different account. Legitimate in multi-account orgs; suspicious if the source account is
  unknown.

A high-volume alert triggered entirely by AWS service principals is not a brute-force attack —
it's infrastructure automation. Confirm the caller before counting rows.

## Query patterns

### Characterise an API burst
```kusto
AWSCloudTrail
| where TimeGenerated > ago(3d)
| where UserIdentityArn has "<arn_fragment>" or UserIdentityAccountId == "<account_id>"
| summarize Count=count(), First=min(TimeGenerated), Last=max(TimeGenerated)
    by EventName, EventSource, UserIdentityType,
       UserIdentityArn, SourceIpAddress, ErrorCode
| order by Count desc
```

### Isolate the caller identity
```kusto
AWSCloudTrail
| where TimeGenerated > ago(3d)
| where EventName == "<event_name>"
| summarize Count=count()
    by UserIdentityType, UserIdentityArn,
       UserIdentityPrincipalid, UserIdentityAccountId,
       SessionIssuerUserName, SourceIpAddress
| order by Count desc
```

### Check for errors (failed calls → reconnaissance indicator)
```kusto
AWSCloudTrail
| where TimeGenerated > ago(3d)
| where UserIdentityArn has "<arn_fragment>"
| where ErrorCode != ""
| summarize Count=count(), First=min(TimeGenerated), Last=max(TimeGenerated)
    by EventName, ErrorCode, ErrorMessage
| order by Count desc
```

### IAM changes by a principal
```kusto
AWSCloudTrail
| where TimeGenerated > ago(7d)
| where EventSource == "iam.amazonaws.com"
| where UserIdentityArn has "<arn_fragment>"
| project TimeGenerated, EventName, RequestParameters,
    ResponseElements, SourceIpAddress, ErrorCode
| order by TimeGenerated asc
```

### S3 bucket policy / ACL changes
```kusto
AWSCloudTrail
| where TimeGenerated > ago(7d)
| where EventSource == "s3.amazonaws.com"
| where EventName has_any ("PutBucketPolicy", "PutBucketAcl",
    "DeleteBucketPolicy", "PutBucketPublicAccessBlock")
| project TimeGenerated, EventName, UserIdentityArn,
    RequestParameters, SourceIpAddress, ErrorCode
| order by TimeGenerated asc
```

### Security group modifications
```kusto
AWSCloudTrail
| where TimeGenerated > ago(7d)
| where EventSource == "ec2.amazonaws.com"
| where EventName has_any ("AuthorizeSecurityGroupIngress",
    "AuthorizeSecurityGroupEgress", "RevokeSecurityGroupIngress",
    "CreateSecurityGroup", "DeleteSecurityGroup")
| project TimeGenerated, EventName, UserIdentityArn,
    RequestParameters, SourceIpAddress, ErrorCode
| order by TimeGenerated asc
```

### Root account usage
```kusto
AWSCloudTrail
| where TimeGenerated > ago(30d)
| where UserIdentityType == "Root"
| summarize Count=count(), First=min(TimeGenerated), Last=max(TimeGenerated)
    by EventName, EventSource, SourceIpAddress, ErrorCode
| order by Count desc
```

### Console login events
```kusto
AWSCloudTrail
| where TimeGenerated > ago(7d)
| where EventName == "ConsoleLogin"
| project TimeGenerated, UserIdentityArn, SourceIpAddress,
    ResponseElements, AdditionalEventData, ErrorMessage
| order by TimeGenerated desc
```

### GuardDuty finding detail
When Sentinel fires on a forwarded GuardDuty finding, the raw finding is in
`ServiceEventDetails` or `RequestParameters`. Extract it:
```kusto
AWSCloudTrail
| where TimeGenerated > ago(3d)
| where EventSource == "guardduty.amazonaws.com"
| where EventName has_any ("CreateSampleFindings", "GetFindings", "ArchiveFindings")
| project TimeGenerated, EventName, RequestParameters,
    ResponseElements, UserIdentityArn
| order by TimeGenerated desc
```

## Traps (AWS-specific)

| Trap | Symptom | Workaround |
|------|---------|------------|
| Service-principal volume | Alert fires on thousands of API calls that are all `invokedBy: config.amazonaws.com` | Check `UserIdentityType` and `invokedBy` first — service automation is not an attack |
| `RequestParameters` is a string | Looks like JSON but isn't parsed — `parse_json()` returns null | `todynamic(RequestParameters)` or `extract()` with regex |
| Multi-account AssumedRole | ARN belongs to a different account — looks foreign | Cross-account roles are normal in AWS Organizations; verify the source account is in the org |
| `ErrorCode` absent on success | Filtering `ErrorCode == ""` catches successes as well as calls with no error field | Use `isempty(ErrorCode)` or `ErrorCode == ""` intentionally; don't confuse with success |
| Time zone in ConsoleLogin | `AdditionalEventData` contains a `MobileVersion`/`MFAUsed` field, not a timezone | Timestamps are UTC; correlate with the user's expected working hours |

## Reusable classification logic (AWS API-activity type)

**Lean benign positive when:** the caller is an AWS service principal (`invokedBy` names an AWS
service); the API calls are read-only (`Describe*`, `List*`, `Get*`); the principal is a known
automation role (CI/CD, Config, CloudFormation); the source IP is an AWS internal IP
(`amazonaws.com` range); all calls succeeded (no reconnaissance-style errors).

**Escalate when:** the caller is a human (`IAMUser` / `Root` / `AssumedRole` with a human
session name) making write calls (`Create*`, `Put*`, `Delete*`, `Attach*`, `Detach*`) outside
business hours or from an unusual IP; IAM policy changes grant broad permissions
(`AdministratorAccess`, `*`); S3 bucket policies are loosened to public; security groups open
`0.0.0.0/0` ingress on sensitive ports; root account is used for anything other than billing
or account-level settings; `ErrorCode` shows `AccessDenied` patterns suggesting credential
testing.

> CloudTrail alerts measure API breadth and novelty. A high count of calls by an AWS service is
> infrastructure, not intrusion. The triage question is: was a human behind this, and if so, was
> it authorised?
