# Claude SOC Triage

An end-to-end SOC alert triage system built on [Claude Code](https://claude.com/claude-code). It pulls a Sentinel alert from Jira, investigates it via KQL and Microsoft Graph, reaches an evidence-backed disposition, and writes the decision record back to Jira + Confluence — all from the terminal.

## What's here

```
skills/triage-ticket/
  SKILL.md                  # The triage skill — Claude Code reads this to run a triage
  references/
    kql-identity.md         # KQL cookbook: Entra sign-in / brute-force / spray / PIM
    kql-email.md            # KQL cookbook: MDO post-delivery / ZAP email detections
    kql-aws.md              # KQL cookbook: AWS CloudTrail API-activity detections
    kql-endpoint.md         # KQL cookbook: Endpoint LOLBin / image-load / Defender exclusion
    kql-cloudapps.md        # KQL cookbook: MDCA OAuth-app / activity anomaly
    incident-record-template.md  # Confluence IIRR page structure

scripts/
  Get-SentinelIncident.ps1  # PowerShell bridge — read a Sentinel incident via az REST
  Setup-ClaudeMcpApp.ps1    # Provision the MS Graph MCP app registration in Entra

examples/
  settings.json.example     # Claude Code user settings reference
  memory-index-example.md   # Example MEMORY.md index for the auto-memory system
```

## How it works

1. **You say** `triage ZETA-4321` (or invoke `/triage-ticket`).
2. **Claude pulls the ticket** from Jira via the Atlassian MCP.
3. **Checks Confluence** for a prior decision record on this alert type.
4. **Confirms the terminal** is logged into the correct Azure tenant.
5. **Runs KQL** via `az rest` against the Log Analytics workspace — sign-in logs, Defender tables, CloudTrail, whatever the detection needs.
6. **For identity lookups on Client A**, uses the MS Graph Enterprise MCP (read-only Entra connector).
7. **Reaches a disposition** — True Positive, False Positive, Benign Positive, or Awaiting Confirmation.
8. **Writes the Jira comment** (verdict + evidence), transitions the ticket, and creates/updates the Confluence IIRR page.

## Prerequisites

- **Claude Code** (desktop app or CLI)
- **Atlassian (Jira/Confluence) MCP** — connected in Claude Code
- **Microsoft MCP Server for Enterprise** — for identity lookups (optional, single-tenant)
- **Azure CLI** (`az`) — authenticated to each tenant you triage

## Setup

### 1. Install the triage skill

Copy `skills/triage-ticket/` (with its `references/` folder) into your Claude Code skills directory:

```bash
# User-level skill (available in all projects)
cp -r skills/triage-ticket ~/.claude/skills/triage-ticket
```

### 2. Configure your environments

Edit `skills/triage-ticket/SKILL.md` and replace the placeholder values in the **Environment** table (section 0):

| Placeholder | What to fill in |
|---|---|
| `<JIRA_SITE>` | Your Jira Cloud site (e.g. `yourorg.atlassian.net`) |
| `<CLTA_TENANT_ID>`, `<CLTB_TENANT_ID>` | Azure AD tenant IDs |
| `<CLTA_SUBSCRIPTION_ID>`, `<CLTB_SUBSCRIPTION_ID>` | Azure subscription IDs |
| `<CLTA_WORKSPACE_ID>`, `<CLTB_WORKSPACE_ID>` | Log Analytics workspace customer IDs |
| `<CONFLUENCE_SPACE_ID>` | Your Confluence personal space ID |
| `<ANALYST_NAME>` | Your name |

### 3. Authenticate Azure CLI

```bash
# Log into each tenant
az login --tenant <TENANT_ID>
az account set --subscription <SUBSCRIPTION_ID>
```

### 4. (Optional) Provision the Graph MCP app

Run `scripts/Setup-ClaudeMcpApp.ps1` in PowerShell as an Entra admin to register the read-only MCP client app.

## Sanitization

This repo has been sanitized — all tenant IDs, subscription IDs, workspace IDs, UPNs, organization names, and personal identifiers have been replaced with placeholders. Search for `<` to find all values you need to fill in for your own environment.

## License

This is a personal workflow published for reference. Use and adapt freely.
