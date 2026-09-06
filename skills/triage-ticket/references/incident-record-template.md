# Incident Investigation & Response Record (IIRR) — page template

The house format for documenting a triaged Sentinel case in Confluence (space: Andrei Momanu,
`~6059e7fc6bb16c00691e31ca`). Title convention:

> **Incident Investigation & Response Record: `<Alert Title>`**

Build with the Confluence MCP (`createConfluencePage` / `updateConfluencePage`, `contentFormat: markdown`).
**Publishing/updating a Confluence page is outward-facing — confirm with Andrei before writing it.**

---

## What an IIRR page is

**One page per detection type — a playbook, plus a ledger of the tickets that hit it.**

The page is not a case log. It is the reusable method for this alert type, written generally, with a
one-row-per-ticket table recording every case that has fired it. Full per-case detail — timelines,
comment IDs, entity lists, the exact values in one burst — **lives in the Jira ticket.** If someone
needs that, they open the ticket; the ledger row gives them the key.

This matters because the failure mode is predictable: a page grows a `# Case one`, then a
`# Case two`, then a `# Case three`, each with its own case-summary table, investigation record and
response actions. Three narratives repeating the same four queries with a different UPN swapped in.
The playbook is then buried inside the case that happened to be documented first, and a reader has
to diff three stories to work out what actually generalises.

**So: no per-case narrative sections.** The playbook steps are written generally, and each one cites
a real observed result inline as evidence that the step works — `**Found (AUT-3531):** …`. Concrete
per-ticket values live in `# Reference data`. Nothing is fully detailed on the page; everything is
attributed, so any of it can be traced back to a ticket.

---

## When a new case earns an edit — the ledger/body rule

Every triaged case updates the page. Almost none of them should touch the body.

### Always — the ledger (this is the whole update for a routine repeat)

1. **One row in `# Cases seen`.** Ticket key, Sentinel incident, date, client, subject, outcome,
   and the deciding evidence in a dozen words or fewer.
2. **Any new concrete values → `# Reference data`,** tagged with the ticket key.
3. **Bump the case count** in the opening framing sentence.

If the case taught nothing that generalises, stop here. A fourth benign-positive that split exactly
the way the page already says benign-positives split is a ledger row and nothing else.

### Only when something special happened — the body

Something special means **the page would have been wrong, incomplete, or misleading for this case.**
Add it to the *general* section it belongs in — never as a new case section:

| What happened | Where it goes |
|---|---|
| An outcome this detection hasn't produced before, that the fork logic doesn't cover | `# Reusable classification logic` + the opening fork blockquote |
| A new discriminator — a signal that separated this case from a prior one | `# Reusable classification logic`, and the step that surfaces it |
| A new query, a table the page doesn't use, or an existing query used for a new purpose | `# Investigation playbook` **and** the family's `kql-<family>.md` |
| A console/KQL gotcha not already listed | `# Traps hit` |
| The verdict diverged from how this page says the family is ruled | One line in `# Reusable classification logic` naming both tickets and why |
| The page's stated meaning, fork, or recommendation didn't hold up | Correct it in place |
| A new tuning, response, or containment conclusion | `# Response actions` (+ `# Open items` if unactioned) |
| A residual question this case leaves open | `# Open items`, tagged with the ticket |

### Never

- **A second case narrative.** No `# Case two` / `# Case three` sections, and no per-case
  `## Case summary`, `## Investigation record` or `## Response actions`.
- **A duplicate query with the identifier swapped.** If the query already exists, the case does not
  add a query — it confirms the existing one. Parameterize; don't copy.
- **A restatement of an outcome the page already covers.**
- **Deleting a query, trap, reference row or classification criterion** because this case didn't need
  it. The page only gains generality; it never loses coverage. Superseded content gets corrected or
  annotated, not dropped.

> The test: *would the next analyst do anything differently because of this?* If yes, it belongs in
> the body, phrased generally. If no, it is a ledger row.

---

## Writing the KQL

Queries live in `# Investigation playbook`, **one per purpose, parameterized** — not one per case.

- **Placeholders, not case values:** `<UPN>`, `<DISPLAY_NAME_TOKEN>`, `<SOURCE_IP>`, `<HOST>`,
  `<MESSAGE_ID>`, `<ACTOR_UPN>`, `<ACCOUNT_ID>`. A reader substitutes and runs.
- **Relative windows** — `ago(3d)` / `ago(7d)` / `ago(30d)` — with a note on when to narrow to an
  absolute window and why. Never leave a hard-coded `datetime(2026-…)` from one case as the default.
- **Keep every distinct query.** Two queries that differ only in the identifier are one query. Two
  that answer different questions — "all rows by table/IP" versus "successes only, absolute window
  pinned to the burst" — are two, and both stay.
- **Name the variant's purpose** when one query has genuine variants, so it's clear which to reach
  for.
- Each step records what a real run returned, attributed: `**Found (TOS-36635):** 79 rows, every one
  from one IP.` That is what makes a general step trustworthy without a case narrative around it.

---

## Section order

Keep this order and these headings so pages stay comparable and diffable.

### Opening block (before the first heading)

1. **Framing:** *"This page is the triage playbook for `<alert type>` (`<detecting product>`). It
   covers `<N>` cases to date — see Cases seen."*
2. **How cases have split:** the outcomes this detection has produced, one clause each. Not a
   per-case summary — the shape of the fork.
3. **Read this first:** the single insight that reframes the alert — the fact that, once known,
   changes how everything else reads.
4. **A blockquote stating the fork** the page exists to get right: which evidence sends the case to
   which outcome.

### `# Cases seen`

The ledger. One row per ticket, newest first.

| Ticket | Sentinel | Date | Client | Subject | Outcome | Deciding evidence |
|---|---|---|---|---|---|---|
| `AUT-1234` | 13778 | 2026-07-27 | AUT | `user@brand.com` | True Positive, unsuccessful | 241 foreign IPs, `50053`, no attacker success |

Close it with:

> Per-case detail — full timelines, entity lists, comment IDs — is in the Jira ticket. This page
> keeps only what generalises.

### `# What this detection means`

What the rule targets (the real threat) **and** its design weakness — the gap between what it
measures and what it asserts. One blockquote capturing what the rule can and cannot tell you.

### `# Why this alert is easy to misjudge`  /  `# The two questions that decide this alert`

The specific traps that produce wrong verdicts on this alert type — treating every failure as a
credential failure, concluding "zero successes" from `SigninLogs` alone, PIM-versus-permanent,
reading the API verb before the caller.

### `# Investigation playbook`

The generalized sequence, numbered, reusable as-is. Each step:

- **Tool:** the console / table / MCP used
- **Reviewed:** what to inspect
- **Query:** the parameterized KQL, inline
- **Found (`<TICKET>`):** what a real run returned — attributed, one or two lines
- **Why:** what the step establishes, and what result would flip the verdict

Always include the *set aside any pre-existing verdict* step and the *disconfirming test* step, and
put the disconfirming test early — if an attacker succeeded, that needs to surface now, not after
four more queries.

### Reference tables (as relevant)

`# Reading the result code` (Entra codes — see `kql-identity.md`), `# Reading the caller` (CloudTrail
identity), operation-name tables, and any other alert-type-specific lookup.

### `# Reusable classification logic`

The portable decision criteria: **Lean false positive when…**, **Lean benign positive when…**,
**Escalate when…**, plus any further split (e.g. True Positive *unsuccessful* versus *compromise*).
Cite ticket keys against criteria that a specific case established.

### `# Response actions`

- **Recommended handling for future cases** — numbered, the playbook distilled to actions.
- **Tuning / allow-list recommendations** — where the cause is rule overbreadth.

Per-case actions taken (comment IDs, transitions) belong in the ticket, not here.

### `# Reusable triage checklist`

The whole method as `- [ ]` items, in order, so the next analyst can run it as a list.

### `# Reference data`

The concrete values, grouped by ticket, with a **Ticket** column so any row is traceable. Accounts,
IPs and prefixes, result codes, target apps, device fingerprints, burst windows, hashes, message IDs,
related incidents. Compact rows — this is an IOC index, not a narrative.

### `# Traps hit`

Table: **Trap | Symptom | Workaround**. Cross-cutting traps live in the matching `kql-<family>.md`;
this table is the standing list for the ones that bite on *this* detection.

### `# Open items`

What's unfinished, tagged with the ticket it belongs to: rule tuning not raised, application owner
not engaged, customer confirmation outstanding, messages pending removal, discrepancies to reconcile.
Strike items when they close.

### `# Tooling reference`

Table: **Data source | How to access it**. Ticket (Jira MCP), Sentinel incident / KQL tables
(terminal `az rest` → Log Analytics API), TOS identity data (MS Graph Enterprise MCP).

### Closing prose paragraph

One dense paragraph restating the method for this alert type end-to-end — the version a colleague
could read alone and reproduce the investigation. Written generally; ticket keys only where a
specific case anchors a claim.

---

**Minimum viable page** — a routine, low-complexity detection (an informational notification, a
broad-indicator match) does not need every section. Keep: Opening block → `# Cases seen` →
`# What this detection means` → `# How these are closed` (numbered) → `# Reusable classification
logic` → `# Response actions` (tuning/suppression) → `# Reusable triage checklist`. Scale up to the
full structure as the family accumulates cases, and the moment a case produces a *different* outcome
from the ones already recorded — that fork is exactly what the full structure exists to hold.
