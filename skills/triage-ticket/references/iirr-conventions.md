# Incident Investigation & Response Record (IIRR) — file conventions

The house format for documenting a triaged Sentinel case as a markdown
file in the `<IIRR_REPO>` repo. One file per detection type, at:

> `iirr/<family>/<slug>.md`

where `<family>` is `identity | email | endpoint | aws | cloudapps` and
`<slug>` is derived from the alert title per the slug rule in
`iirr/README.md`. Frontmatter `alert_title` holds the exact Sentinel
`AlertName` (case-preserved, unslugged).

Build a new record by copying `iirr/_template.md` into place and filling
it in. Update an existing one with `Edit` (frontmatter appends, small
body tweaks) or `Write` (larger body edits). Commit and push in the
run's teardown — the git repo is the authoritative store; a change that
isn't pushed hasn't happened for the next analyst.

---

## What an IIRR file is

**One markdown file per detection type — a playbook, plus a ledger of the
tickets that hit it.**

The file is not a case log. It is the reusable method for this alert
type, written generally, with a one-row-per-ticket entry in the
frontmatter `cases` array recording every case that has fired it. Full
per-case detail — timelines, comment IDs, entity lists, the exact values
in one burst — **lives in the Jira ticket.** If someone needs that, they
open the ticket; the ledger row gives them the key.

This matters because the failure mode is predictable: a file grows a
`# Case one`, then a `# Case two`, then a `# Case three`, each with its
own case-summary table, investigation record and response actions. Three
narratives repeating the same four queries with a different UPN swapped
in. The playbook is then buried inside the case that happened to be
documented first, and a reader has to diff three stories to work out
what actually generalises.

**So: no per-case narrative sections.** The playbook steps are written
generally, and each one cites a real observed result inline as evidence
that the step works — `**Found (CLTB-3531):** …`. Concrete per-ticket
values live in `# Reference data`. Nothing is fully detailed in the
body; everything is attributed, so any of it can be traced back to a
ticket.

---

## When a new case earns an edit — the ledger/body rule

Every triaged case updates the frontmatter. Almost none of them should
touch the body.

### Always — the frontmatter update (this is the whole update for a routine repeat)

1. **Append one entry to `cases`.** Ticket key, Sentinel incident number,
   date, client, subject, outcome, and the deciding evidence in ≤ 12
   words. Order is **oldest-first** — append to the end, never insert at
   the top.
2. **Update `last_seen`** to this case's date and **increment
   `case_count`**. `first_seen` never changes after the first case.
3. **Any new concrete values → `# Reference data`,** tagged with the
   ticket key.

If the case taught nothing that generalises, stop here. A fourth
benign-positive that split exactly the way the record already says
benign-positives split is a ledger entry and nothing else.

### Only when something special happened — the body

Something special means **the file would have been wrong, incomplete, or
misleading for this case.** Add it to the *general* section it belongs
in — never as a new case section:

| What happened | Where it goes |
|---|---|
| An outcome this detection hasn't produced before, that the fork logic doesn't cover | `# Reusable classification logic` **and** frontmatter `classification_fork` (keep them consistent) |
| A new discriminator — a signal that separated this case from a prior one | `# Reusable classification logic`, and the step that surfaces it |
| A new query, a table the file doesn't use, or an existing query used for a new purpose | `# Investigation playbook` **and** the family's `kql-<family>.md` |
| A console/KQL gotcha not already listed | `# Traps hit` |
| The verdict diverged from how this file says the family is ruled | One line in `# Reusable classification logic` naming both tickets and why |
| The file's stated meaning, fork, or recommendation didn't hold up | Correct it in place (both `classification_fork` and body if the fork changed) |
| A new tuning, response, or containment conclusion | `# Response actions` (+ `# Open items` if unactioned) |
| A residual question this case leaves open | `# Open items`, tagged with the ticket |

### Never

- **A second case narrative.** No `# Case two` / `# Case three` sections,
  and no per-case `## Case summary`, `## Investigation record` or
  `## Response actions`.
- **A duplicate query with the identifier swapped.** If the query already
  exists, the case does not add a query — it confirms the existing one.
  Parameterize; don't copy.
- **A restatement of an outcome the file already covers.**
- **Deleting a query, trap, reference row or classification criterion**
  because this case didn't need it. The file only gains generality; it
  never loses coverage. Superseded content gets corrected or annotated,
  not dropped.
- **Duplicating the ledger in the body.** The frontmatter `cases` array
  *is* the ledger. No `# Cases seen` section in the body — anyone
  reading the raw file sees the frontmatter, and any renderer can
  present it as a table if wanted.

> The test: *would the next analyst do anything differently because of
> this?* If yes, it belongs in the body, phrased generally. If no, it
> is a frontmatter update.

---

## Writing the KQL

Queries live in `# Investigation playbook`, **one per purpose,
parameterized** — not one per case.

- **Placeholders, not case values:** `<UPN>`, `<DISPLAY_NAME_TOKEN>`,
  `<SOURCE_IP>`, `<HOST>`, `<MESSAGE_ID>`, `<ACTOR_UPN>`, `<ACCOUNT_ID>`.
  A reader substitutes and runs.
- **Relative windows** — `ago(3d)` / `ago(7d)` / `ago(30d)` — with a note
  on when to narrow to an absolute window and why. Never leave a
  hard-coded `datetime(2026-…)` from one case as the default.
- **Keep every distinct query.** Two queries that differ only in the
  identifier are one query. Two that answer different questions — "all
  rows by table/IP" versus "successes only, absolute window pinned to
  the burst" — are two, and both stay.
- **Name the variant's purpose** when one query has genuine variants, so
  it's clear which to reach for.
- **KQL goes in ```` ```kusto ```` fences** — no escaping needed. A
  reader copy-pastes into a terminal / the wrapper scripts / the KQL
  console and it runs as-is.
- Each step records what a real run returned, attributed:
  `**Found (CLTA-36635):** 79 rows, every one from one IP.` That is what
  makes a general step trustworthy without a case narrative around it.

---

## Section order

Keep this order and these headings so files stay comparable and
diffable.

### Frontmatter (before the body)

The YAML frontmatter carries every structured value the skill reads or
updates: metadata (`alert_title`, `family`, `detecting_product`,
`first_seen`, `last_seen`, `case_count`), the fork summary
(`classification_fork` — 3–5 lines), and the ledger (`cases`). Full
schema in `iirr/README.md`.

The framing that used to sit at the top of a page — *"This page is the
triage playbook for `<alert type>` … covers `<N>` cases to date"* — is
derived from the frontmatter, so it does not need a body element. The
fork blockquote also lives in the frontmatter (`classification_fork`);
the body counterpart is `# Reusable classification logic` (detailed
criteria + attribution).

### `# Read this first`

The single insight that reframes the alert — the fact that, once known,
changes how everything else reads. One or two sentences. This is the
first heading in the body.

### `# What this detection means`

What the rule targets (the real threat) **and** its design weakness —
the gap between what it measures and what it asserts. One blockquote
capturing what the rule can and cannot tell you.

### `# Why this alert is easy to misjudge`  /  `# The two questions that decide this alert`

The specific traps that produce wrong verdicts on this alert type —
treating every failure as a credential failure, concluding "zero
successes" from `SigninLogs` alone, PIM-versus-permanent, reading the
API verb before the caller.

### `# Investigation playbook`

The generalized sequence, numbered, reusable as-is. Each step:

- **Tool:** the console / table / MCP used
- **Reviewed:** what to inspect
- **Query:** the parameterized KQL in a ```` ```kusto ```` fence, inline
- **Found (`<TICKET>`):** what a real run returned — attributed, one or two lines
- **Why:** what the step establishes, and what result would flip the verdict

Always include the *set aside any pre-existing verdict* step and the
*disconfirming test* step, and put the disconfirming test early — if an
attacker succeeded, that needs to surface now, not after four more
queries.

### Reference tables (as relevant)

`# Reading the result code` (Entra codes — see `kql-identity.md`),
`# Reading the caller` (CloudTrail identity), operation-name tables, and
any other alert-type-specific lookup.

### `# Reusable classification logic`

The portable decision criteria: **Lean false positive when…**, **Lean
benign positive when…**, **Escalate when…**, plus any further split
(e.g. True Positive *unsuccessful* versus *compromise*). Cite ticket
keys against criteria that a specific case established. Keep these
criteria consistent with the frontmatter `classification_fork` summary
— when one changes, update the other.

### `# Response actions`

- **Recommended handling for future cases** — numbered, the playbook
  distilled to actions.
- **Tuning / allow-list recommendations** — where the cause is rule
  overbreadth.

Per-case actions taken (comment IDs, transitions) belong in the ticket,
not here.

### `# Reusable triage checklist`

The whole method as `- [ ]` items, in order, so the next analyst can run
it as a list.

### `# Reference data`

The concrete values, grouped by ticket, with a **Ticket** column so any
row is traceable. Accounts, IPs and prefixes, result codes, target
apps, device fingerprints, burst windows, hashes, message IDs, related
incidents. Compact rows — this is an IOC index, not a narrative.

### `# Traps hit`

Table: **Trap | Symptom | Workaround**. Cross-cutting traps live in the
matching `kql-<family>.md`; this table is the standing list for the
ones that bite on *this* detection.

### `# Open items`

What's unfinished, tagged with the ticket it belongs to: rule tuning not
raised, application owner not engaged, customer confirmation
outstanding, messages pending removal, discrepancies to reconcile.
Strike items when they close.

### `# Tooling reference`

Table: **Data source | How to access it**. Jira ticket (Jira MCP),
Sentinel incident (CLTA: `scripts/incident-api.ps1`; CLTB: admin `az rest`),
KQL / all Sentinel & Defender tables (CLTA: `scripts/kql.ps1`; CLTB: admin
`az rest` → Log Analytics API), CLTA identity data (MS Graph Enterprise
MCP), notifications (Inkbox `inkbox_imessage_send` → `<ANALYST_PHONE>`).

### `# Method summary`

One dense paragraph restating the method for this alert type end-to-end
— the version a colleague could read alone and reproduce the
investigation. Written generally; ticket keys only where a specific
case anchors a claim.

---

**Minimum viable file** — a routine, low-complexity detection (an
informational notification, a broad-indicator match) does not need
every section. Keep: frontmatter (always) → `# Read this first` → `#
What this detection means` → `# Reusable classification logic` → `#
Response actions` (tuning/suppression) → `# Reusable triage checklist`.
Scale up to the full structure as the family accumulates cases, and the
moment a case produces a *different* outcome from the ones already
recorded — that fork is exactly what the full structure exists to hold.
