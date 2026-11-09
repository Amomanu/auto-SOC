# Incident Investigation & Response Record (IIRR) — conventions

One JSON record per **detection type** in the git repo `C:\Claude\<IIRR_REPO>`
(private GitHub `<IIRR_REPO>`), at `iirr/<family>/<slug>.json`.
`<family>` is `identity | email | endpoint | aws | cloudapps | network`; `<slug>` is the
alert title lowercased with non-alphanumerics collapsed to `-`.

Records are written for a model to read. **Never read or edit the JSON raw** —
every section is one long line. Everything goes through `iirr.py` in the repo root:

```
python iirr.py find "<alert title>"               # which record, if any
python iirr.py show <file>                        # ledger + intro + core sections
python iirr.py show <file> --with reference_data  # add a skipped section
python iirr.py show <file> --only <key>           # one section, e.g. before editing it
python iirr.py new <family> "<alert title>"       # new empty record, prints its path
python iirr.py add-case <file> '<json>'           # append a ledger row
python iirr.py set-case <file> <ticket> '<json>'  # change an existing row
python iirr.py set <file> <key> <textfile>        # replace/create a section, intro or cases_notes
```

`git pull --rebase --autostash` before reading. After any write:
`git add -A && git commit -m "<TICKET>: <what changed>" && git push`. Never force-push.

---

## What a record is

**A playbook for one alert type, plus a ledger of the tickets that taught it something.**

It is not a case log. Full per-case detail — timelines, comment IDs, entity
lists, the exact values in one burst — lives in the Jira ticket. There are no
per-case narrative sections: playbook steps are written generally, and each
cites a real observed result inline as evidence that the step works —
`Found (CLTB-3531): …`. Concrete per-ticket values live in `reference_data`.

## When a case earns an edit

**Routine repeat** — same outcome, same evidence pattern, nothing new: **do not
touch the record.** No ledger row, no commit. The Jira comment is the record.

**Something new** — the record would have been wrong, incomplete or misleading
for this case. Add a ledger row (`add-case`) and put the new knowledge in the
*general* section it belongs in:

| What happened | Where it goes |
|---|---|
| An outcome the fork doesn't cover | `classification` (and `intro`/`decides` if the fork summary changes) |
| A new discriminator that separated this case from a prior one | `classification`, and the `playbook` step that surfaces it |
| A new query, a table the record doesn't use, an existing query used for a new purpose | `playbook` **and** the family's `kql-<family>.md` |
| A console/KQL gotcha not already listed | `traps` |
| The verdict diverged from how the record says the family is ruled | one line in `classification` naming both tickets and why |
| A stated meaning, fork or recommendation didn't hold up | correct it in place |
| A new tuning, response or containment conclusion | `response` (+ `open_items` if unactioned) |
| A residual question the case leaves open | `open_items`, tagged with the ticket |
| New concrete values worth keeping (IPs, accounts, hashes) | `reference_data`, tagged with the ticket |

**Never:** a per-case section or key; a duplicate query with only the identifier
swapped; deleting a query, trap, reference row or criterion because this case
didn't need it. `set` replaces the whole section, so start from
`show --only <key>` output, never from memory.

> The test: *would the next analyst do anything differently because of this?*
> If yes, it goes in a section, phrased generally. If no, leave the record alone.

## Ledger rows (`cases`)

`{"ticket":"CLTB-1234","sentinel_incident":13778,"date":"2026-07-27","client":"CLTB","subject":"user@brand.com","outcome":"Benign Positive","deciding_evidence":"…"}`

- `date` is `YYYY-MM-DD`. `sentinel_incident` is the incident number.
- `outcome` in words: `False Positive`, `Benign Positive`, `True Positive, unsuccessful`,
  `True Positive, compromise`, `Awaiting customer confirmation`.
- `deciding_evidence`: what separated this case from its neighbour on the fork, one sentence.
- When an awaiting case resolves, `set-case` the existing row; do not append a second.
- `first_seen`, `last_seen`, `case_count` and `index.json` are recomputed by the script.

## Sections

Text is plain markdown without presentation markup: no bold, no table separator
rows, no backslash escapes, no links to Jira. Keep backticks, `|` table rows and
```` ```kusto ```` fences.

| Key | Holds | Shown by default |
|---|---|---|
| `intro` | two or three lines: detecting product, what the rule fires on, the fork | yes |
| `read_first` | the single insight that reframes the alert | yes |
| `decides` | the question(s) the verdict turns on | yes |
| `meaning` | what the rule targets, and what it can and cannot tell you | yes |
| `misjudge` | the traps that produce wrong verdicts on this alert type | yes |
| `playbook` | numbered steps — tool, query, `Found (<TICKET>): …`, why | yes |
| `classification` | lean FP when / lean BP when / escalate when / awaiting confirmation when | yes |
| `response` | handling for future cases, close steps, tuning | yes |
| `traps` | table: trap, symptom, workaround | yes |
| `open_items` | unfinished work, tagged with the ticket | yes |
| `reference_data` | per-ticket IOC index: accounts, IPs, hashes, windows | no — `--with reference_data` |
| `checklist`, `tooling`, `summary` | legacy; do not add to new records | no |

A detection-specific lookup table (e.g. `reading_the_result_code`) may have its own
key. A routine, low-complexity detection needs only `intro`, `decides`,
`classification`, `response`.

## Writing the KQL

- One query per purpose, **parameterized**: `<UPN>`, `<DISPLAY_NAME_TOKEN>`,
  `<SOURCE_IP>`, `<HOST>`, `<MESSAGE_ID>`, `<ACTOR_UPN>`, `<ACCOUNT_ID>`.
- Relative windows (`ago(3d)` / `ago(7d)` / `ago(30d)`) with a note on when to
  pin an absolute window. Never leave one case's `datetime(2026-…)` as the default.
- Two queries that differ only in the identifier are one query. Two that answer
  different questions are two, and both stay.
- Always include the *set aside any pre-existing verdict* step and the
  *disconfirming test*, and put the disconfirming test early.
- Each step records what a real run returned, attributed:
  `Found (CLTA-36635): 79 rows, every one from one IP.`
