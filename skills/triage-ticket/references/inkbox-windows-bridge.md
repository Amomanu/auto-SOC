# Inkbox real-time bridge on Windows — run the daemon in WSL (THE working method)

**This supersedes any earlier "Windows can't run the daemon, just poll" note — that was wrong.**
The real-time push bridge DOES work on this laptop: run the gateway daemon inside **WSL2 Ubuntu**
(a local POSIX/Linux environment — the same kind of environment as the CCR container where it first
worked), and have a `Monitor` tail its `events.jsonl`. Verified end-to-end 2026-09-08: a real iMessage
reply woke the session in ~1s with zero polling. Plain MCP polling is a last-resort fallback, not this.

## ⚠️ TAIL GOTCHA — TWO bugs, either makes it "look broken" (read first)
The Monitor command MUST be exactly (do not simplify):
```
MSYS_NO_PATHCONV=1 wsl.exe -u root bash -lc "stdbuf -oL tail -n 0 -F /root/.inkbox-claude/events.jsonl"
```
In both failure modes the tunnel still writes the reply into `events.jsonl` (you can `cat` it and see
it) but the Monitor **never fires** — it looks like the bridge is dead when it's fine, only the tail is
mis-plumbed. Do not spin debugging the tail; it's always one of these two:
1. **Path translation — `MSYS_NO_PATHCONV=1` MANDATORY.** The Monitor runs through Git Bash; MSYS
   rewrites a `/root/.inkbox-claude/events.jsonl` argument to
   `C:/Program Files/Git/root/.inkbox-claude/events.jsonl` before `wsl` sees it, so `tail` watches a
   nonexistent path. `MSYS_NO_PATHCONV=1` stops the rewrite. (Reproduced 2026-09-09; equivalent form
   `MSYS_NO_PATHCONV=1 wsl -u root -- stdbuf -oL tail -n 0 -F /root/...` also works.)
2. **Buffering — `stdbuf -oL`, NO `| tr` / `| grep` / any pipe stage.** A non-line-buffered pipe
   block-buffers so lines never flush to the Monitor.
Confirm the running tail: `wsl.exe -u root bash -lc "ps -eo args | grep '[t]ail -n 0 -F'"` must show
the bare `/root/...` path (NOT `C:/Program Files/Git/...`) with nothing piped after it. Self-test:
`wsl.exe -u root bash -lc 'echo "{\"kind\":\"selftest\"}" >> /root/.inkbox-claude/events.jsonl'` → fires in ~1s.

## Why Windows-native fails but WSL works
- Windows-native `inkbox-claude start`/`run` die: `inkbox.tunnels.connect requires a POSIX platform`.
- **WSL2 is POSIX/Linux** — the tunnel connects there. Run everything in WSL **as root** (`wsl -u root`):
  no sudo password, and paths match the documented `/root/.inkbox-claude/...`.
- The daemon runs *inside* WSL; this Windows session reaches its event file by running
  `wsl.exe -u root ... tail -F` as the Monitor command.

## One-time build (idempotent) — `references/wsl-inkbox-setup.sh`
```bash
# 1. prereqs (root, no password needed)
wsl.exe -u root bash -lc 'apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3.12-venv python3-pip'
# 2. build: stage patched source from the Windows repo, venv, install, write /root env, doctor
wsl.exe -u root bash -c "tr -d '\r' < /mnt/c/Users/andre/.claude/skills/triage-ticket/references/wsl-inkbox-setup.sh > /tmp/s.sh && bash /tmp/s.sh"
```
The script copies the **already-patched** source from `/mnt/c/Users/andre/inkbox-ai/claude-code-plugin`
(patch marker `_external_handler_active` present ×4), makes a Linux venv, `pip install -e .`, and writes
`/root/.inkbox-claude/.env` with the existing identity `agent-notification`, the API key, the signing key,
and `INKBOX_EXTERNAL_HANDLER_LOG=/root/.inkbox-claude/events.jsonl`. doctor is all ✓ except
`claude CLI not on PATH` — **that ✗ is expected and harmless**: the patch disables the gateway's own
Claude sessions whenever the external-handler log is set; we consume events via the Monitor instead.

## Start the daemon (every session that needs the bridge)
```bash
wsl.exe -u root bash -lc 'cd /root/inkbox-ai/claude-code-plugin && PYTHONUTF8=1 PYTHONIOENCODING=utf-8 .venv/bin/inkbox-claude start'
```
Confirm the tunnel connected (this is the line that never appears on Windows-native):
```bash
wsl.exe -u root bash -lc 'grep "\[bridge\] ready" /root/.inkbox-claude/gateway.log'
# also: "tunnel runtime: initial connection established" + "[bridge] tunnel ready: https://agent-notification.inkboxwire.com -> 127.0.0.1:8767"
```
`start` daemonizes (POSIX fork works in WSL); WSL2 keeps the VM alive while the daemon runs.

## Arm the Monitor — the ONE gotcha that bit us
```
Monitor({
  command: "MSYS_NO_PATHCONV=1 wsl.exe -u root bash -lc \"stdbuf -oL tail -n 0 -F /root/.inkbox-claude/events.jsonl\"",
  description: "inkbox inbound events (WSL tunnel) — instant push",
  persistent: true, timeout_ms: 3600000
})
```
- **MUST be `stdbuf -oL` and MUST NOT pipe through `| tr` (or any non-flushing filter).** The first
  attempt used `... tail -F' | tr -d '\0'` and the wake **never fired** even though events reached
  `events.jsonl` — `tr` block-buffered the stream. `tr`/`grep`/`awk` on the Windows side of the pipe
  buffer; `stdbuf -oL` on `tail` and no downstream filter = lines stream immediately.
- `wsl.exe` passes `tail`'s stdout through as UTF-8 — no null-stripping is needed, so don't add `tr`.
- Self-test the wake path without bothering the user:
  `wsl.exe -u root bash -lc 'echo "{\"kind\":\"selftest\"}" >> /root/.inkbox-claude/events.jsonl'`
  — the Monitor should fire within ~1s.

## Event shape & replying
Each inbound is one JSON line: `{"kind":"imessage","sender":"<ANALYST_PHONE>","body":"...","meta":{"conversation_id":"<CONVERSATION_ID>", ...}}`.
Reply with `inkbox_imessage_send` (recipient `<ANALYST_PHONE>`, `conversation_id` from `meta`, `text`).

## Gotchas
- Monitor times out ~30–60 min even at `timeout_ms:3600000` — re-arm on the timeout notice.
- Monitor + daemon are session/VM-scoped: if the session ends, re-run "Start the daemon" + re-arm.
- Teardown: `wsl.exe -u root bash -lc '/root/inkbox-ai/claude-code-plugin/.venv/bin/inkbox-claude stop'`.
- Do NOT arm a Monitor on the **Windows** `C:\Users\andre\.inkbox-claude\events.jsonl` — nothing writes
  it (the Windows daemon can't run). The live event file is the **WSL** `/root/.inkbox-claude/events.jsonl`.

## Fallback only (bridge genuinely unavailable)
If WSL is broken, degrade to MCP poll: `inkbox_conversation_get` (channel imessage, conversation_id
`<CONVERSATION_ID>`); newest `direction:inbound` after your send. This is NOT push and makes <ANALYST_NAME> prompt you —
use only if the WSL bridge cannot be brought up.
