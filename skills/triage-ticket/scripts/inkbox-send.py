#!/usr/bin/env python3
"""Send an iMessage to <ANALYST_NAME> through the Inkbox SDK inside WSL — no MCP connector needed.

Runs in the WSL gateway venv (see references/inkbox-windows-bridge.md). Reads the API key and
identity from /root/.inkbox-claude/.env. Message text comes from a FILE so no shell quoting is
involved.

Usage (from the Windows session):
  MSYS_NO_PATHCONV=1 wsl.exe -u root /root/inkbox-ai/claude-code-plugin/.venv/bin/python \
    /mnt/c/Users/<USER>/.claude/skills/triage-ticket/scripts/inkbox-send.py \
    --text-file /mnt/c/Users/<USER>/AppData/Local/Temp/triage/<TICKET>-<rand>/imsg.txt \
    [--conversation-id <uuid> | --to <ANALYST_PHONE>]

Default: replies into the standing conversation with <ANALYST_NAME> (DEFAULT_CONVERSATION) because the
shared iMessage line cannot start new conversations. Prints JSON {"sent":true,"id":...,"conversation_id":...}.
"""
import argparse
import json
import sys

from inkbox import Inkbox

ENV_FILE = "/root/.inkbox-claude/.env"
DEFAULT_CONVERSATION = "<CONVERSATION_ID>"  # <ANALYST_NAME>, <ANALYST_PHONE>


def read_env(path):
    env = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()
    return env


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--text-file", required=True)
    g = p.add_mutually_exclusive_group()
    g.add_argument("--conversation-id")
    g.add_argument("--to")
    a = p.parse_args()

    with open(a.text_file, encoding="utf-8-sig") as f:
        text = f.read().strip()
    if not text:
        sys.exit("empty message text")

    env = read_env(ENV_FILE)
    identity = Inkbox(api_key=env["INKBOX_API_KEY"]).get_identity(env["INKBOX_IDENTITY"])

    kwargs = {"text": text}
    if a.to:
        kwargs["to"] = a.to
    else:
        kwargs["conversation_id"] = a.conversation_id or DEFAULT_CONVERSATION
    msg = identity.send_imessage(**kwargs)
    print(json.dumps({
        "sent": True,
        "id": str(getattr(msg, "id", "")),
        "conversation_id": str(getattr(msg, "conversation_id", kwargs.get("conversation_id", ""))),
    }))


if __name__ == "__main__":
    main()
