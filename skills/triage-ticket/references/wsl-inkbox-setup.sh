#!/usr/bin/env bash
set -e
echo "[*] staging patched plugin source"
SRC=/mnt/c/Users/<USER>/inkbox-ai/claude-code-plugin
DST=/root/inkbox-ai/claude-code-plugin
rm -rf "$DST"; mkdir -p "$DST"
cp -r "$SRC/inkbox_claude" "$DST/"
cp "$SRC/pyproject.toml" "$DST/" 2>/dev/null || true
cp "$SRC/uv.lock" "$DST/" 2>/dev/null || true
cp "$SRC/README.md" "$DST/" 2>/dev/null || true

echo "[*] patch check"
if grep -q "_external_handler_active" "$DST/inkbox_claude/gateway.py"; then
  echo "[*] already patched"
else
  echo "[*] applying external-handler patch"
  ( cd "$DST" && patch -p1 < /mnt/c/ClaudeSkills/references/gateway-external-handler.patch ) || echo "[!] PATCH FAILED"
fi

echo "[*] venv + install (this pulls deps from PyPI)"
cd "$DST"
python3 -m venv .venv
.venv/bin/pip install -q --upgrade pip
.venv/bin/pip install -q -e .

echo "[*] writing /root/.inkbox-claude/.env"
mkdir -p /root/.inkbox-claude /root/claude-pushed
cat > /root/.inkbox-claude/.env <<EOF
INKBOX_API_KEY=<INKBOX_API_KEY>
INKBOX_IDENTITY=agent-notification
CLAUDE_PROJECT_DIR=/root/claude-pushed
INKBOX_ALLOW_ALL_USERS=true
INKBOX_SIGNING_KEY=<INKBOX_SIGNING_KEY>
INKBOX_REQUIRE_SIGNATURE=true
INKBOX_EXTERNAL_HANDLER_LOG=/root/.inkbox-claude/events.jsonl
EOF
touch /root/.inkbox-claude/events.jsonl

echo "[*] patched marker in installed source:"
grep -c "_external_handler_active" "$DST/inkbox_claude/gateway.py" || true
echo "[*] doctor:"
PYTHONUTF8=1 PYTHONIOENCODING=utf-8 .venv/bin/inkbox-claude doctor || true
echo "[*] DONE-SETUP"
