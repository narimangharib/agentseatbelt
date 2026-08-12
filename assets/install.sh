#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

VERSION="1.0.4"
PRIMARY="https://agentseatbelt.com"
GUARD_URL="${AGENTSEATBELT_URL:-$PRIMARY}/guard.sh"
SIG_URL="${AGENTSEATBELT_URL:-$PRIMARY}/guard.sh.sig"
EXPECTED_SHA256="${AGENTSEATBELT_SHA256:-325c3f69a0baa8420adbae8d10f98bf652bf9c10b0f9d18a8e915841a92d9a00}"

# Pinned signing key. Before trusting an install you did not initiate yourself,
# cross-check the value below against the copies published at:
#   https://agentseatbelt.com/allowed_signers
#   https://agentseatbelt.com/checksums.txt
#   https://github.com/narimangharib/agentseatbelt  (assets/allowed_signers)
# A mismatch between any of these means something is wrong. Do not install.
SIGNING_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICBibR3KoMM0xoKSQwqwNpu9xCANqaNWAk+MZgO7yAB2"
SIGNING_ID="security@agentseatbelt.com"
SIGNING_NS="agentseatbelt.com"
INSTALL_DIR="${HOME}/.agentseatbelt"
GUARD_PATH="${INSTALL_DIR}/guard.sh"
LOG_PREFIX="agentseatbelt"

say() { printf '%s\n' "$*"; }
ok() { printf '[ok] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
die() { printf '[error] %s\n' "$*" >&2; exit 1; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

need_cmd curl
need_cmd mkdir
need_cmd chmod
need_cmd mktemp

if [[ "$(uname -s)" == "Darwin" ]] || command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1; then
  :
else
  die "Need sha256sum or shasum to verify the download"
fi

hash_file() {
  local f="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$f" | awk '{print $1}'
  else
    shasum -a 256 "$f" | awk '{print $1}'
  fi
}

say ""
say "=============================================="
say "  Agent Seatbelt  v${VERSION}"
say "  Seatbelt for AI coding agents"
say "=============================================="
say ""
say "This installs a small safety hook on your computer."
say "It blocks dangerous shell commands before AI agents can run them."
say "It does not send your files or chat history anywhere."
say ""

mkdir -p "$INSTALL_DIR"
TMP="$(mktemp "${TMPDIR:-/tmp}/agentseatbelt.XXXXXX")"
cleanup() { rm -f "$TMP"; }
trap cleanup EXIT

say "Downloading guard from ${GUARD_URL} ..."
HTTP_CODE="$(curl -fsSL --proto '=https' --tlsv1.2 --connect-timeout 20 --max-time 60 \
  -A "AgentSeatbelt-Installer/${VERSION}" \
  -w '%{http_code}' -o "$TMP" "$GUARD_URL" || true)"

if [[ ! -s "$TMP" ]]; then
  die "Download failed (empty file). Check your network and try again."
fi

if [[ "$HTTP_CODE" != "200" && "$HTTP_CODE" != "000" ]]; then
  if ! head -1 "$TMP" | grep -q '^#!/'; then
    die "Download failed with HTTP ${HTTP_CODE}"
  fi
fi

GOT_HASH="$(hash_file "$TMP")"
if [[ -n "$EXPECTED_SHA256" && "$GOT_HASH" != "$EXPECTED_SHA256" ]]; then
  die "Checksum mismatch.
  expected: ${EXPECTED_SHA256}
  got:      ${GOT_HASH}
Refusing to install. Visit ${PRIMARY} and try again, or open an issue."
fi
ok "Checksum verified (${GOT_HASH:0:12}…)"

verify_signature() {
  local target="$1" sig signers out rc

  if ! command -v ssh-keygen >/dev/null 2>&1; then
    warn "ssh-keygen not found, skipping signature check. The checksum was verified."
    return 0
  fi

  sig="$(mktemp "${TMPDIR:-/tmp}/agentseatbelt-sig.XXXXXX")"
  signers="$(mktemp "${TMPDIR:-/tmp}/agentseatbelt-signers.XXXXXX")"
  trap 'rm -f "$TMP" "$sig" "$signers"' EXIT

  if ! curl -fsSL --proto '=https' --tlsv1.2 --connect-timeout 20 --max-time 60 \
      -A "AgentSeatbelt-Installer/${VERSION}" -o "$sig" "$SIG_URL" || [[ ! -s "$sig" ]]; then
    die "Could not download the signature from ${SIG_URL}.
Refusing to install. Check your network and try again."
  fi

  printf '%s %s\n' "$SIGNING_ID" "$SIGNING_KEY" > "$signers"

  set +e
  out="$(ssh-keygen -Y verify -f "$signers" -I "$SIGNING_ID" -n "$SIGNING_NS" -s "$sig" < "$target" 2>&1)"
  rc=$?
  set -e

  if [[ $rc -eq 0 ]]; then
    ok "Signature verified (${SIGNING_ID})"
    return 0
  fi

  if printf '%s' "$out" | grep -qiE 'unknown option|invalid option|unsupported|illegal option'; then
    warn "This ssh-keygen is too old to check signatures. The checksum was verified."
    return 0
  fi

  die "SIGNATURE VERIFICATION FAILED.
The downloaded guard is not signed by the expected key. Someone may be
tampering with the download, or the release is broken.
Refusing to install. Please report this to ${SIGNING_ID}."
}

verify_signature "$TMP"

cp "$TMP" "$GUARD_PATH"
chmod 755 "$GUARD_PATH"
ok "Installed guard → ${GUARD_PATH}"

merge_claude() {
  local settings="${HOME}/.claude/settings.json"
  local hooks_dir="${HOME}/.claude/hooks"
  mkdir -p "$hooks_dir"
  ln -sfn "$GUARD_PATH" "${hooks_dir}/bash-guard.sh"
  ok "Linked Claude Code hook → ${hooks_dir}/bash-guard.sh"

  if ! command -v python3 >/dev/null 2>&1; then
    warn "python3 not found; add this to ${settings} manually under hooks.PreToolUse:"
    warn "  matcher Bash → command ${hooks_dir}/bash-guard.sh"
    return 0
  fi

  python3 - "$settings" "$hooks_dir/bash-guard.sh" <<'PY'
import json, os, sys, tempfile
path, cmd = sys.argv[1], sys.argv[2]
data = {}
if os.path.isfile(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read().strip()
        data = json.loads(raw) if raw else {}
        if not isinstance(data, dict):
            data = {}
    except Exception:
        bak = path + ".agentseatbelt.bak"
        os.replace(path, bak)
        print(f"[!] Existing settings were not valid JSON. Backed up to {bak}", file=sys.stderr)
        data = {}

hooks = data.setdefault("hooks", {})
if not isinstance(hooks, dict):
    hooks = {}
    data["hooks"] = hooks
pre = hooks.setdefault("PreToolUse", [])
if not isinstance(pre, list):
    pre = []
    hooks["PreToolUse"] = pre

entry = {
    "matcher": "Bash",
    "hooks": [
        {
            "type": "command",
            "command": cmd,
            "timeout": 5,
        }
    ],
}

def is_ours(item):
    if not isinstance(item, dict):
        return False
    for h in item.get("hooks") or []:
        if not isinstance(h, dict):
            continue
        c = str(h.get("command") or "")
        if "bash-guard.sh" in c or "agentseatbelt" in c or "guard.sh" in c:
            return True
    return False

pre[:] = [x for x in pre if not is_ours(x)]
pre.insert(0, entry)

parent = os.path.dirname(path) or "."
os.makedirs(parent, exist_ok=True)
fd, tmp = tempfile.mkstemp(prefix="claude-settings.", suffix=".json", dir=parent)
try:
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    os.replace(tmp, path)
except Exception:
    try:
        os.unlink(tmp)
    except OSError:
        pass
    raise
print("[ok] Updated Claude Code settings →", path)
PY
}

merge_grok() {
  local hooks_dir="${HOME}/.grok/hooks"
  mkdir -p "$hooks_dir"
  ln -sfn "$GUARD_PATH" "${hooks_dir}/bash-guard.sh"
  ok "Linked Grok hook → ${hooks_dir}/bash-guard.sh"

  local cfg="${HOME}/.grok/hooks/agentseatbelt.json"
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$cfg" "$hooks_dir/bash-guard.sh" <<'PY'
import json, os, sys, tempfile
path, cmd = sys.argv[1], sys.argv[2]
data = {
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Shell|shell",
        "hooks": [
          {"type": "command", "command": cmd, "timeout": 5}
        ]
      }
    ]
  }
}
parent = os.path.dirname(path) or "."
os.makedirs(parent, exist_ok=True)
fd, tmp = tempfile.mkstemp(prefix="grok-hooks.", suffix=".json", dir=parent)
try:
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    os.replace(tmp, path)
except Exception:
    try:
        os.unlink(tmp)
    except OSError:
        pass
    raise
print("[ok] Wrote Grok hook config →", path)
PY
  fi
}

merge_codex() {
  local hooks="${HOME}/.codex/hooks.json"
  mkdir -p "${HOME}/.codex"
  if ! command -v python3 >/dev/null 2>&1; then
    warn "python3 missing; skip Codex auto-config. Guard is still at ${GUARD_PATH}"
    return 0
  fi
  python3 - "$hooks" "$GUARD_PATH" <<'PY'
import json, os, sys, tempfile
path, cmd = sys.argv[1], sys.argv[2]
data = {}
if os.path.isfile(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read().strip()
        data = json.loads(raw) if raw else {}
        if not isinstance(data, dict):
            data = {}
    except Exception:
        bak = path + ".agentseatbelt.bak"
        os.replace(path, bak)
        print(f"[!] Codex hooks backed up to {bak}", file=sys.stderr)
        data = {}

pre = data.setdefault("PreToolUse", data.setdefault("hooks", {}).get("PreToolUse") if isinstance(data.get("hooks"), dict) else None)
# normalize to top-level PreToolUse list used by several agents
if not isinstance(data.get("PreToolUse"), list):
    if isinstance(data.get("hooks"), dict) and isinstance(data["hooks"].get("PreToolUse"), list):
        data["PreToolUse"] = data["hooks"]["PreToolUse"]
    else:
        data["PreToolUse"] = []

entry = {
    "matcher": "Bash",
    "hooks": [{"type": "command", "command": cmd, "timeout": 5}],
}

def is_ours(item):
    if not isinstance(item, dict):
        return False
    for h in item.get("hooks") or []:
        if isinstance(h, dict) and ("agentseatbelt" in str(h.get("command") or "") or "guard.sh" in str(h.get("command") or "")):
            return True
    return False

data["PreToolUse"] = [x for x in data["PreToolUse"] if not is_ours(x)]
data["PreToolUse"].insert(0, entry)

parent = os.path.dirname(path) or "."
os.makedirs(parent, exist_ok=True)
fd, tmp = tempfile.mkstemp(prefix="codex-hooks.", suffix=".json", dir=parent)
try:
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    os.replace(tmp, path)
except Exception:
    try:
        os.unlink(tmp)
    except OSError:
        pass
    raise
print("[ok] Updated Codex hooks →", path)
PY
}

say "Configuring supported AI tools (only if present)…"
CONFIGURED=0
if [[ -d "${HOME}/.claude" ]] || command -v claude >/dev/null 2>&1; then
  merge_claude
  CONFIGURED=$((CONFIGURED + 1))
fi
if [[ -d "${HOME}/.grok" ]] || command -v grok >/dev/null 2>&1; then
  merge_grok
  CONFIGURED=$((CONFIGURED + 1))
fi
if [[ -d "${HOME}/.codex" ]] || command -v codex >/dev/null 2>&1; then
  merge_codex
  CONFIGURED=$((CONFIGURED + 1))
fi

if [[ "$CONFIGURED" -eq 0 ]]; then
  say ""
  warn "No supported AI tool was found on this computer."
  say "  The guard is installed at ${GUARD_PATH}, but nothing is using it yet."
  say "  Install Claude Code, Grok, or Codex and run this installer again,"
  say "  or point your tool's PreToolUse hook at that file yourself."
fi

printf '%s\n' "$VERSION" > "${INSTALL_DIR}/VERSION"
printf '%s\n' "$GOT_HASH" > "${INSTALL_DIR}/SHA256"
printf '%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "${INSTALL_DIR}/INSTALLED_AT"

say ""
ok "Agent Seatbelt is installed."
say ""
say "What to do next (takes about 30 seconds):"
say "  1. Fully quit your AI coding app (Claude Code, Grok, Cursor, etc.)."
say "  2. Open it again."
say "  3. Ask the AI to run a safe command like:  ls"
say "  4. Dangerous commands such as  rm -rf /  or  git push --force  will be blocked."
say ""
say "Files on this computer:"
say "  Guard:    ${GUARD_PATH}"
say "  Version:  ${INSTALL_DIR}/VERSION"
say "  Checksum: ${INSTALL_DIR}/SHA256"
say ""
say "Uninstall later:"
say "  rm -rf ${INSTALL_DIR}"
say "  (and remove the hook entry from your AI tool settings if needed)"
say ""
say "Help: ${PRIMARY}"
say "Developed by Nariman Gharib"
say ""
