#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

INPUT="$(cat || true)"

extract_command() {
  local raw="$1"
  if [[ -z "$raw" ]]; then
    printf ''
    return 0
  fi
  if command -v jq >/dev/null 2>&1; then
    local out
    if out="$(printf '%s' "$raw" | jq -re '.tool_input.command // .command // empty' 2>/dev/null)"; then
      printf '%s' "$out"
      return 0
    fi
    if printf '%s' "$raw" | jq -e . >/dev/null 2>&1; then
      printf ''
      return 0
    fi
    printf 'bash-guard: invalid hook JSON; blocking closed\n' >&2
    exit 2
  fi
  if command -v python3 >/dev/null 2>&1; then
    local py_out py_rc
    set +e
    py_out="$(printf '%s' "$raw" | python3 -c '
import json, sys
raw = sys.stdin.read()
if not raw.strip():
    sys.exit(0)
try:
    d = json.loads(raw)
except Exception:
    sys.exit(3)
if not isinstance(d, dict):
    sys.exit(0)
ti = d.get("tool_input")
c = None
if isinstance(ti, dict):
    c = ti.get("command")
if c is None:
    c = d.get("command")
if c is None or c == "":
    sys.exit(0)
sys.stdout.write(str(c))
' 2>/dev/null)"
    py_rc=$?
    set -e
    if [[ "$py_rc" -eq 0 ]]; then
      printf '%s' "$py_out"
      return 0
    fi
    if [[ "$py_rc" -eq 3 ]]; then
      printf 'bash-guard: invalid hook JSON; blocking closed\n' >&2
      exit 2
    fi
    printf 'bash-guard: failed to parse hook input; blocking closed\n' >&2
    exit 2
  fi
  printf 'bash-guard: jq and python3 missing; cannot parse hook input; blocking closed\n' >&2
  exit 2
}

CMD="$(extract_command "$INPUT")"

if [[ -z "${CMD//[[:space:]]/}" ]]; then
  exit 0
fi

NORM="$(printf '%s' "$CMD" | tr -s '[:space:]' ' ' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
NORM_LC="$(printf '%s' "$NORM" | tr '[:upper:]' '[:lower:]')"
# Quote-stripped view. Shell quoting does not change what a path resolves to,
# so rm -rf "$HOME" must be judged the same as rm -rf $HOME.
NORM_NQ="$(printf '%s' "$NORM" | tr -d '\042\047')"

block() {
  local reason="$1"
  printf 'BLOCKED by agent-seatbelt: %s\n' "$reason" >&2
  printf 'Command: %s\n' "$CMD" >&2
  printf 'Hint: run this yourself in a normal terminal if it is intentional.\n' >&2
  exit 2
}

matches() {
  local pattern="$1"
  printf '%s' "$NORM" | grep -qE "$pattern"
}

matches_lc() {
  local pattern="$1"
  printf '%s' "$NORM_LC" | grep -qE "$pattern"
}

matches_nq() {
  local pattern="$1"
  printf '%s' "$NORM_NQ" | grep -qE "$pattern"
}

BOUNDARY='(^|[[:space:];&|`|(])'
SEP='([[:space:]]|$)'

has_rm() {
  matches "${BOUNDARY}rm${SEP}"
}

has_rm_recursive() {
  has_rm || return 1
  if matches '[[:space:]]--recursive([[:space:]]|$)|[[:space:]]-[a-zA-Z]*[rR][a-zA-Z]*([[:space:]]|$)'; then
    return 0
  fi
  return 1
}

has_rm_force() {
  matches '[[:space:]]--force([[:space:]]|$)|[[:space:]]-[a-zA-Z]*[fF][a-zA-Z]*([[:space:]]|$)'
}

# Two deliberate narrowings, both so ordinary cleanup is not blocked:
#   the bare-glob alternative requires whitespace before the *, so `ls dist*`
#   elsewhere in a compound command does not count as a broad glob; and /dev is
#   matched only as a bare target or a real block device, so `2>/dev/null` is fine.
PROTECTED_RM_PATH='(~(/|$|[[:space:]/*])|\$HOME(/|$|[[:space:]])|\$\{HOME\}(/|$|[[:space:]])|\.\.(/|$|[[:space:]])|[[:space:]]\*([[:space:]]|$)|/\*|~\*|/(Users|home)(/|$|[[:space:]/*])|/Users/[^[:space:]/]+(/|$|[[:space:]])|/home/[^[:space:]/]+(/|$|[[:space:]])|/(etc|usr|bin|sbin|opt|System|Library|Volumes|Applications|boot|root)(/|[[:space:]/*]|$)|/dev([[:space:]]|$)|/dev/(disk|rdisk|sd[a-z]|nvme|hd[a-z]|mmcblk)|/private/(etc|var)(/|[[:space:]/*]|$)|/var/(log|lib|db|empty|folders|root|spool|cache|mail|run|lock|backups|audit)(/|[[:space:]/*]|$)|(~/|\$HOME/|\$\{HOME\}/|/Users/[^[:space:]/]+/|/home/[^[:space:]/]+/)(Desktop|Documents|Downloads|Pictures|Movies|Music|Sites|\.ssh|\.gnupg|\.aws|\.config|\.claude|\.grok|\.codex)(/|$|[[:space:]])|~/.Trash|/Trash(/|$))'

if has_rm_recursive; then
  if matches "(^|[[:space:]])(/($|[[:space:]]))" || matches_nq "(^|[[:space:]])(/($|[[:space:]]))"; then
    block "recursive rm targeting filesystem root"
  fi
  if matches "${PROTECTED_RM_PATH}" || matches_nq "${PROTECTED_RM_PATH}"; then
    block "recursive rm targeting home, user data, system path, or broad glob"
  fi
  if has_rm_force && matches '(^|[[:space:]])(\./|\.\./|[^/~$[:space:]][^[:space:]]*)'; then
    if matches '[[:space:]]\*([[:space:]]|$)|[[:space:]]\.\*([[:space:]]|$)'; then
      block "recursive force rm with broad glob"
    fi
  fi
fi

if has_rm && has_rm_force && matches '[[:space:]]\*([[:space:]]|$)|[[:space:]]\.\*([[:space:]]|$)'; then
  block "force rm with broad glob"
fi

if matches_lc 'xargs[[:space:]]+([^;|&]*[[:space:]])?rm[[:space:]]|xargs[[:space:]]+([^;|&]*[[:space:]])?-0[[:space:]]+rm'; then
  block "xargs rm bulk delete is not allowed without explicit human action"
fi

if matches "${BOUNDARY}(sudo|doas|pkexec)${SEP}"; then
  block "elevated shell (sudo/doas/pkexec) is not allowed from agent context"
fi

if matches_lc 'osascript[[:space:]].*administrator privileges|osascript[[:space:]].*with administrator'; then
  block "macOS administrator osascript is not allowed from agent context"
fi

# The second alternative catches the + refspec form, git push origin +main,
# which is a force push that carries no --force flag.
if matches_lc 'git[[:space:]]+push[[:space:]]+([^;|&]*[[:space:]])?(-f|--force|--force-with-lease)([[:space:]]|$)|git[[:space:]]+push[[:space:]]+[^;|&]*[[:space:]][+][^[:space:];|&]'; then
  block "git force push is not allowed without explicit human action"
fi

if matches_lc 'git[[:space:]]+push[[:space:]]+([^;|&]*[[:space:]])?--mirror([[:space:]]|$)'; then
  block "git push --mirror is not allowed from agent context"
fi

if matches_lc 'git[[:space:]]+reset[[:space:]]+([^;|&]*[[:space:]])?--hard([[:space:]]|$)'; then
  block "git reset --hard is not allowed without explicit human action"
fi

if matches_lc 'git[[:space:]]+checkout[[:space:]]+--[[:space:]]*\.([[:space:]]|$)|git[[:space:]]+checkout[[:space:]]+\.([[:space:]]|$)|git[[:space:]]+restore[[:space:]]+\.([[:space:]]|$)|git[[:space:]]+restore[[:space:]]+--worktree[[:space:]]+\.([[:space:]]|$)'; then
  block "git checkout/restore that discards all local work is not allowed without explicit human action"
fi

if matches_lc 'git[[:space:]]+clean[[:space:]]'; then
  if matches_lc '[[:space:]]-[a-zA-Z]*f[a-zA-Z]*x|[[:space:]]-[a-zA-Z]*x[a-zA-Z]*f|[[:space:]]-f([[:space:]]|$).*[[:space:]]-x|[[:space:]]-x([[:space:]]|$).*[[:space:]]-f|[[:space:]]--force.*(-x|--exclude)|[[:space:]]-x.*--force'; then
    block "git clean force with ignored-file removal is not allowed without explicit human action"
  fi
  if matches_lc '[[:space:]]-[a-zA-Z]*f[a-zA-Z]*d|[[:space:]]-[a-zA-Z]*d[a-zA-Z]*f|[[:space:]]-f([[:space:]]|$).*[[:space:]]-d|[[:space:]]-d([[:space:]]|$).*[[:space:]]-f|[[:space:]]--force.*-d|[[:space:]]-d.*--force'; then
    if ! matches_lc '--dry-run|-n([[:space:]]|$)'; then
      block "git clean -fd is not allowed without explicit human action"
    fi
  fi
  if matches_lc '[[:space:]]-f([[:space:]]|$)|[[:space:]]--force([[:space:]]|$)'; then
    if ! matches_lc '--dry-run|-n([[:space:]]|$)'; then
      block "git clean --force is not allowed without explicit human action"
    fi
  fi
fi

if matches_lc 'git[[:space:]]+(filter-branch|filter-repo|update-ref[[:space:]]+-d|push[[:space:]]+[^;|&]*--delete|stash[[:space:]]+(drop|clear)|branch[[:space:]]+(-D|--delete[[:space:]]+-f)|reflog[[:space:]]+expire|gc[[:space:]]+.*--prune=now)([[:space:]]|$)'; then
  block "destructive git history, stash wipe, or force branch delete is not allowed without explicit human action"
fi

if matches_lc 'rsync[[:space:]]+[^;|&]*--[[:space:]]*delete|rsync[[:space:]]+[^;|&]*--[[:space:]]*delete-(after|before|during|excluded|delay)'; then
  block "rsync --delete can wipe the destination; not allowed from agent context"
fi

if matches_lc '(curl|wget|fetch)[^|;]*\|[[:space:]]*(sudo[[:space:]]+)?(ba|z|k|fi)?sh([[:space:]]|$)'; then
  block "piping a remote download into a shell is not allowed"
fi

if matches_lc '(ba)?sh[[:space:]]+<[[:space:]]*\([[:space:]]*(curl|wget|fetch)\b'; then
  block "process-substitution shell from remote download is not allowed"
fi

if matches_lc '(ba)?sh[[:space:]]+-c[[:space:]]+["'"'"']?\$\([[:space:]]*(curl|wget|fetch)\b'; then
  block "bash -c with remote download substitution is not allowed"
fi

if matches_lc 'source[[:space:]]+<[[:space:]]*\([[:space:]]*(curl|wget|fetch)\b|\.[[:space:]]+<[[:space:]]*\([[:space:]]*(curl|wget|fetch)\b'; then
  block "sourcing a remote download is not allowed"
fi

if matches_lc '(curl|wget|fetch).+(-o|--output|-O)[[:space:]]+[^;|&]+(;|&&|\|)[[:space:]]*(sudo[[:space:]]+)?(ba|z|fi)?sh([[:space:]]|$)'; then
  block "download-then-execute shell chain is not allowed"
fi

if matches_lc 'base64[[:space:]]+(-d|--decode|-[Dd])[^|;]*\|[[:space:]]*(ba)?sh([[:space:]]|$)'; then
  block "piping base64 decode into a shell is not allowed"
fi

if matches_lc '(\|[[:space:]]*iex|iwr[[:space:]].*\|[[:space:]]*iex|invoke-expression)'; then
  block "PowerShell download-and-invoke is not allowed"
fi

if matches "${BOUNDARY}eval${SEP}"; then
  block "eval is not allowed from agent context"
fi

if matches "${BOUNDARY}exec[[:space:]]+(\$\(|\`)"; then
  block "exec on a command substitution is not allowed"
fi

if matches_lc "${BOUNDARY}(ba|z|fi)?sh[[:space:]]+(-[a-zA-Z]*c|-c)[[:space:]]"; then
  if matches_lc 'rm[[:space:]]|git[[:space:]]+(reset|clean|push|filter|checkout|restore)|sudo|doas|mkfs|dd[[:space:]]|shutdown|reboot|curl|wget|chmod[[:space:]]|chown[[:space:]]|drop[[:space:]]+|truncate[[:space:]]+table|flushall|rsync|terraform|prisma|:\(\)\{'; then
    block "nested shell -c with destructive or network-exec payload is not allowed"
  fi
fi

if matches_lc "${BOUNDARY}(python3?|python)[[:space:]]+(-[a-zA-Z]*c|-c)[[:space:]]"; then
  if matches_lc 'shutil\.rmtree|os\.(system|remove|unlink|rmdir)|subprocess\.(run|call|popen|check_call)|pathlib\.path.*unlink|rm[[:space:]]+-|git[[:space:]]+reset|git[[:space:]]+clean|git[[:space:]]+push|drop[[:space:]]+table|flushall'; then
    block "python -c with destructive filesystem or subprocess payload is not allowed"
  fi
fi

if matches_lc "${BOUNDARY}(node|nodejs)[[:space:]]+(-[a-zA-Z]*e|-e)[[:space:]]"; then
  if matches_lc 'rmsync|rmdirsync|unlinksync|child_process|execsync|spawnsync|fs\.rm\b'; then
    block "node -e with destructive filesystem or process payload is not allowed"
  fi
fi

if matches_lc "${BOUNDARY}(perl|ruby)[[:space:]]+(-[a-zA-Z]*e|-e)[[:space:]]"; then
  if matches_lc 'system\(|exec\(|unlink|rmtree|fileutils|rm_rf|rm_r'; then
    block "perl/ruby -e with destructive payload is not allowed"
  fi
fi

if matches ':\(\)\{[[:space:]]*: \|:&[[:space:]]*\};:|:\(\)\{[[:space:]]*:\|:&[[:space:]]*\};:'; then
  block "fork bomb pattern detected"
fi

if matches_lc "${BOUNDARY}dd[[:space:]]+([^;|&]*[[:space:]])?of=/dev/(disk|rdisk|sd[a-z]|nvme|hd[a-z]|mmcblk)"; then
  block "dd write to a raw disk device"
fi

if matches_lc "${BOUNDARY}(mkfs(\.|[[:space:]]|$)|newfs([[:space:]]|$)|diskutil[[:space:]]+(erase|partition|reformat)|fdisk([[:space:]]|$)|parted([[:space:]]|$)|wipefs([[:space:]]|$)|shred[[:space:]]|srm[[:space:]])"; then
  block "disk erase, secure-delete, or filesystem format command"
fi

if matches "${BOUNDARY}(shutdown|reboot|halt|poweroff|init[[:space:]]+[06])${SEP}"; then
  block "system shutdown or reboot is not allowed from agent context"
fi

if matches_lc 'chmod[[:space:]]+([^;|&]*[[:space:]])?-R[[:space:]]+([^;|&]*[[:space:]])?(777|a\+rwx)[[:space:]]+(/|~|\$HOME|/Users|/home|/etc|/usr|/var|/System|/Library)'; then
  block "recursive world-writable chmod on absolute or home path"
fi

if matches_lc 'chown[[:space:]]+([^;|&]*[[:space:]])?-R[[:space:]]+[^;|&]+[[:space:]]+(/|~|\$HOME|/Users|/home|/etc|/usr|/var|/System|/Library)([[:space:]]|$)'; then
  block "recursive chown on critical path"
fi

if matches_lc 'find[[:space:]].*[[:space:]]-delete([[:space:]]|$)|find[[:space:]].*[[:space:]]-exec[[:space:]]+rm([[:space:]]|$)|find[[:space:]].*[[:space:]]-execdir[[:space:]]+rm([[:space:]]|$)'; then
  block "find delete/rm bulk removal is not allowed without explicit human action"
fi

if matches '(/dev/(sd[a-z]|nvme|disk|rdisk)|/etc/(passwd|shadow|sudoers))'; then
  if matches "${BOUNDARY}(cat|tee|dd|cp|mv|install|truncate|printf|echo)${SEP}"; then
    if matches '>[>]?[[:space:]]*/(dev/(sd|nvme|disk|rdisk)|etc/(passwd|shadow|sudoers))|of=/(dev/(sd|nvme|disk|rdisk)|etc/)'; then
      block "write targeting raw device or critical auth files"
    fi
  fi
fi

if matches_lc "${BOUNDARY}(iptables[[:space:]]+-F|ip6tables[[:space:]]+-F|pfctl[[:space:]]+-F)"; then
  block "flushing host firewall rules is not allowed from agent context"
fi

if matches_lc 'launchctl[[:space:]]+(bootout|unload)[[:space:]]+(system|system/)|csrutil[[:space:]]+disable|nvram[[:space:]]+'; then
  block "macOS system integrity or launchd system-domain change is not allowed"
fi

if matches_lc "${BOUNDARY}(security[[:space:]]+delete-keychain|security[[:space:]]+delete-generic-password)${SEP}"; then
  block "keychain deletion is not allowed from agent context"
fi

if matches_lc 'crontab[[:space:]]+-r([[:space:]]|$)|[[:space:]]*>[[:space:]]*/etc/crontab([[:space:]]|$)'; then
  block "removing or overwriting crontab is not allowed from agent context"
fi

if matches_lc 'docker[[:space:]]+system[[:space:]]+prune[[:space:]]+[^;|&]*(-a|--all)|docker[[:space:]]+volume[[:space:]]+(prune|rm)|docker[[:space:]]+rmi[[:space:]]+(-f[[:space:]]+)?\$\(|docker[[:space:]]+compose[[:space:]]+down[[:space:]]+[^;|&]*-v|docker-compose[[:space:]]+down[[:space:]]+[^;|&]*-v'; then
  block "broad docker prune, volume wipe, or compose down -v is not allowed without explicit human action"
fi

if matches_lc 'kubectl[[:space:]]+delete[[:space:]]+(namespace|ns)[[:space:]]|kubectl[[:space:]]+delete[[:space:]]+[^;|&]*--all([[:space:]]|$)'; then
  block "kubectl delete namespace or --all is not allowed without explicit human action"
fi

if matches_lc '(drop[[:space:]]+(database|schema)\b|truncate[[:space:]]+table[[:space:]]|;\s*drop\s+table\b|dropdb[[:space:]]|mysqladmin[[:space:]]+drop)'; then
  block "destructive database drop/truncate is not allowed without explicit human action"
fi

if matches_lc 'prisma[[:space:]]+(migrate[[:space:]]+reset|db[[:space:]]+push[[:space:]]+[^;|&]*--force-reset)|rails[[:space:]]+db:(drop|reset|setup)|rake[[:space:]]+db:(drop|reset)|manage\.py[[:space:]]+flush|redis-cli[[:space:]]+[^;|&]*flush(all|db)|flushall|flushdb'; then
  block "framework/database reset or flush is not allowed without explicit human action"
fi

if matches_lc 'terraform[[:space:]]+destroy|pulumi[[:space:]]+destroy|cdk[[:space:]]+destroy|wrangler[[:space:]]+(delete|d1[[:space:]]+delete|r2[[:space:]]+object[[:space:]]+delete)|flyctl[[:space:]]+apps[[:space:]]+destroy|fly[[:space:]]+apps[[:space:]]+destroy|heroku[[:space:]]+.*?(destroy|pg:reset)'; then
  block "cloud/infra destroy or production reset is not allowed without explicit human action"
fi

if matches_lc 'curl[[:space:]]+[^;|&]*[[:space:]]-o[[:space:]]+/etc/|wget[[:space:]]+[^;|&]*-O[[:space:]]+/etc/'; then
  block "download writing directly under /etc is not allowed"
fi

if matches_lc "${BOUNDARY}(brew[[:space:]]+uninstall[[:space:]]+--force|apt(-get)?[[:space:]]+(remove|purge)[[:space:]]+(-y|--yes).*--autoremove|npm[[:space:]]+publish([[:space:]]|$)|pypi[[:space:]]+upload|twine[[:space:]]+upload)"; then
  block "force package uninstall or unattended publish is not allowed without explicit human action"
fi

if matches_lc 'mv[[:space:]]+([^;|&]*[[:space:]])?(~|/Users|/home|\$HOME|\$\{HOME\})(/|[[:space:]]|$)'; then
  block "moving home or user root path is not allowed from agent context"
fi

if matches_lc 'rm[[:space:]]+[^;|&]*Trash|emptytrash|trash[[:space:]]+empty|tputil[[:space:]]+empty'; then
  block "emptying trash from agent context is not allowed"
fi

exit 0
