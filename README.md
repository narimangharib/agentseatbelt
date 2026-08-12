# Agent Seatbelt

A seatbelt for AI coding agents. It inspects the shell commands an AI agent wants to run and blocks the destructive ones before they execute.

**Website:** https://agentseatbelt.com
**Developer:** Nariman Gharib

This repository contains the two files that run on your machine, and nothing else. The marketing site is not published here, so the code you audit is exactly the code you install.

```
assets/guard.sh     the guard itself, runs as a PreToolUse hook
assets/install.sh   installer, verifies the guard checksum before writing it
```

## Install

```bash
curl -fsSL https://agentseatbelt.com/install | bash
```

Prefer to read it first, which is the better habit:

```bash
curl -fsSL https://agentseatbelt.com/guard.sh -o guard.sh
shasum -a 256 guard.sh
less guard.sh
```

Compare that checksum against the one published at https://agentseatbelt.com/checksums.txt and the copy in this repository.

## Verifying the signature

Releases are signed with an Ed25519 key. When `ssh-keygen` 8.0 or newer is present, the installer verifies the signature and refuses to install if it does not match. If `ssh-keygen` is missing or older, it says so and falls back to the checksum alone. See [Honest limits](#honest-limits) for what that means. To check by hand:

```bash
curl -fsSL https://agentseatbelt.com/guard.sh     -o guard.sh
curl -fsSL https://agentseatbelt.com/guard.sh.sig -o guard.sh.sig
curl -fsSL https://agentseatbelt.com/allowed_signers -o allowed_signers

ssh-keygen -Y verify -f allowed_signers -I security@agentseatbelt.com \
  -n agentseatbelt.com -s guard.sh.sig < guard.sh
```

Expected output:

```
Good "agentseatbelt.com" signature for security@agentseatbelt.com with ED25519 key SHA256:t5c5m2Ioz6ODOdx9pqEZ9uv7iOS20KtcQZuiO/Ypxig
```

The signing key fingerprint is `SHA256:t5c5m2Ioz6ODOdx9pqEZ9uv7iOS20KtcQZuiO/Ypxig`. The private key is held offline. It is not on the web server, not in this repository, and not reachable from the deploy path, so compromising the website does not let anyone produce a valid signature.

**Why the checksum alone was not enough.** The guard and its expected checksum are published from the same place. Anyone able to change what that site serves could change the script and its published hash together, and the installer would still have reported a clean verification. The signature breaks that, because the signing key is never on the server. Compare the key in `assets/allowed_signers` here against the one at https://agentseatbelt.com/checksums.txt, and treat any mismatch as an incident.

## What it blocks

Recursive deletes targeting home, Desktop, Documents, or system paths. Destructive git history operations, including force push, hard reset, `clean --force`, and branch history rewrites. Database drops, truncates, and framework database resets. Mirroring deletes, container volume wipes, and infrastructure teardown. Remote pipe-to-shell execution, privilege escalation, and disk formatting.

Everyday work is untouched. Listing files, running tests, `git status`, builds, and relative project deletes such as `rm -rf ./dist` all continue to work.

## How it works

The guard reads the hook payload on stdin, extracts the proposed shell command, normalises it, and matches it against a set of high-risk patterns. Exit code `0` allows the command. Exit code `2` blocks it and prints the reason.

It never executes the command it inspects. It performs no network access, writes no logs, and sends nothing anywhere.

Claude Code is configured automatically. Grok and Codex are configured when their config directories already exist. The guard also works with any tool that supports a `PreToolUse` shell hook.

## Updating

Run the same install command again. It is idempotent: it replaces the guard in place, re-verifies the checksum and the signature, and does not duplicate your hook entries.

```bash
curl -fsSL https://agentseatbelt.com/install | bash
```

Check the version you have against the current release:

```bash
cat ~/.agentseatbelt/VERSION
curl -fsS https://agentseatbelt.com/version
```

**There is deliberately no auto-updater.** The guard runs on every shell command an agent proposes, so an automatic update channel would be an unusually valuable target: whoever controlled it would get code execution on every user's machine, on every command. The guard also makes no network calls of any kind, which is what lets this project honestly say nothing leaves your computer. Both properties are worth more than the convenience of updating itself.

Watch this repository, or the version endpoint above, to know when there is something new.

## Uninstall

```bash
rm -rf ~/.agentseatbelt
```

Then remove the hook entry from your AI tool's settings, for example the `PreToolUse` block in `~/.claude/settings.json`.

## Honest limits

This is a seatbelt, not a sandbox. It is pattern matching over a command string, so a determined attacker or an unusual quoting trick can get around it. Version 1.0.1 fixed exactly that class of bug: `rm -rf "$HOME"` was allowed while `rm -rf $HOME` was blocked, because the path check required a slash, whitespace, or end of line after the variable and a closing quote is none of those.

Version 1.0.2 fixed a false positive in the other direction: `curl <url> | shasum -a 256`, the checksum verification this README recommends, was blocked because the pattern matched `sh` as a prefix of `shasum`.

Version 1.0.3 closed two more. A push using a `+` refspec, and a mirror push, are both force pushes that carry no `--force` flag, so the flag-based rule never saw them.

Version 1.0.4 narrowed two rules that were too eager. Patterns are matched against the whole command line rather than the delete target's arguments, so a recursive delete alongside a redirect to the null device, or alongside an unrelated glob later in the same line, was refused. Both are ordinary cleanup and now pass, while every destructive form still blocks.

**The signature protection is conditional.** It is what defends you if this website is ever compromised, because the signing key is not on the server. That defence only applies on systems that can actually check a signature. If `ssh-keygen` is absent or predates 8.0, the installer warns you and proceeds on the checksum alone, and in that case a compromised server could serve a modified guard together with a matching hash, which is exactly the attack the signature exists to stop. Most systems shipped since 2019 are fine. If you want certainty, run the verification commands above by hand before installing.

For higher assurance, combine it with OS level sandboxing and do not leave an agent running unattended against production systems.

## License

MIT. See [LICENSE](LICENSE).

## Reporting a security issue

security@agentseatbelt.com, or see https://agentseatbelt.com/.well-known/security.txt

Please include reproduction steps and the version from https://agentseatbelt.com/version. Test only against machines you own.
