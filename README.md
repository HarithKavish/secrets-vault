# secrets-vault

A local blind secret broker for AI coding agents (Claude Code, and any other
CLI-driven agent) running on the same machine.

## The problem

Any text an agent tool call returns becomes part of that agent's context — it
is sent to the model provider's API and stored in the session transcript. A
secret that shows up in a tool result has already leaked at that point, even
if the agent never repeats it back to anyone. Asking an agent to "be careful"
with a value it can already see doesn't fix this — the leak already happened
the moment the value entered its context.

The only reliable fix is architectural: the agent must never receive the
plaintext at all. It only ever deals in opaque names and masked previews;
a separate local process moves the real bytes directly from storage to
destination.

## What this is

`secretctl` is that local process — a single script plus two thin shims so it
runs the same way from PowerShell, `cmd`, or a POSIX shell (Git Bash/WSL):

- `secretctl.ps1` — the implementation (PowerShell 7+)
- `secretctl.cmd` — Windows shim (PowerShell/cmd resolve bare `secretctl`)
- `secretctl` — POSIX shim (Git Bash resolves bare `secretctl`)

Every subcommand emits only a masked preview (`********ab12`) or a
success/failure line to its own output — including `reveal`, which delivers
the value via the clipboard instead of printing it, specifically so it stays
safe to call from an agent.

**Every verb is callable by any agent.** Nothing is gated on "is a human
typing in this terminal" — that was the original design and it's gone. What
gates the sensitive verbs (`reveal`, `allow`, the first push to a new
destination, `delete`) is **Windows Hello**: a real fingerprint/PIN prompt,
a separate OS-level surface from this process's console, so an agent can
trigger the request but only a physically present human with an enrolled
credential can satisfy it — no typing required on either side. See
[Windows Hello approval](#windows-hello-approval) below. `set` is the one
exception that's still human-only, and for a structurally different reason:
it's data entry (typing the actual secret value in), not a yes/no decision,
and no biometric prompt can substitute for that.

## Threat model — what this actually stops, and what it doesn't

Be precise about the boundary, because it's easy to overstate: **Windows
Hello gates secretctl's own code path, not the encrypted data itself.**
`vault.json` is protected by DPAPI, bound to this Windows user + machine —
that's the actual security boundary. Any process running as this user can
decrypt it directly (`ConvertTo-SecureString` / `Marshal.SecureStringToBSTR`,
the same two calls this script uses) without ever going through
`secretctl.ps1` or triggering a single Hello prompt. A compromised
dependency, a malicious postinstall script, another agent, anything with
local code execution as this account, bypasses every verb-level gate here
completely — because the gate is a property of *this script's* code path,
not of the ciphertext.

What that means concretely: this tool's actual, tested guarantee is that a
**well-behaved agent calling secretctl as documented** never has plaintext
land in its own context — through generation, capture, push, or run,
including through a downstream error message. That is a real, load-bearing
property and it holds up. It does **not** defend against a machine already
compromised at the level of "arbitrary code running as you" — at that point
the actual protection is DPAPI plus the strength of the Windows account
itself, not anything secretctl adds on top. Treat every Windows Hello gate
in this tool as raising the bar for a well-intentioned caller doing the
wrong thing, not as a barrier against a genuinely hostile one with local
code execution.

A few more limits worth being explicit about, so they don't read as implied
guarantees:

- **`run`'s output redaction is a literal string-replace** against the exact
  plaintext plus a couple of known transforms (URL-encoded, base64). It
  reliably catches a value echoed back verbatim or in one of those forms —
  it does not catch hex, truncation, case changes, or a child process
  writing the value to a file or over the network instead of printing it.
  It's a good last-ditch net for the "printed back in an error" case it was
  built for, not a general guarantee about what a downstream command does
  with the value it's handed.
- **No sandboxing of what `run`/`capture` invoke.** Once a value is set in a
  child process's environment, that process (and anything it spawns) has
  full access to it with no restriction on where it's sent. secretctl trusts
  the command line it's given completely; there's no allowlist of "safe"
  destination binaries, and building one would be a materially different,
  much larger project than this tool.
- **The audit log proves tampering, it doesn't prevent extraction.** The
  hash chain (`audit-verify`) detects retroactive edits or deletions to its
  own history, but it lives in the same user-writable location as
  everything else, has no external anchor, and by design never records
  values — if the vault itself were ever exfiltrated, the audit log
  wouldn't say which secrets were in it.
- **In-memory plaintext residue is an accepted risk, not a solved one.**
  `Unprotect-Value` zeroes the BSTR it marshals, but the plaintext also
  exists as ordinary `System.String` values elsewhere in the same functions
  for their lifetime. Setting a variable to `$null` drops the reference, not
  the heap bytes — a memory dump of `pwsh.exe` taken during or shortly after
  an operation could recover it. High bar to exploit, but real.
- **Windows Hello's own failure modes are real.** No enrollment on a given
  machine means every Hello-gated verb falls back to typed console
  confirmation (still human-only, so an agent's call still fails closed —
  see [above](#windows-hello-approval)), but the effective strength of
  `reveal`/`delete`/`allow`/new-target-push depends on Hello staying
  configured. And Hello proves a human with enrolled biometrics tapped yes —
  it doesn't prove they understood what they approved; nothing here defends
  against approval fatigue if requests were ever spammed (which is exactly
  why the agent guidance above says not to spam them).

## How it works

- **Vault**: `%LOCALAPPDATA%\secretctl\vault.json`. Values are encrypted at
  rest with Windows DPAPI (`ConvertTo-SecureString` / `ConvertFrom-SecureString`,
  no explicit key), which ties decryption to this Windows user account and
  machine. Copying the file elsewhere does not help an attacker decrypt it.
- **Audit log**: `%LOCALAPPDATA%\secretctl\audit.log` — append-only,
  hash-chained JSON lines recording verb, secret name, target, and timestamp
  (never values). Each entry's hash covers the previous entry's hash, so
  editing or deleting a past line breaks the chain; `secretctl audit-verify`
  walks the whole log and reports the first broken link.
- **Destination allow-list**: a secret can only be pushed to a target it has
  already been pushed to, or one approved via `secretctl allow` or a Windows
  Hello prompt triggered by the first push to a new target. This is what
  stops a manipulated or mistaken agent instruction from silently redirecting
  a real secret to an unintended destination; it doesn't require re-approval
  for routine, already-established automation.
- **Vault directory permissions**: the vault directory's ACL is reset to grant
  only the current user (by SID) and SYSTEM, removing any broader inherited
  access. This is defense in depth — DPAPI encryption is what actually
  protects the values even if another local account could read the file.
- **Generation**: secrets are produced with a CSPRNG
  (`RandomNumberGenerator`), never by asking a language model to invent
  entropy.
- **Capture**: `secretctl capture -Name X -- gh auth token` runs another
  CLI as a subprocess and stores its stdout directly into the vault. The
  wrapper never echoes that output to its own stdout — the calling agent
  only ever sees the masked preview.
- **Push**: `secretctl push -Name X -Target ...` decrypts internally and
  pipes the value straight into the destination CLI's **stdin** (`gh secret
  set`, `vercel env add`) or writes a file line directly — never as a CLI
  argument, since process arguments are visible to other local processes
  (Task Manager, WMI, `ps`).
- **Run**: `secretctl run -Name X -- <command>` injects the decrypted value
  into that one child process's environment, then scans the child's combined
  stdout/stderr and replaces every literal occurrence of the value — plus a
  URL-encoded and base64-encoded rendering of it — with `[REDACTED]` before
  printing it. This covers the case a plain env-var injection doesn't: a
  subprocess that echoes the secret back in an error message (a
  malformed-connection-string exception, a verbose driver log) never
  actually leaks it to whatever is reading the command's output. See
  [Threat model](#threat-model--what-this-actually-stops-and-what-it-doesnt)
  for what this redaction does and doesn't cover.

## A fundamental argument-passing bug, and why every invocation is now encoded

An independent review of this codebase surfaced a real, reproducible bug:
passing a downstream argument shaped like `-word:word` (e.g.
`-storepass:env`, a genuine Java `keytool` convention for keeping a
password out of argv by naming an environment variable instead) through
`run`/`capture` got silently corrupted — split into two separate arguments
— defeating the exact guarantee those verbs exist to provide. Someone hit
this for real generating an Android keystore and had to work around it by
putting the plaintext directly in a downstream process's argv instead,
exactly the exposure this tool exists to prevent.

Traced to the actual root cause rather than patched around the symptom:
**`pwsh.exe`'s own startup command-line parser** silently splits any
argument shaped like `-word:word` into two arguments, before
`secretctl.ps1` — or any script it invokes — ever runs a single line of
code. Confirmed directly with a minimal one-argument reproduction
independent of anything in this codebase: `pwsh.exe -File script.ps1
-storepass:env` hands the script `@("-storepass", "env")`, not
`@("-storepass:env")`. Since secretctl.ps1 is always launched as a brand
new `pwsh.exe` process (via the shims), this corrupted its own top-level
argument list for any command line containing that shape, anywhere in it —
not something any internal rewrite of this script's own argument-parsing
logic could have caught, since the damage is done before the script starts.

The fix had to happen at the process-launch boundary: no raw argument is
put on `pwsh.exe`'s command line at all anymore. The `secretctl` (bash) shim
now base64-encodes every argument and hands them to `secretctl.ps1` via an
environment variable (`SECRETCTL_ENCODED_ARGS`) instead of argv — env vars
aren't subject to this parsing bug — and `secretctl.ps1` decodes them back
into the real argument list as the very first thing it does. Verified via
direct reproduction before and after: the exact `-storepass:env` case now
survives intact end-to-end through a real downstream process, confirmed via
a genuine non-PowerShell target so the test wasn't just re-triggering the
same `pwsh.exe` parsing bug at a different layer.

`secretctl.cmd` (the native Windows shim, for bare `secretctl` from
PowerShell/cmd) has this same underlying exposure and is not yet fixed the
same way — CMD batch has no native base64 encoding to build an equivalent
fix from. If you need to pass a `-word:word`-shaped argument through `run`
from a native PowerShell session, call `secretctl.ps1` directly via the
call operator (`& C:\path\secretctl.ps1 run ...`) from inside an already-running
PowerShell 7 session instead of the bare `secretctl` command — that path
doesn't spawn a new `pwsh.exe` process with raw argv, so it isn't subject to
this bug at all.

## Windows Hello approval

Five things require approval before they happen: **`reveal`**, **`allow`**,
the **first push to a target a secret hasn't used before**, **`delete`**
(unless `-Force`), and **`rotate -RepushAll`** (as one aggregate approval
covering the whole redistribution, separate from each target's own standing
grant — see [below](#rotate--repushall-gets-its-own-approval) for why).
Approval works the same way for all five:

1. secretctl calls `Windows.Security.Credentials.UI.UserConsentVerifier`
   (via a disposable Windows PowerShell 5.1 subprocess — pwsh 7 can't
   resolve WinRT types directly) and asks for verification, with a message
   naming exactly what's being approved (e.g. *"secretctl: approve pushing
   'DATABASE_URL' to new destination 'github:acme/api'?"*).
2. Windows shows its native Hello prompt — fingerprint, face, or PIN,
   whichever you've enrolled — **regardless of whether the process that
   triggered it is interactive**. This is the load-bearing property: an
   agent's tool call runs with redirected/null stdin, so it can never answer
   a console prompt, but Hello isn't a console prompt — it's a separate
   OS-level surface tied to hardware-backed credentials, so the agent can
   *trigger* the request without being able to *satisfy* it.
3. Only an explicit `Verified` result approves the action. Denied, canceled,
   timed out, or any other outcome refuses it outright — there's no retry
   with a weaker method.
4. If Windows Hello isn't configured on this machine at all,
   `CheckAvailabilityAsync` reports that up front and secretctl falls back
   to the original typed-confirmation gate (type the secret's name back) —
   which still only works for a genuinely interactive human, so an agent's
   call still fails closed even without Hello available.

**`reveal` specifically** also had to change *how* it delivers the value.
Windows Hello proves a human is present, but it doesn't create a channel for
delivering a value that bypasses the calling process's own output stream —
and that output stream is exactly what an agent's tool call reads back into
its own context. So `reveal` copies the value to the **clipboard** instead
of printing it, and starts a detached background process that clears the
clipboard after 45 seconds *if it still contains that same value* (compared
by hash, so something else you copied in the meantime isn't wiped).
secretctl's own output after a successful `reveal` is only ever a status
line — the value never appears in anything an agent reads.

`set` does not go through this — see above for why.

**Getting the prompt to actually appear in front of you** turned out to need
its own fix. Reported in practice: the Hello prompt would appear minimized
in the background instead of popping to the front, so it was easy to
trigger a request and never notice it was waiting. The first fix attempt
(force this process's own console window to the foreground before asking)
didn't apply here — `GetConsoleWindow()` returns zero in this execution
context, confirmed by direct testing, meaning there's no window of ours to
force in the first place. The actual fix: snapshot every visible top-level
window before calling `RequestVerificationAsync`, then poll briefly for
whatever *new* window appears once the request is issued (found to be
titled "Windows Security", though the code doesn't hardcode that — it
detects it as a diff, robust to the exact title changing across Windows
versions) and force that one to the foreground and flash it. Verified live,
twice, including once with a fullscreen video playing over everything else
on screen — the prompt still came to the front both times.

This diffing approach has a known, accepted limitation: it's racy by
construction. If some unrelated window (a notification, another app
launching) happens to appear as a "new" top-level window in the same
roughly-4.5-second polling span, it could get forced to the foreground
instead of the real dialog. When multiple new windows appear, secretctl
prefers one actually titled "Windows Security" over forcing all of them
indiscriminately — narrows the race, doesn't eliminate it — falling back to
forcing every new window only if none match that title, so this still
works if a future Windows version renames the dialog.

### `rotate -RepushAll` gets its own approval

Each individual push inside `rotate -RepushAll` passes the destination
allow-list silently, since those targets were already approved
individually in the past — by design, so routine automation doesn't
re-prompt per target every time. But redistributing a freshly rotated value
to *every* one of them in a single call is a categorically bigger action
than any one push: if an agent were ever misdirected into rotating the
wrong secret, this is the moment that would silently overwrite it
everywhere the old value went, all at once. That aggregate step gets its
own Hello approval, naming every destination about to receive the new
value, on top of (not instead of) each target's own standing grant.


## Generating Cloudflare API tokens

`cf-create-token` mints a new, narrowly-scoped Cloudflare API token via
Cloudflare's own REST API (`POST /user/tokens`) and stores the result
directly in the vault — an agent never sees the value, same as everything
else here. But minting a token requires *another* token with permission to
create tokens, so there's a one-time human bootstrap step that can't be
automated away (the same category as `wrangler login`/`gh auth login`
elsewhere in this repo):

1. In the Cloudflare dashboard → My Profile → API Tokens → Create Token →
   Custom Token, grant only **User → API Tokens → Edit**. This is
   deliberately narrower than the Global API Key (which Cloudflare itself
   discourages) — it can create/edit/delete tokens and nothing else.
2. Capture it once: `secretctl set -Name CF_TOKEN_BOOTSTRAP`.
3. From then on, minting any new scoped token is a blind CLI command. Look
   up the exact permission group IDs first — don't guess at them, Cloudflare's
   taxonomy isn't guaranteed stable:
   ```
   secretctl cf-list-permission-groups -BootstrapName CF_TOKEN_BOOTSTRAP -AccountId <account-id>
   ```
4. Build a policy from the IDs that came back and create the token:
   ```
   secretctl cf-create-token -Name MY_PROJECT_CF_TOKEN -BootstrapName CF_TOKEN_BOOTSTRAP -TokenName "my-project-ci" -PolicyJson '[{"effect":"allow","resources":{"com.cloudflare.api.account.<account-id>":"*"},"permission_groups":[{"id":"<id-from-step-3>"}]}]'
   ```

The bootstrap token itself is just another vault entry — it's protected the
same way as everything else (DPAPI, audit-logged, Windows Hello gates
`reveal`/`delete` on it same as any secret).

## Finding secrets already sitting in plaintext environment variables

It's common for people to paste an API key or connection string into a
User or System environment variable years ago and forget about it. `scan-env`
finds those candidates without ever exposing a value — the fundamental
split this needs is: an agent (or human) can safely look at variable
*names*, but must never look at *values* to decide what's worth vaulting.

```
secretctl scan-env -Scope Both
```

lists every User/Machine environment variable with its length and a
name-based heuristic flag (`KEY`, `SECRET`, `TOKEN`, `PASSWORD`, `URI`,
`URL`, etc.) — never the value. The heuristic is a starting point, not a
verdict: it can both miss real secrets with unusual names and flag
harmless ones (a `DOCS_URL` matches `URL` too). A live scan on the machine
this was built on immediately found five real, forgotten credentials
sitting in plaintext `User` variables (Mongo/Redis connection strings, two
API keys) that had never been through this vault.

To vault a candidate blind, no new command is needed — `capture` already
does this generically:

```
secretctl capture -Name MONGODB_URI -- pwsh -NoProfile -Command "[Environment]::GetEnvironmentVariable('MONGODB_URI','User')"
```

Then, once it's safely in the vault, clean up the now-duplicated plaintext
original:

```
secretctl clear-env -EnvVar MONGODB_URI -Scope User
```

`clear-env` accepts multiple `-EnvVar` flags for exactly one Windows Hello
prompt covering the whole batch — cleaning up several forgotten secrets at
once shouldn't cost one physical tap per name:

```
secretctl clear-env -EnvVar MONGODB_URI -EnvVar REDIS_URI -EnvVar RENDER_API_KEY -Scope User
```

`clear-env` is Windows Hello-gated like `delete`/`reveal`/`allow` — removing
a variable other tools might depend on is exactly the kind of action that
deserves a human's physical approval, not a plain agent decision. It also
deletes the registry value outright rather than blanking it: `[Environment]
::SetEnvironmentVariable($name, $null, 'User')` was tried first and
confirmed (by testing, not assumption) to leave an empty-string value
behind instead of actually removing it — fixed by going straight to
`HKCU:\Environment` / `HKLM:\...\Session Manager\Environment`. Either way,
already-running processes keep their existing copy in memory until
restarted, same as any Windows environment variable change.

### Scanning a remote machine over SSH

The same scan works against a remote host's environment and specific config
files, for importing secrets that only ever lived on a server (a VM's
service `.env` file, say) into this local vault:

```
secretctl scan-env -Via ssh:oracle-vm -Files "/opt/hermes/state/.env"
```

This runs `bash -lc env` on the remote host (a login shell, so it catches
vars exported from `.bashrc`/`.profile`, not just a bare non-interactive
shell's sparse environment) plus a `grep` for key names in each `-Files`
path given — names and lengths only, same rule as the local scan. To vault
one, `capture` again needs no new mechanism:

```
secretctl capture -Name HERMES_GITHUB_TOKEN -- ssh oracle-vm "grep '^GITHUB_TOKEN=' /opt/hermes/state/.env | cut -d= -f2- | sed 's/\r$//'"
```

**Watch for Git Bash's automatic path mangling** if driving this from a
POSIX shell on Windows: a `-Files` value starting with `/` (a real remote
path) gets silently rewritten into a local Windows path before it ever
reaches PowerShell, unless you set `MSYS_NO_PATHCONV=1` first. Confirmed the
hard way — the scan just came back empty, no error, because the remote
`grep` was quietly searching for a mangled path that doesn't exist on the
remote host at all.

Nothing about `-Via ssh:` touches the remote machine beyond a read - it
doesn't remove or modify anything there. `clear-env` remains local-only
(`-Scope User|Machine`, both Windows registry scopes) on purpose: a
variable on your own machine you've forgotten about is very different from
one a live remote service is actively reading from a config file — deleting
the latter risks breaking a running system, so that step is left to you to
do deliberately on the VM itself, not something this tool automates.

## Usage

```
secretctl generate    -Name <n> [-Length 32] [-Charset alnum|hex|base64url|numeric] [-Force]
secretctl capture     -Name <n> [-Force] -- <command> [args...]
secretctl set         -Name <n> [-Force]                      (human types the value - no approval prompt applies)
secretctl import-file -Name <n> -Path <file> [-Delete] [-Force]
secretctl cf-list-permission-groups -BootstrapName <vaultName> [-AccountId <id>]
secretctl cf-create-token -Name <n> -BootstrapName <vaultName> [-TokenName <cf-name>] (-PolicyJson <json> | -PolicyFile <path>) [-Force]
secretctl list
secretctl scan-env     [-Scope User|Machine|Both] [-Pattern <regex>] [-Via ssh:<host> [-Files <path1,path2,...>]]
secretctl clear-env    -EnvVar <name> [-EnvVar <name> ...] -Scope User|Machine   (Windows Hello approval)
secretctl push        -Name <n> -Target github:owner/repo|vercel[:project]|wrangler:worker-name|file:<path>
                       [-EnvName NAME] [-RepoEnv env] [-VercelEnv production|preview|development] [-Project name] [-Cwd dir]
secretctl run          [-Name <n> [-As ENV_VAR]] [-Env ENV_VAR=VaultName ...] -- <command> [args...]
secretctl rotate      -Name <n> [-RepushAll]
secretctl delete      -Name <n> [-Force]                      (Windows Hello approval, or -Force to skip)
secretctl reveal      -Name <n>                                (Windows Hello approval; copies to clipboard, never printed)
secretctl allow       -Name <n> -Target <target-spec>          (Windows Hello approval)
secretctl audit-verify
```

### Example: generate a secret and push it to GitHub Actions and Vercel

```
secretctl generate -Name STRIPE_WEBHOOK_SECRET -Length 32 -Charset hex
secretctl push -Name STRIPE_WEBHOOK_SECRET -Target github:acme/api -EnvName STRIPE_WEBHOOK_SECRET
secretctl push -Name STRIPE_WEBHOOK_SECRET -Target vercel:acme-api -VercelEnv production -EnvName STRIPE_WEBHOOK_SECRET
```

At no point does the value appear in either command's output.

### Example: push a secret to a Cloudflare Worker

```
secretctl push -Name GATEWAY_SHARED_SECRET -Target wrangler:forge-gateway
```

Pipes the value into `wrangler secret put`'s stdin, same pattern as the
other targets. `wrangler`'s non-interactive mode silently answers "yes" to
its own "there's no Worker called X, create one?" prompt, so a typo'd
worker name would otherwise create a brand-new empty Worker instead of
failing loudly (confirmed the hard way while building this) — `push`
checks the Worker already exists first and refuses if it doesn't.

### Example: capture a token another CLI already generated

```
secretctl capture -Name GH_TOKEN -- gh auth token
secretctl push -Name GH_TOKEN -Target file:.env -EnvName GH_TOKEN
```

### Example: run a migration against a write-only ("Sensitive") Vercel var

A Vercel env var marked Sensitive is write-only forever — no dashboard reveal,
no `vercel env pull`, no API call ever returns it again, by design. Get it
from the actual issuer once, then always run against it blind:

```
secretctl capture -Name DATABASE_URL -- neon connection-string
secretctl run -Name DATABASE_URL -- npm run db:migrate
```

Neither command ever prints the connection string — not on success, and not
if the migration tool's own error handling tries to echo the value it was
given.

## Install

Copy `secretctl.ps1`, `secretctl.cmd`, and `secretctl` onto your `PATH`
(they must sit in the same directory as each other). Requires PowerShell 7+
(`pwsh`) — not Windows PowerShell 5.1, which lacks features the script
depends on (`ConvertFrom-Json -AsHashtable`, `RandomNumberGenerator.Fill`).

## Guidance for agents

- Call whatever verb the task actually needs, including `reveal`, `allow`,
  and `delete` — they're gated by a Windows Hello prompt the user has to
  physically approve, not by whether you're allowed to ask. Asking is fine;
  the gate is the point, not something to route around by finding a verb
  that skips it.
- Never attempt to supply a value to `set` on the user's behalf — it exists
  specifically for a human to type a value you don't and shouldn't know.
  There's no approval flow that substitutes for this; if a task needs it,
  tell the user to run `secretctl set -Name X` themselves.
- If a task needs a secret's plaintext to exist somewhere (a `.env` file, a
  cloud provider's secret store), use `generate` / `capture` / `import-file`
  followed by `push` — you never need to see the value to do this.
- Don't spam approval requests. Each Windows Hello prompt interrupts the
  user physically; batch what you can (e.g. `rotate -RepushAll` re-pushes to
  every already-approved target in one call instead of one `push` per
  target), and don't retry a declined/timed-out request without a good
  reason to think the user's answer would change.
- Before `cf-create-token`, always run `cf-list-permission-groups` against
  the actual account first — don't construct a policy from remembered or
  guessed permission group IDs. Cloudflare's IDs are account/product-specific
  and not something to hardcode from training data or a past project.

## Known limitations

- The vault is intentionally machine- and account-bound; it does not survive
  a profile migration or move to another machine. This is a local secret
  broker, not a portable or shared vault.
- `push -Target file:<path>` writes real plaintext to that file, same as any
  `.env` file would — `secretctl` does not protect a secret once it has been
  deliberately placed at a destination.
- In-process plaintext (briefly held as a .NET string while pushing or
  generating) cannot be reliably zeroed from memory. Accepted residual risk
  for a local tool; not a vector by which an agent can read the value.
- Windows Hello approval requires an interactive desktop session (it's a GUI
  prompt) and Windows PowerShell 5.1 to still be present on the machine
  alongside pwsh 7 (used only for the WinRT interop call). Without either,
  approval falls back to typed console confirmation, which only works for a
  genuinely interactive human — an agent's call still fails closed either way.
- `reveal`'s clipboard delivery means the value briefly sits in the OS
  clipboard, readable by anything else running as this user that polls the
  clipboard, for up to 45 seconds (or until overwritten). This is the
  accepted tradeoff for making `reveal` agent-triggerable without ever
  putting the value in an agent-readable output stream.
- Backup/sync tools could in principle carry the encrypted vault file off
  this machine. Checked directly on the machine this was built on:
  `%LOCALAPPDATA%` (where the vault lives) is not under this account's
  OneDrive folder, so it isn't swept up by OneDrive sync here — but this
  isn't guaranteed on every machine, and DPAPI decryption stays bound to
  this exact user + machine regardless, so a copy of the file alone doesn't
  help an attacker decrypt it.
- `secretctl.cmd` (the native Windows shim) has the same `pwsh.exe`
  argv-corruption exposure described in
  [the section above](#a-fundamental-argument-passing-bug-and-why-every-invocation-is-now-encoded)
  and isn't fixed the same way yet — only the bash shim's fix has an
  equivalent in place.
