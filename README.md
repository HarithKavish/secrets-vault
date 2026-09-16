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
  stdout/stderr and replaces every literal occurrence of the value with
  `[REDACTED]` before printing it. This covers the case a plain env-var
  injection doesn't: a subprocess that echoes the secret back in an error
  message (a malformed-connection-string exception, a verbose driver log)
  never actually leaks it to whatever is reading the command's output.

## Windows Hello approval

Four things require approval before they happen: **`reveal`**, **`allow`**,
the **first push to a target a secret hasn't used before**, and **`delete`**
(unless `-Force`). Approval works the same way for all four:

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

## Usage

```
secretctl generate    -Name <n> [-Length 32] [-Charset alnum|hex|base64url|numeric] [-Force]
secretctl capture     -Name <n> [-Force] -- <command> [args...]
secretctl set         -Name <n> [-Force]                      (human types the value - no approval prompt applies)
secretctl import-file -Name <n> -Path <file> [-Delete] [-Force]
secretctl cf-list-permission-groups -BootstrapName <vaultName> [-AccountId <id>]
secretctl cf-create-token -Name <n> -BootstrapName <vaultName> [-TokenName <cf-name>] (-PolicyJson <json> | -PolicyFile <path>) [-Force]
secretctl list
secretctl scan-env     [-Scope User|Machine|Both] [-Pattern <regex>]
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
