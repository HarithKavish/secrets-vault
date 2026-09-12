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
success/failure line. Two subcommands are the deliberate exception —
`set` and `reveal` — and both hard-refuse the moment they detect
non-interactive or redirected input, which is always true when an agent
calls them. They exist purely for a human to run themselves, in their own
terminal.

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
  already been pushed to, or one approved via `secretctl allow`. The first
  push to any new target always requires an interactive human to confirm it —
  it fails closed exactly like `reveal`/`set` for a non-interactive caller —
  then that target is remembered for that secret going forward. This is what
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

## Usage

```
secretctl generate    -Name <n> [-Length 32] [-Charset alnum|hex|base64url|numeric] [-Force]
secretctl capture     -Name <n> [-Force] -- <command> [args...]
secretctl set         -Name <n> [-Force]                      (interactive humans only)
secretctl import-file -Name <n> -Path <file> [-Delete] [-Force]
secretctl list
secretctl push        -Name <n> -Target github:owner/repo|vercel[:project]|file:<path>
                       [-EnvName NAME] [-RepoEnv env] [-VercelEnv production|preview|development] [-Project name]
secretctl run          [-Name <n> [-As ENV_VAR]] [-Env ENV_VAR=VaultName ...] -- <command> [args...]
secretctl rotate      -Name <n> [-RepushAll]
secretctl delete      -Name <n> [-Force]
secretctl reveal      -Name <n>                                (interactive humans only)
secretctl allow       -Name <n> -Target <target-spec>          (interactive humans only)
secretctl audit-verify
```

### Example: generate a secret and push it to GitHub Actions and Vercel

```
secretctl generate -Name STRIPE_WEBHOOK_SECRET -Length 32 -Charset hex
secretctl push -Name STRIPE_WEBHOOK_SECRET -Target github:acme/api -EnvName STRIPE_WEBHOOK_SECRET
secretctl push -Name STRIPE_WEBHOOK_SECRET -Target vercel:acme-api -VercelEnv production -EnvName STRIPE_WEBHOOK_SECRET
```

At no point does the value appear in either command's output.

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

- Never call `reveal`, and never attempt to supply a value to `set` on a
  user's behalf — both are designed to fail closed for you, by design.
- If a task needs a secret's plaintext to exist somewhere (a `.env` file, a
  cloud provider's secret store), use `generate` / `capture` / `import-file`
  followed by `push`. If manual entry or a human actually looking at a value
  is genuinely required, tell the user to run `set` or `reveal` themselves.

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
