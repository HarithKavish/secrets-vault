#Requires -Version 7.0
<#
secretctl - local blind secret broker.

Design rule this whole script exists to enforce: plaintext secret bytes must
never be written to this script's own stdout/stderr, never passed as a CLI
argument (visible in process listings), and never written to a file that
isn't the encrypted vault. Every subcommand emits only masked previews,
metadata, or success/failure - including 'reveal', which delivers the value
via the clipboard rather than printing it, specifically so it stays
agent-triggerable without ever entering a calling agent's own output stream.

Every agent (this Windows user's CLIs included) can freely call every verb -
generate, capture, push, run, rotate, delete, allow, reveal. Nothing is
gated by "is this caller a human typing in a terminal." What gates the
sensitive verbs (reveal, allow, a push to a not-yet-approved destination,
delete) is Windows Hello: a real fingerprint/PIN prompt via
Windows.Security.Credentials.UI.UserConsentVerifier, a separate OS-level
surface from this process's own console, so it pops up and can only be
satisfied by whoever is physically at the machine - regardless of whether
the request that triggered it came from a redirected, non-interactive agent
call. If Windows Hello isn't set up on this machine, those verbs fall back
to the original typed-confirmation gate, which still only works for a
genuinely interactive human. See README.md for the full model and why each
piece is shaped the way it is.

Vault: $env:LOCALAPPDATA\secretctl\vault.json, values encrypted with Windows
DPAPI (ConvertTo/From-SecureString with no -Key) - bound to this Windows user
account + machine. Anything running as this user (any agent CLI included)
can call this tool; nothing off this machine, and no other local user, can
decrypt the vault file even if they copy it.
#>

$ErrorActionPreference = 'Stop'

$VaultDir  = Join-Path $env:LOCALAPPDATA 'secretctl'
$VaultPath = Join-Path $VaultDir 'vault.json'
$AuditPath = Join-Path $VaultDir 'audit.log'

function Lock-VaultAcl([string]$path) {
    try {
        # Grant by SID, never by bare account name: on at least this machine,
        # icacls resolving a bare username (even the exact string from
        # $env:USERNAME / whoami) silently produced a truncated/wrong SID in
        # the resulting ACE - icacls reported success, but the real account
        # lost access to its own vault directory. The SID from the current
        # process's own WindowsIdentity is unambiguous and can't be mis-resolved
        # the same way. *S-1-5-18 is the well-known SYSTEM SID.
        $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $out = icacls $path /inheritance:r /grant:r "*${sid}:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "secretctl: could not tighten permissions on '$path' (icacls exit $LASTEXITCODE): $out. DPAPI (user+machine bound encryption) still protects the secret values regardless."
        }
    } catch {
        Write-Warning "secretctl: could not tighten permissions on '$path': $_. DPAPI (user+machine bound encryption) still protects the secret values regardless."
    }
}

function Ensure-VaultDir {
    if (-not (Test-Path $VaultDir)) { New-Item -ItemType Directory -Path $VaultDir -Force | Out-Null }
    # Applied every time, not just on creation: a directory created before this
    # hardening existed (or one that inherited broader ACLs from a parent, e.g.
    # a sandboxed-tool group with read access to the user profile) would
    # otherwise never get locked down.
    Lock-VaultAcl $VaultDir
    if (-not (Test-Path $VaultPath)) { '{}' | Set-Content -Path $VaultPath -Encoding utf8 -NoNewline }
}

function Load-Vault {
    Ensure-VaultDir
    $raw = Get-Content -Path $VaultPath -Raw
    if ([string]::IsNullOrWhiteSpace($raw)) { return @{} }
    $obj = $raw | ConvertFrom-Json -AsHashtable -Depth 20
    if ($null -eq $obj) { return @{} }
    return $obj
}

function Save-Vault([hashtable]$vault) {
    Ensure-VaultDir
    ($vault | ConvertTo-Json -Depth 20) | Set-Content -Path $VaultPath -Encoding utf8
}

function Get-LastAuditHash {
    if (-not (Test-Path $AuditPath)) { return '0' * 64 }
    $lastLine = Get-Content -Path $AuditPath -Tail 1
    if ([string]::IsNullOrWhiteSpace($lastLine)) { return '0' * 64 }
    $m = [regex]::Match($lastLine, '"hash":"([0-9a-f]{64})"\}$')
    if ($m.Success) { return $m.Groups[1].Value }
    return '0' * 64
}

function Write-Audit([string]$verb, [string]$name, [string]$target = '') {
    Ensure-VaultDir
    $prevHash = Get-LastAuditHash
    $body = [pscustomobject]@{
        time   = (Get-Date).ToUniversalTime().ToString('o')
        verb   = $verb
        name   = $name
        target = $target
        user   = $env:USERNAME
        prev   = $prevHash
    }
    $bodyJson = $body | ConvertTo-Json -Compress
    $hasher = [Security.Cryptography.SHA256]::Create()
    $hashBytes = $hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($prevHash + $bodyJson))
    $hash = -join ($hashBytes | ForEach-Object { $_.ToString('x2') })
    # Splice the hash into the literal bodyJson text rather than reconstructing
    # an object and re-serializing it - PowerShell's JSON cmdlets auto-detect
    # ISO-8601-looking strings (our 'time' field) and reformat them on
    # round-trip (drops a trailing fractional-second zero), which silently
    # changes the exact bytes verification would recompute the hash over.
    # Splicing keeps the hashed text and the persisted text byte-identical.
    $line = $bodyJson.Substring(0, $bodyJson.Length - 1) + ',"hash":"' + $hash + '"}'
    $line | Add-Content -Path $AuditPath -Encoding utf8
}

function Cmd-AuditVerify {
    if (-not (Test-Path $AuditPath)) { Write-Output "(no audit log yet)"; return }
    $lines = Get-Content -Path $AuditPath
    $prevHash = '0' * 64
    $lineNum = 0
    foreach ($line in $lines) {
        $lineNum++
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        # Recompute the hash over the literal stored text, not a reconstructed
        # object - re-serializing a parsed 'time' field would silently reformat
        # it (PowerShell's JSON cmdlets reformat date-like strings on
        # round-trip) and produce a false tamper flag on every line.
        $m = [regex]::Match($line, '^(.*),"hash":"([0-9a-f]{64})"\}$')
        if (-not $m.Success) {
            Write-Error "Audit log line $lineNum is malformed (no trailing hash field) - cannot verify from here on."
        }
        $bodyJson = $m.Groups[1].Value + '}'
        $storedHash = $m.Groups[2].Value
        $parsed = $bodyJson | ConvertFrom-Json -AsHashtable
        if ($parsed.prev -ne $prevHash) {
            Write-Error "Audit log tampering detected at line $lineNum - expected prev hash '$prevHash', found '$($parsed.prev)'. Do not trust entries from here on without investigating."
        }
        $hasher = [Security.Cryptography.SHA256]::Create()
        $hashBytes = $hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($parsed.prev + $bodyJson))
        $recomputed = -join ($hashBytes | ForEach-Object { $_.ToString('x2') })
        if ($recomputed -ne $storedHash) {
            Write-Error "Audit log tampering detected at line $lineNum - entry content does not match its recorded hash."
        }
        $prevHash = $storedHash
    }
    Write-Output "Audit log intact: $lineNum entries, hash chain verified."
}

function Protect-Value([string]$plain) {
    $secure = ConvertTo-SecureString -String $plain -AsPlainText -Force
    return ConvertFrom-SecureString -SecureString $secure
}

function Unprotect-Value([string]$cipher) {
    $secure = ConvertTo-SecureString -String $cipher
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

function Get-Preview([string]$plain) {
    $len = $plain.Length
    if ($len -le 4) { return ('*' * $len) }
    $tail = $plain.Substring($len - 4)
    $stars = [Math]::Min(8, $len - 4)
    return ('*' * $stars) + $tail
}

function New-RandomSecret([int]$Length = 32, [string]$Charset = 'alnum') {
    switch ($Charset) {
        'hex' {
            $bytes = [byte[]]::new([Math]::Ceiling($Length / 2.0))
            [Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
            $hex = -join ($bytes | ForEach-Object { $_.ToString('x2') })
            return $hex.Substring(0, $Length)
        }
        'base64url' {
            $bytes = [byte[]]::new([Math]::Ceiling($Length * 3 / 4.0) + 3)
            [Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
            $b64 = [Convert]::ToBase64String($bytes) -replace '\+', '-' -replace '/', '_' -replace '=', ''
            return $b64.Substring(0, $Length)
        }
        'numeric' { $pool = '0123456789' }
        default   { $pool = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789' }
    }
    $sb = [Text.StringBuilder]::new()
    for ($i = 0; $i -lt $Length; $i++) {
        $idx = [Security.Cryptography.RandomNumberGenerator]::GetInt32(0, $pool.Length)
        [void]$sb.Append($pool[$idx])
    }
    return $sb.ToString()
}

function Get-Named([string[]]$rest, [string]$flag, [string]$default = $null) {
    for ($i = 0; $i -lt $rest.Length; $i++) {
        if ($rest[$i] -eq $flag) {
            if ($i + 1 -lt $rest.Length) { return $rest[$i + 1] }
        }
    }
    return $default
}

function Has-Flag([string[]]$rest, [string]$flag) {
    return ($rest -contains $flag)
}

function Get-AllNamed([string[]]$rest, [string]$flag) {
    $values = @()
    for ($i = 0; $i -lt $rest.Length; $i++) {
        if ($rest[$i] -eq $flag -and $i + 1 -lt $rest.Length) { $values += $rest[$i + 1] }
    }
    return $values
}

function Require-Entry([hashtable]$vault, [string]$Name) {
    if (-not $vault.ContainsKey($Name)) {
        Write-Error "No secret named '$Name' in vault."
    }
}

function Cmd-Generate([string[]]$rest) {
    $Name    = Get-Named $rest '-Name'
    $Length  = [int](Get-Named $rest '-Length' '32')
    $Charset = Get-Named $rest '-Charset' 'alnum'
    $Force   = Has-Flag $rest '-Force'
    if (-not $Name) { Write-Error "Usage: secretctl generate -Name <name> [-Length 32] [-Charset alnum|hex|base64url|numeric] [-Force]" }

    $vault = Load-Vault
    if ($vault.ContainsKey($Name) -and -not $Force) {
        Write-Error "Secret '$Name' already exists. Use -Force to overwrite."
    }

    $plain = New-RandomSecret -Length $Length -Charset $Charset
    $now = (Get-Date).ToUniversalTime().ToString('o')
    $vault[$Name] = @{
        cipher   = (Protect-Value $plain)
        created  = if ($vault.ContainsKey($Name)) { $vault[$Name].created } else { $now }
        updated  = $now
        length   = $plain.Length
        charset  = $Charset
        preview  = Get-Preview $plain
        source   = 'generated'
        pushedTo = @()
        allowedTargets = @()
    }
    Save-Vault $vault
    Write-Audit 'generate' $Name
    $plain = $null
    Write-Output "Generated '$Name' ($Length chars, $Charset). Preview: $((Load-Vault)[$Name].preview)"
}

function Cmd-Capture([string[]]$rest) {
    $Name  = Get-Named $rest '-Name'
    $Force = Has-Flag $rest '-Force'
    $sepIdx = [array]::IndexOf($rest, '--')
    if (-not $Name -or $sepIdx -lt 0 -or $sepIdx -eq $rest.Length - 1) {
        Write-Error "Usage: secretctl capture -Name <name> [-Force] -- <command> [args...]"
    }
    $cmd = $rest[$sepIdx + 1]
    $cmdArgs = @()
    if ($sepIdx + 2 -le $rest.Length - 1) {
        $cmdArgs = @($rest[($sepIdx + 2)..($rest.Length - 1)])
    }

    $vault = Load-Vault
    if ($vault.ContainsKey($Name) -and -not $Force) {
        Write-Error "Secret '$Name' already exists. Use -Force to overwrite."
    }

    $output = & $cmd @cmdArgs
    if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
        Write-Error "Captured command exited with code $LASTEXITCODE; nothing stored."
    }
    $plain = ($output | Out-String).Trim()
    if ([string]::IsNullOrEmpty($plain)) {
        $resolved = Get-Command $cmd -ErrorAction SilentlyContinue | Select-Object -First 1
        $hint = ''
        if ($resolved -and $resolved.Source -and $resolved.Source -notmatch '\.(exe|cmd|bat|ps1)$') {
            $hint = " '$cmd' resolved to '$($resolved.Source)', which has no Windows-executable extension - it may be a POSIX shell shim pwsh can't spawn and capture output from. Try the '.cmd' or '.exe' variant on PATH instead (e.g. '$cmd.cmd')."
        }
        Write-Error "Captured command produced no output; nothing stored.$hint"
    }

    $now = (Get-Date).ToUniversalTime().ToString('o')
    $vault[$Name] = @{
        cipher   = (Protect-Value $plain)
        created  = if ($vault.ContainsKey($Name)) { $vault[$Name].created } else { $now }
        updated  = $now
        length   = $plain.Length
        charset  = 'captured'
        preview  = Get-Preview $plain
        source   = "captured:$cmd"
        pushedTo = @()
        allowedTargets = @()
    }
    Save-Vault $vault
    Write-Audit 'capture' $Name
    $plain = $null
    Write-Output "Captured '$Name' from '$cmd' ($((Load-Vault)[$Name].length) chars). Preview: $((Load-Vault)[$Name].preview)"
}

function Cmd-Set([string[]]$rest) {
    $Name  = Get-Named $rest '-Name'
    $Force = Has-Flag $rest '-Force'
    if (-not $Name) { Write-Error "Usage: secretctl set -Name <name> [-Force]" }
    if ([Console]::IsInputRedirected -or -not [Environment]::UserInteractive) {
        Write-Error "'set' requires an interactive terminal - refusing under redirected/non-interactive input. This is data entry (typing the actual value), not an approval decision, so Windows Hello can't substitute for it the way it does for reveal/allow/delete; a human has to type the value in themselves."
    }
    $vault = Load-Vault
    if ($vault.ContainsKey($Name) -and -not $Force) {
        Write-Error "Secret '$Name' already exists. Use -Force to overwrite."
    }
    $secure = Read-Host -Prompt "Enter value for '$Name'" -AsSecureString
    $plain = Unprotect-Value (ConvertFrom-SecureString $secure)
    if ([string]::IsNullOrEmpty($plain)) { Write-Error "Empty value; nothing stored." }

    $now = (Get-Date).ToUniversalTime().ToString('o')
    $vault[$Name] = @{
        cipher   = (Protect-Value $plain)
        created  = if ($vault.ContainsKey($Name)) { $vault[$Name].created } else { $now }
        updated  = $now
        length   = $plain.Length
        charset  = 'manual'
        preview  = Get-Preview $plain
        source   = 'manual'
        pushedTo = @()
        allowedTargets = @()
    }
    Save-Vault $vault
    Write-Audit 'set' $Name
    $plain = $null
    Write-Output "Stored '$Name' ($((Load-Vault)[$Name].length) chars). Preview: $((Load-Vault)[$Name].preview)"
}

function Cmd-ImportFile([string[]]$rest) {
    $Name   = Get-Named $rest '-Name'
    $Path   = Get-Named $rest '-Path'
    $Force  = Has-Flag $rest '-Force'
    $Delete = Has-Flag $rest '-Delete'
    if (-not $Name -or -not $Path) { Write-Error "Usage: secretctl import-file -Name <name> -Path <file> [-Delete] [-Force]" }
    if (-not (Test-Path $Path)) { Write-Error "File not found: $Path" }

    $vault = Load-Vault
    if ($vault.ContainsKey($Name) -and -not $Force) {
        Write-Error "Secret '$Name' already exists. Use -Force to overwrite."
    }
    $plain = Get-Content -Path $Path -Raw
    if ([string]::IsNullOrEmpty($plain)) { Write-Error "File is empty; nothing stored." }

    $now = (Get-Date).ToUniversalTime().ToString('o')
    $vault[$Name] = @{
        cipher   = (Protect-Value $plain)
        created  = if ($vault.ContainsKey($Name)) { $vault[$Name].created } else { $now }
        updated  = $now
        length   = $plain.Length
        charset  = 'imported'
        preview  = Get-Preview $plain
        source   = "imported-file"
        pushedTo = @()
        allowedTargets = @()
    }
    Save-Vault $vault
    Write-Audit 'import-file' $Name
    $plain = $null
    if ($Delete) { Remove-Item -Path $Path -Force }
    Write-Output "Imported '$Name' from file ($((Load-Vault)[$Name].length) chars)$(if($Delete){' - source file deleted'}). Preview: $((Load-Vault)[$Name].preview)"
}

function Invoke-CloudflareApi([string]$Method, [string]$Path, [string]$BootstrapToken, $Body = $null) {
    $headers = @{ Authorization = "Bearer $BootstrapToken" }
    $uri = "https://api.cloudflare.com/client/v4$Path"
    try {
        if ($null -ne $Body) {
            $resp = Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers -ContentType 'application/json' -Body ($Body | ConvertTo-Json -Depth 10)
        } else {
            $resp = Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers
        }
    } catch {
        $detail = $_.ErrorDetails.Message
        if ($detail) { Write-Error "Cloudflare API request failed: $detail" }
        else { Write-Error "Cloudflare API request failed: $_" }
    }
    if (-not $resp.success) {
        $errMsg = ($resp.errors | ForEach-Object { $_.message }) -join '; '
        Write-Error "Cloudflare API returned an error: $errMsg"
    }
    return $resp.result
}

function Cmd-CfListPermissionGroups([string[]]$rest) {
    $BootstrapName = Get-Named $rest '-BootstrapName'
    $AccountId     = Get-Named $rest '-AccountId'
    if (-not $BootstrapName) {
        Write-Error "Usage: secretctl cf-list-permission-groups -BootstrapName <vaultName> [-AccountId <id>]"
    }
    $vault = Load-Vault
    Require-Entry $vault $BootstrapName
    $token = Unprotect-Value $vault[$BootstrapName].cipher
    try {
        $path = if ($AccountId) { "/accounts/$AccountId/tokens/permission_groups" } else { '/user/tokens/permission_groups' }
        $groups = Invoke-CloudflareApi -Method 'Get' -Path $path -BootstrapToken $token
    } finally {
        $token = $null
    }
    $groups | Select-Object id, name | Sort-Object name | Format-Table -AutoSize | Out-String -Width 200 | Write-Output
}

function Cmd-CfCreateToken([string[]]$rest) {
    $Name          = Get-Named $rest '-Name'
    $BootstrapName = Get-Named $rest '-BootstrapName'
    $TokenName     = Get-Named $rest '-TokenName' $Name
    $PolicyJson    = Get-Named $rest '-PolicyJson'
    $PolicyFile    = Get-Named $rest '-PolicyFile'
    $Force         = Has-Flag $rest '-Force'
    if (-not $Name -or -not $BootstrapName -or (-not $PolicyJson -and -not $PolicyFile)) {
        Write-Error "Usage: secretctl cf-create-token -Name <vaultName> -BootstrapName <bootstrapVaultName> [-TokenName <cf-token-name>] (-PolicyJson <json> | -PolicyFile <path>) [-Force]"
    }

    $vault = Load-Vault
    Require-Entry $vault $BootstrapName
    if ($vault.ContainsKey($Name) -and -not $Force) {
        Write-Error "Secret '$Name' already exists. Use -Force to overwrite."
    }

    $policyText = if ($PolicyFile) { Get-Content -Path $PolicyFile -Raw } else { $PolicyJson }
    $policies = $policyText | ConvertFrom-Json

    $bootstrapToken = Unprotect-Value $vault[$BootstrapName].cipher
    $newTokenValue = $null
    try {
        $body = @{ name = $TokenName; policies = $policies }
        $result = Invoke-CloudflareApi -Method 'Post' -Path '/user/tokens' -BootstrapToken $bootstrapToken -Body $body
        $newTokenValue = $result.value
    } finally {
        $bootstrapToken = $null
    }
    if ([string]::IsNullOrEmpty($newTokenValue)) {
        Write-Error "Cloudflare did not return a token value - the token may still have been created on their side under the name '$TokenName'; check the dashboard before retrying to avoid an orphaned token."
    }

    $now = (Get-Date).ToUniversalTime().ToString('o')
    $vault[$Name] = @{
        cipher         = (Protect-Value $newTokenValue)
        created        = if ($vault.ContainsKey($Name)) { $vault[$Name].created } else { $now }
        updated        = $now
        length         = $newTokenValue.Length
        charset        = 'cloudflare-token'
        preview        = Get-Preview $newTokenValue
        source         = "cf-create-token:$TokenName"
        pushedTo       = @()
        allowedTargets = @()
    }
    Save-Vault $vault
    Write-Audit 'cf-create-token' $Name
    $newTokenValue = $null
    Write-Output "Created Cloudflare API token '$TokenName' and stored as '$Name'. Preview: $((Load-Vault)[$Name].preview)"
}

function Cmd-List([string[]]$rest) {
    $vault = Load-Vault
    if ($vault.Count -eq 0) { Write-Output "(vault is empty)"; return }
    $rows = foreach ($k in ($vault.Keys | Sort-Object)) {
        $e = $vault[$k]
        [pscustomobject]@{
            Name    = $k
            Preview = $e.preview
            Length  = $e.length
            Source  = $e.source
            Updated = $e.updated
            PushedTo = ($e.pushedTo | ForEach-Object { $_.target }) -join '; '
        }
    }
    $rows | Format-Table -AutoSize | Out-String -Width 200 | Write-Output
}

function Cmd-ScanEnv([string[]]$rest) {
    $Scope   = Get-Named $rest '-Scope' 'Both'
    $Pattern = Get-Named $rest '-Pattern'
    $Via     = Get-Named $rest '-Via'
    $Files   = Get-Named $rest '-Files'

    # Heuristic on the NAME only - never the value. Not exhaustive (a secret
    # named oddly won't be flagged) and not proof (e.g. TOKENIZER_PATH would
    # false-positive on TOKEN) - it's a starting point for a human/agent to
    # look at, not a verdict.
    $secretHeuristic = '(KEY|SECRET|TOKEN|PASS(WORD)?|PWD|CREDENTIAL|AUTH|APIKEY|CONN(ECTION)?STR|DSN|CERT|PRIVATE|CLIENT_SECRET|ACCESS_KEY|URI|URL)'
    $rows = @()

    if ($Via -and $Via -match '^ssh:(.+)$') {
        $sshHost = $Matches[1]
        # bash -lc env (a login shell), not a bare non-interactive shell's
        # sparse environment - this is what actually catches vars exported
        # from .bashrc/.bash_profile/.profile.
        $remoteEnv = ssh $sshHost "bash -lc env" 2>$null
        if ($LASTEXITCODE -ne 0) {
            Write-Error "ssh to '$sshHost' failed (exit $LASTEXITCODE). Check the host is reachable and the SSH alias/config is correct."
        }
        foreach ($line in $remoteEnv) {
            $idx = $line.IndexOf('=')
            if ($idx -lt 1) { continue }
            $key = $line.Substring(0, $idx)
            $val = $line.Substring($idx + 1)
            if ($Pattern -and $key -notmatch $Pattern) { continue }
            $rows += [pscustomobject]@{
                Name        = $key
                Scope       = "ssh:$sshHost env"
                Length      = $val.Length
                LooksSecret = if ($key -match $secretHeuristic) { 'YES' } else { '' }
            }
        }

        if ($Files) {
            foreach ($f in ($Files -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
                $kvLines = ssh $sshHost "grep -E '^[A-Za-z_][A-Za-z0-9_]*=' '$f' 2>/dev/null" 2>$null
                foreach ($line in $kvLines) {
                    $idx = $line.IndexOf('=')
                    if ($idx -lt 1) { continue }
                    $key = $line.Substring(0, $idx)
                    $val = $line.Substring($idx + 1)
                    if ($Pattern -and $key -notmatch $Pattern) { continue }
                    $rows += [pscustomobject]@{
                        Name        = $key
                        Scope       = "ssh:${sshHost}:$f"
                        Length      = $val.Length
                        LooksSecret = if ($key -match $secretHeuristic) { 'YES' } else { '' }
                    }
                }
            }
        }
    } else {
        $scopes = switch ($Scope) {
            'User'    { @('User') }
            'Machine' { @('Machine') }
            'Both'    { @('User', 'Machine') }
            default   { Write-Error "Invalid -Scope '$Scope'. Use User, Machine, or Both." }
        }
        foreach ($sc in $scopes) {
            $vars = [Environment]::GetEnvironmentVariables($sc)
            foreach ($key in ($vars.Keys | Sort-Object)) {
                if ($Pattern -and $key -notmatch $Pattern) { continue }
                $val = $vars[$key]
                $rows += [pscustomobject]@{
                    Name        = $key
                    Scope       = $sc
                    Length      = if ($val) { $val.Length } else { 0 }
                    LooksSecret = if ($key -match $secretHeuristic) { 'YES' } else { '' }
                }
            }
        }
    }

    if (@($rows).Count -eq 0) { Write-Output "(no matching environment variables)"; return }
    $rows | Sort-Object @{Expression = 'LooksSecret'; Descending = $true }, Scope, Name |
        Format-Table -AutoSize | Out-String -Width 200 | Write-Output
    Write-Output "Names and lengths only - values are never shown here."
    if ($Via -and $Via -match '^ssh:(.+)$') {
        $sshHost = $Matches[1]
        Write-Output "To vault one blind from the remote environment:"
        Write-Output "  secretctl capture -Name <vaultName> -- ssh $sshHost `"printenv '<VarName>'`""
        Write-Output "To vault one blind from a scanned file:"
        Write-Output "  secretctl capture -Name <vaultName> -- ssh $sshHost `"grep '^<VarName>=' '<file>' | cut -d= -f2-`""
    } else {
        Write-Output "To vault one blind:"
        Write-Output "  secretctl capture -Name <vaultName> -- pwsh -NoProfile -Command `"[Environment]::GetEnvironmentVariable('<VarName>','<Scope>')`""
    }
}

function Cmd-ClearEnvVar([string[]]$rest) {
    $EnvVarNames = @(Get-AllNamed $rest '-EnvVar')
    $Scope       = Get-Named $rest '-Scope'
    if ($EnvVarNames.Count -eq 0 -or $Scope -notin @('User', 'Machine')) {
        Write-Error "Usage: secretctl clear-env -EnvVar <name> [-EnvVar <name> ...] -Scope User|Machine"
    }
    $namesList = $EnvVarNames -join ', '

    # Accepts multiple -EnvVar for exactly one Windows Hello prompt covering
    # the whole batch - each prompt is a real physical interruption, so a
    # cleanup of several variables at once shouldn't cost one tap per name.
    $approved = Request-HumanApproval "secretctl: approve removing $($EnvVarNames.Count) variable(s) from $Scope environment variables: $namesList? (Make sure each is safely captured into the vault first.)"
    if ($approved -eq $false) {
        Write-Error "Not approved (Windows Hello declined, timed out, or is unavailable and this call is non-interactive)."
    }
    if ($null -eq $approved) {
        $confirm = Read-Host "Type 'yes' to confirm removing $($EnvVarNames.Count) variable(s) ($namesList) from $Scope environment variables"
        if ($confirm -ne 'yes') { Write-Error "Confirmation did not match; aborted." }
    }

    # [Environment]::SetEnvironmentVariable($name, $null, scope) does NOT
    # delete the registry value on this system - confirmed by testing: it
    # left an empty string behind instead of removing the value entirely.
    # The secret's content is gone either way, but that's not the same as
    # actually removing the variable, so go straight to the registry.
    $regPath = if ($Scope -eq 'User') { 'HKCU:\Environment' } else { 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' }
    foreach ($name in $EnvVarNames) {
        Remove-ItemProperty -Path $regPath -Name $name -ErrorAction SilentlyContinue
        Write-Audit 'clear-env' $name $Scope
    }
    Write-Output "Removed $($EnvVarNames.Count) variable(s) from $Scope environment variables (registry values deleted): $namesList. Already-running processes (including this shell) keep their existing copies in memory until restarted, and other running apps won't see the change until they restart either - Windows itself works the same way."
}

function Push-ToGithub([string]$plain, [string]$ownerRepo, [string]$envName, [string]$repoEnv) {
    $ghArgs = @('secret', 'set', $envName, '--repo', $ownerRepo)
    if ($repoEnv) { $ghArgs += @('--env', $repoEnv) }
    $plain | gh @ghArgs
    if ($LASTEXITCODE -ne 0) { Write-Error "gh secret set failed with exit code $LASTEXITCODE" }
}

function Push-ToVercel([string]$plain, [string]$project, [string]$vercelEnv, [string]$envName) {
    $vArgs = @('env', 'add', $envName, $vercelEnv, '--force', '--yes')
    if ($project) { $vArgs += @('--project', $project) }
    $plain | vercel @vArgs
    if ($LASTEXITCODE -ne 0) { Write-Error "vercel env add failed with exit code $LASTEXITCODE" }
}

function Push-ToFile([string]$plain, [string]$path, [string]$envName) {
    if ($plain -match "[\r\n]") {
        Write-Error "Refusing to push '$envName' to '$path': the value contains a newline, which would inject extra line(s) - possibly extra bogus KEY=VALUE entries - into the file instead of one clean assignment."
    }
    if ($envName -notmatch '^[A-Za-z_][A-Za-z0-9_]*$') {
        Write-Error "Refusing to push to file: '$envName' is not a safe env-var name (letters/digits/underscore, not starting with a digit)."
    }
    $line = "$envName=$plain"
    if (Test-Path $path) {
        $content = Get-Content -Path $path
        $pattern = "^$([regex]::Escape($envName))="
        $found = $false
        $newContent = foreach ($l in $content) {
            if ($l -match $pattern) { $found = $true; $line } else { $l }
        }
        if (-not $found) { $newContent = @($content) + @($line) }
        Set-Content -Path $path -Value $newContent -Encoding utf8
    } else {
        Set-Content -Path $path -Value @($line) -Encoding utf8
    }
}

function Push-ToWrangler([string]$plain, [string]$workerName, [string]$envName, [string]$cwd) {
    # wrangler's non-interactive fallback silently answers "yes" to its own
    # "there's no Worker called X, create one?" prompt - a typo'd worker name
    # would otherwise create a brand-new empty Worker and push the secret
    # there instead of failing loudly (confirmed: it really did this in
    # testing). Refuse up front unless the named Worker already exists.
    $listArgs = @('secret', 'list', '--name', $workerName)
    if ($cwd) { $listArgs += @('--cwd', $cwd) }
    & wrangler @listArgs *>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Worker '$workerName' does not appear to exist (or wrangler isn't logged into the right account). Refusing to push - wrangler would otherwise silently create a new empty Worker for a typo'd name. Run 'wrangler deploy' first if this is meant to be a new Worker."
    }
    $wArgs = @('secret', 'put', $envName, '--name', $workerName)
    if ($cwd) { $wArgs += @('--cwd', $cwd) }
    $plain | wrangler @wArgs
    if ($LASTEXITCODE -ne 0) { Write-Error "wrangler secret put failed with exit code $LASTEXITCODE" }
}

function Confirm-HumanPresence([string]$message) {
    # secretctl.ps1 runs on pwsh 7, which cannot resolve WinRT types directly
    # ("[Windows.Security.Credentials.UI.UserConsentVerifier,...,ContentType=
    # WindowsRuntime]" only works under Windows PowerShell 5.1's type
    # resolver) - so the actual Windows Hello call is shelled out to
    # powershell.exe as a disposable temp script. $message is passed as a
    # -File parameter, never string-concatenated, so it can't break the
    # nested script regardless of its content.
    $helloScript = @'
param([string]$Message)
try {
    Add-Type -AssemblyName System.Runtime.WindowsRuntime
    [Windows.Security.Credentials.UI.UserConsentVerifier,Windows.Security.Credentials.UI,ContentType=WindowsRuntime] | Out-Null
    $asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
        $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'
    })[0]

    $availOp = [Windows.Security.Credentials.UI.UserConsentVerifier]::CheckAvailabilityAsync()
    $asTaskAvail = $asTaskGeneric.MakeGenericMethod([Windows.Security.Credentials.UI.UserConsentVerifierAvailability])
    $availability = $asTaskAvail.Invoke($null, @($availOp)).GetAwaiter().GetResult()
    if ($availability -ne [Windows.Security.Credentials.UI.UserConsentVerifierAvailability]::Available) {
        Write-Output "UNAVAILABLE:$availability"
        exit 0
    }

    # A background/non-focused process's Windows Hello prompt can end up
    # behind other windows or minimized on the taskbar instead of popping to
    # the front - confirmed as a real, reported problem, not theoretical.
    # Tried forcing this process's own console window to the foreground
    # first, but GetConsoleWindow() returns zero here (this process is
    # launched with no console window at all in this execution context, e.g.
    # via redirected-output process creation) - confirmed by direct testing,
    # so there is no window of ours to force. Instead: snapshot the set of
    # visible top-level windows before requesting verification, then poll
    # briefly for whatever NEW window appears once the request is issued
    # (the dialog itself, whatever it turns out to be titled/classed as) and
    # force that one to the foreground - robust to not knowing the exact
    # title Windows uses for this dialog on a given version.
    Add-Type @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
public class SecretctlWin32 {
    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern int GetWindowTextLength(IntPtr hWnd);
    [DllImport("user32.dll", CharSet = CharSet.Auto)] public static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll")] public static extern bool FlashWindow(IntPtr hWnd, bool bInvert);

    public static List<IntPtr> GetVisibleWindows() {
        var list = new List<IntPtr>();
        EnumWindows((hWnd, lParam) => {
            if (IsWindowVisible(hWnd) && GetWindowTextLength(hWnd) > 0) { list.Add(hWnd); }
            return true;
        }, IntPtr.Zero);
        return list;
    }

    public static string GetTitle(IntPtr hWnd) {
        int len = GetWindowTextLength(hWnd);
        var sb = new StringBuilder(len + 1);
        GetWindowText(hWnd, sb, sb.Capacity);
        return sb.ToString();
    }
}
"@
    $before = [SecretctlWin32]::GetVisibleWindows()

    $reqOp = [Windows.Security.Credentials.UI.UserConsentVerifier]::RequestVerificationAsync($Message)

    $forcedTitles = @()
    for ($i = 0; $i -lt 30; $i++) {
        Start-Sleep -Milliseconds 150
        $after = [SecretctlWin32]::GetVisibleWindows()
        $newWindows = $after | Where-Object { $before -notcontains $_ }
        if ($newWindows.Count -gt 0) {
            foreach ($w in $newWindows) {
                [SecretctlWin32]::ShowWindow($w, 9) | Out-Null   # SW_RESTORE
                [SecretctlWin32]::SetForegroundWindow($w) | Out-Null
                [SecretctlWin32]::FlashWindow($w, $true) | Out-Null
                $forcedTitles += [SecretctlWin32]::GetTitle($w)
            }
            break
        }
    }

    $asTaskResult = $asTaskGeneric.MakeGenericMethod([Windows.Security.Credentials.UI.UserConsentVerificationResult])
    $result = $asTaskResult.Invoke($null, @($reqOp)).GetAwaiter().GetResult()
    Write-Output "RESULT:$result"
    Write-Output "FORCED_WINDOWS:$($forcedTitles -join '|')"
} catch {
    Write-Output "ERROR:$($_.Exception.Message)"
}
'@
    $tmpScript = Join-Path ([IO.Path]::GetTempPath()) "secretctl-hello-$([guid]::NewGuid()).ps1"
    try {
        Set-Content -Path $tmpScript -Value $helloScript -Encoding utf8
        $output = (& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $tmpScript -Message $message 2>&1 | Out-String).Trim()
    } finally {
        Remove-Item -Path $tmpScript -Force -ErrorAction SilentlyContinue
    }

    if ($output -match 'RESULT:Verified') { return @{ ok = $true; reason = 'Verified' } }
    if ($output -match 'RESULT:(\S+)') { return @{ ok = $false; reason = $Matches[1] } }
    if ($output -match 'UNAVAILABLE:(\S+)') { return @{ ok = $false; reason = "unavailable:$($Matches[1])" } }
    return @{ ok = $false; reason = "error:$output" }
}

function Request-HumanApproval([string]$message) {
    # Approval-only gate: no secret value is ever involved in the decision
    # itself (unlike 'reveal', which has to deliver a value somewhere - see
    # Cmd-Reveal for why that one can't just print to stdout once it's
    # agent-triggerable). Safe for an agent to trigger directly: Windows
    # Hello is a separate OS-level GUI/hardware surface from the calling
    # process's console, so it pops up and can only be satisfied by a
    # physically present human with an enrolled fingerprint/PIN, regardless
    # of whether the caller itself is interactive.
    $hello = Confirm-HumanPresence $message
    if ($hello.ok) { return $true }
    if ($hello.reason -like 'unavailable:*') {
        # Windows Hello isn't set up on this machine - fall back to the
        # original typed-confirmation gate, which only works for a genuinely
        # interactive human (still refuses an agent outright).
        if ([Console]::IsInputRedirected -or -not [Environment]::UserInteractive) { return $false }
        return $null  # signals "no verdict; caller should do its own typed fallback"
    }
    # Hello ran and was not Verified (Denied/Canceled/Timeout/DeviceBusy/etc) -
    # respect that explicitly, never silently retry with a weaker method.
    return $false
}

function Assert-TargetAllowed([hashtable]$vault, [string]$Name, [string]$Target) {
    $entry = $vault[$Name]
    # Bracket indexing, not dot-notation: entries created before destination
    # allow-listing existed have no 'allowedTargets' key at all, and under a
    # caller session running Set-StrictMode -Version 2+ (e.g. VS Code's
    # PowerShell Integrated Console), dot-notation on a missing hashtable key
    # throws PropertyNotFoundException instead of returning $null.
    $allowed = @($entry['allowedTargets']) + @($entry['pushedTo'] | ForEach-Object { $_.target })
    $allowed = @($allowed | Where-Object { $_ } | Select-Object -Unique)
    if ($allowed -contains $Target) { return }

    $approved = Request-HumanApproval "secretctl: approve pushing '$Name' to new destination '$Target'?"
    if ($approved -eq $false) {
        Write-Error "Target '$Target' is not approved for '$Name' (Windows Hello declined, timed out, or is unavailable and this call is non-interactive). A human must approve a new destination - via the Windows Hello prompt this triggers, or by running 'secretctl allow -Name $Name -Target $Target' themselves. If an agent asked for a new destination it hasn't used before, don't approve it on its behalf without checking the target is actually intended."
    }
    if ($null -eq $approved) {
        # Windows Hello unavailable on this machine, but a real interactive
        # human is at the console - fall back to the original typed gate.
        $confirm = Read-Host "'$Name' has never been approved for target '$Target'. Type the secret name to approve this destination"
        if ($confirm -ne $Name) { Write-Error "Confirmation did not match; aborted." }
    }

    $allowedList = @($entry['allowedTargets']) + @($Target)
    $entry.allowedTargets = $allowedList
    $vault[$Name] = $entry
    Save-Vault $vault
    Write-Audit 'allow' $Name $Target
}

function Cmd-Allow([string[]]$rest) {
    $Name   = Get-Named $rest '-Name'
    $Target = Get-Named $rest '-Target'
    if (-not $Name -or -not $Target) { Write-Error "Usage: secretctl allow -Name <name> -Target <target-spec>" }
    $vault = Load-Vault
    Require-Entry $vault $Name

    $approved = Request-HumanApproval "secretctl: approve '$Name' being pushed to '$Target'?"
    if ($approved -eq $false) {
        Write-Error "Not approved (Windows Hello declined, timed out, or is unavailable and this call is non-interactive)."
    }
    if ($null -eq $approved) {
        $confirm = Read-Host "Approve '$Name' to be pushed to '$Target'? Type the secret name to confirm"
        if ($confirm -ne $Name) { Write-Error "Confirmation did not match; aborted." }
    }

    $entry = $vault[$Name]
    $allowed = @($entry['allowedTargets'])
    if ($allowed -notcontains $Target) { $allowed += $Target }
    $entry.allowedTargets = $allowed
    $vault[$Name] = $entry
    Save-Vault $vault
    Write-Audit 'allow' $Name $Target
    Write-Output "'$Name' is now approved for target '$Target'."
}

function Cmd-Push([string[]]$rest) {
    $Name      = Get-Named $rest '-Name'
    $Target    = Get-Named $rest '-Target'
    $EnvName   = Get-Named $rest '-EnvName' $Name
    $RepoEnv   = Get-Named $rest '-RepoEnv'
    $VercelEnv = Get-Named $rest '-VercelEnv' 'production'
    $Project   = Get-Named $rest '-Project'
    $Cwd       = Get-Named $rest '-Cwd'

    if (-not $Name -or -not $Target) {
        Write-Error "Usage: secretctl push -Name <name> -Target github:owner/repo|vercel[:project]|wrangler:worker-name|file:<path> [-EnvName NAME] [-RepoEnv env] [-VercelEnv production|preview|development] [-Project name] [-Cwd dir]"
    }

    $vault = Load-Vault
    Require-Entry $vault $Name
    Assert-TargetAllowed -vault $vault -Name $Name -Target $Target
    $vault = Load-Vault
    $plain = Unprotect-Value $vault[$Name].cipher

    $pushRecord = $null
    try {
        if ($Target -match '^github:(.+)$') {
            $ownerRepo = $Matches[1]
            Push-ToGithub -plain $plain -ownerRepo $ownerRepo -envName $EnvName -repoEnv $RepoEnv
            $pushRecord = @{ target = $Target; envName = $EnvName; repoEnv = $RepoEnv }
            $desc = "github:$ownerRepo as $EnvName" + $(if ($RepoEnv) { " (env: $RepoEnv)" } else { " (repo secret)" })
        }
        elseif ($Target -match '^vercel(?::(.+))?$') {
            $proj = if ($Matches[1]) { $Matches[1] } else { $Project }
            Push-ToVercel -plain $plain -project $proj -vercelEnv $VercelEnv -envName $EnvName
            $pushRecord = @{ target = $Target; envName = $EnvName; vercelEnv = $VercelEnv; project = $proj }
            $desc = "vercel" + $(if ($proj) { ":$proj" } else { " (linked project)" }) + " [$VercelEnv] as $EnvName"
        }
        elseif ($Target -match '^wrangler:(.+)$') {
            $workerName = $Matches[1]
            Push-ToWrangler -plain $plain -workerName $workerName -envName $EnvName -cwd $Cwd
            $pushRecord = @{ target = $Target; envName = $EnvName; cwd = $Cwd }
            $desc = "wrangler:$workerName as $EnvName"
        }
        elseif ($Target -match '^file:(.+)$') {
            $path = $Matches[1]
            Push-ToFile -plain $plain -path $path -envName $EnvName
            $pushRecord = @{ target = $Target; envName = $EnvName }
            $desc = "file:$path as $EnvName"
        }
        else {
            Write-Error "Unrecognized -Target '$Target'. Use github:owner/repo, vercel[:project], wrangler:worker-name, or file:<path>."
        }
    }
    finally {
        $plain = $null
    }

    $existing = @($vault[$Name].pushedTo)
    $vault[$Name].pushedTo = $existing + $pushRecord
    Save-Vault $vault
    Write-Audit 'push' $Name $Target
    Write-Output "Pushed '$Name' -> $desc. Value not displayed."
}

function Cmd-Rotate([string[]]$rest) {
    $Name       = Get-Named $rest '-Name'
    $RepushAll  = Has-Flag $rest '-RepushAll'
    if (-not $Name) { Write-Error "Usage: secretctl rotate -Name <name> [-RepushAll]" }

    $vault = Load-Vault
    Require-Entry $vault $Name
    $entry = $vault[$Name]
    $length = if ($entry.length) { $entry.length } else { 32 }
    $charset = if ($entry.charset -and $entry.charset -notin @('manual', 'captured', 'imported')) { $entry.charset } else { 'alnum' }

    $plain = New-RandomSecret -Length $length -Charset $charset
    $now = (Get-Date).ToUniversalTime().ToString('o')
    $entry.cipher = Protect-Value $plain
    $entry.updated = $now
    $entry.preview = Get-Preview $plain
    $entry.source = 'rotated'
    $vault[$Name] = $entry
    Save-Vault $vault
    Write-Audit 'rotate' $Name
    Write-Output "Rotated '$Name'. Preview: $($entry.preview)"

    if ($RepushAll -and $entry.pushedTo) {
        foreach ($p in $entry.pushedTo) {
            $pushArgs = @('-Name', $Name, '-Target', $p.target)
            if ($p.envName)   { $pushArgs += @('-EnvName', $p.envName) }
            if ($p.repoEnv)   { $pushArgs += @('-RepoEnv', $p.repoEnv) }
            if ($p.vercelEnv) { $pushArgs += @('-VercelEnv', $p.vercelEnv) }
            if ($p.project)   { $pushArgs += @('-Project', $p.project) }
            if ($p.cwd)       { $pushArgs += @('-Cwd', $p.cwd) }
            Cmd-Push $pushArgs
        }
    }
    $plain = $null
}

function Cmd-Run([string[]]$rest) {
    $sepIdx = [array]::IndexOf($rest, '--')
    if ($sepIdx -lt 0 -or $sepIdx -eq $rest.Length - 1) {
        Write-Error "Usage: secretctl run [-Name <n> [-As <ENV_VAR>]] [-Env ENV_VAR=VaultName ...] -- <command> [args...]"
    }
    $flagsPart = $rest[0..($sepIdx - 1)]
    $cmd = $rest[$sepIdx + 1]
    $cmdArgs = @()
    if ($sepIdx + 2 -le $rest.Length - 1) {
        $cmdArgs = @($rest[($sepIdx + 2)..($rest.Length - 1)])
    }

    $Name = Get-Named $flagsPart '-Name'
    $As   = Get-Named $flagsPart '-As' $Name

    $envPairs = @()
    if ($Name) { $envPairs += @{ envVar = $As; vaultName = $Name } }
    foreach ($spec in (Get-AllNamed $flagsPart '-Env')) {
        $parts = $spec -split '=', 2
        if ($parts.Length -ne 2 -or -not $parts[0] -or -not $parts[1]) {
            Write-Error "Invalid -Env spec '$spec'; expected ENV_VAR=VaultName."
        }
        $envPairs += @{ envVar = $parts[0]; vaultName = $parts[1] }
    }
    if ($envPairs.Count -eq 0) {
        Write-Error "No secrets specified. Use -Name <n> [-As ENV_VAR] and/or -Env ENV_VAR=VaultName."
    }

    $vault = Load-Vault
    foreach ($p in $envPairs) { Require-Entry $vault $p.vaultName }

    $plainValues = @{}
    $savedEnv = @{}
    foreach ($p in $envPairs) {
        $plainValues[$p.envVar] = Unprotect-Value $vault[$p.vaultName].cipher
    }

    $exitCode = 0
    $output = ''
    try {
        foreach ($k in $plainValues.Keys) {
            $savedEnv[$k] = [Environment]::GetEnvironmentVariable($k)
            [Environment]::SetEnvironmentVariable($k, $plainValues[$k])
        }
        $output = (& $cmd @cmdArgs 2>&1 | Out-String)
        $exitCode = if ($LASTEXITCODE) { $LASTEXITCODE } else { 0 }
    }
    finally {
        foreach ($k in $savedEnv.Keys) { [Environment]::SetEnvironmentVariable($k, $savedEnv[$k]) }
    }

    foreach ($v in $plainValues.Values) {
        if (-not $v) { continue }
        $output = $output.Replace($v, '[REDACTED]')
        $urlEncoded = [Uri]::EscapeDataString($v)
        if ($urlEncoded -ne $v) { $output = $output.Replace($urlEncoded, '[REDACTED]') }
    }
    $plainValues.Clear()

    Write-Output $output
    Write-Audit 'run' (($envPairs | ForEach-Object { $_.vaultName }) -join ',') $cmd
    if ($exitCode -ne 0) {
        Write-Error "Command '$cmd' exited with code $exitCode (output above; any secret values redacted)."
    }
}

function Cmd-Delete([string[]]$rest) {
    $Name  = Get-Named $rest '-Name'
    $Force = Has-Flag $rest '-Force'
    if (-not $Name) { Write-Error "Usage: secretctl delete -Name <name> [-Force]" }
    $vault = Load-Vault
    Require-Entry $vault $Name
    if (-not $Force) {
        $approved = Request-HumanApproval "secretctl: approve deleting '$Name'?"
        if ($approved -eq $false) {
            Write-Error "Not approved (Windows Hello declined, timed out, or is unavailable and this call is non-interactive). Use -Force to skip confirmation, or approve via the Windows Hello prompt this triggers."
        }
        if ($null -eq $approved) {
            if ([Console]::IsInputRedirected) { Write-Error "Refusing to delete without -Force under non-interactive input." }
            $confirm = Read-Host "Type the secret name to confirm deletion of '$Name'"
            if ($confirm -ne $Name) { Write-Error "Confirmation did not match; aborted." }
        }
    }
    $vault.Remove($Name)
    Save-Vault $vault
    Write-Audit 'delete' $Name
    Write-Output "Deleted '$Name'."
}

function Start-ClipboardAutoClear([string]$plain, [int]$delaySeconds = 45) {
    # Never pass the plaintext itself to the background process (argv is
    # visible to other local processes via Task Manager/WMI) - only a hash,
    # used purely to check "is this still what I put there" before clearing,
    # so an unrelated thing the user copied in the meantime isn't wiped.
    $hasher = [Security.Cryptography.SHA256]::Create()
    $hash = -join ($hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($plain)) | ForEach-Object { $_.ToString('x2') })
    $clearScript = @'
param([string]$ExpectedHash, [int]$DelaySeconds, [string]$SelfPath)
try {
    Start-Sleep -Seconds $DelaySeconds
    $current = Get-Clipboard -Raw -ErrorAction SilentlyContinue
    if ($current) {
        $hasher = [Security.Cryptography.SHA256]::Create()
        $currentHash = -join ($hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($current)) | ForEach-Object { $_.ToString('x2') })
        if ($currentHash -eq $ExpectedHash) { Set-Clipboard -Value ' ' }
    }
} catch {
} finally {
    # The child deletes its own script once it's done reading/running it -
    # never the parent. Deleting from the parent (the original approach)
    # raced against this process's own startup: pwsh needs time to launch
    # and read the -File script before this 45s sleep even begins, and a
    # parent-side delete after a fixed short pause deleted it out from under
    # the child before that finished, killing the auto-clear silently.
    # Confirmed as the actual root cause by removing the premature delete
    # and observing the clear succeed every time.
    Remove-Item -Path $SelfPath -Force -ErrorAction SilentlyContinue
}
'@
    $tmpScript = Join-Path ([IO.Path]::GetTempPath()) "secretctl-clip-$([guid]::NewGuid()).ps1"
    Set-Content -Path $tmpScript -Value $clearScript -Encoding utf8
    Start-Process -FilePath 'pwsh' -ArgumentList @('-NoProfile', '-WindowStyle', 'Hidden', '-File', $tmpScript, '-ExpectedHash', $hash, '-DelaySeconds', $delaySeconds, '-SelfPath', $tmpScript) -WindowStyle Hidden | Out-Null
}

function Cmd-Reveal([string[]]$rest) {
    $Name = Get-Named $rest '-Name'
    if (-not $Name) { Write-Error "Usage: secretctl reveal -Name <name>" }
    $vault = Load-Vault
    Require-Entry $vault $Name

    $approved = Request-HumanApproval "secretctl: approve revealing '$Name' to the clipboard?"
    if ($approved -eq $false) {
        Write-Error "Not approved (Windows Hello declined, timed out, or is unavailable and this call is non-interactive). If an agent asked for this, don't approve it on its behalf."
    }
    if ($null -eq $approved) {
        $confirm = Read-Host "This will copy '$Name' in plaintext to the clipboard. Type the secret name to confirm"
        if ($confirm -ne $Name) { Write-Error "Confirmation did not match; aborted." }
    }

    $plain = Unprotect-Value $vault[$Name].cipher
    # Copied to the clipboard, never printed to this script's own stdout -
    # that stream is exactly what an agent's tool call captures back into its
    # own context, which is the one thing this whole tool exists to prevent.
    # Windows Hello proves a human is present; it does not create a channel
    # for delivering the value that bypasses the caller's own output stream,
    # so the delivery mechanism has to be the thing that changes instead.
    Set-Clipboard -Value $plain
    Start-ClipboardAutoClear -plain $plain
    Write-Audit 'reveal' $Name
    Write-Output "'$Name' copied to clipboard (auto-clears in 45s if unchanged). Value not displayed here or anywhere an agent can read it."
    $plain = $null
}

function Cmd-Help {
    @"
secretctl - local blind secret broker. Every verb below is agent-callable;
sensitive ones are gated by Windows Hello, not by "is a human typing here."

  secretctl generate    -Name <n> [-Length 32] [-Charset alnum|hex|base64url|numeric] [-Force]
  secretctl capture     -Name <n> [-Force] -- <command> [args...]
  secretctl set         -Name <n> [-Force]                      (types the value itself - human only, no Hello prompt substitutes for data entry)
  secretctl import-file -Name <n> -Path <file> [-Delete] [-Force]
  secretctl cf-list-permission-groups -BootstrapName <vaultName> [-AccountId <id>]
  secretctl cf-create-token -Name <n> -BootstrapName <vaultName> [-TokenName <cf-name>] (-PolicyJson <json> | -PolicyFile <path>) [-Force]
  secretctl list
  secretctl scan-env     [-Scope User|Machine|Both] [-Pattern <regex>] [-Via ssh:<host> [-Files <path1,path2,...>]]
  secretctl clear-env    -EnvVar <name> -Scope User|Machine          (Windows Hello approval)
  secretctl push        -Name <n> -Target github:owner/repo|vercel[:project]|wrangler:worker-name|file:<path> [-EnvName NAME] [-RepoEnv env] [-VercelEnv production|preview|development] [-Project name] [-Cwd dir]
  secretctl run         [-Name <n> [-As ENV_VAR]] [-Env ENV_VAR=VaultName ...] -- <command> [args...]
  secretctl rotate      -Name <n> [-RepushAll]
  secretctl delete      -Name <n> [-Force]                      (Windows Hello approval, or -Force)
  secretctl reveal      -Name <n>                                (Windows Hello approval; delivers via clipboard, never printed)
  secretctl allow       -Name <n> -Target <target-spec>          (Windows Hello approval)
  secretctl audit-verify

A secret can only be pushed to a target it has been used with before, or one
approved via 'allow'. The first push to any new target, 'reveal', 'delete',
and 'allow' all trigger a Windows Hello prompt (fingerprint/PIN) - a real
human has to physically approve it, but nothing needs to be typed, and any
agent can trigger the request. If Windows Hello isn't set up on this
machine, these fall back to typed console confirmation, which only works
for a genuinely interactive human (an agent's call still fails closed).

'cf-create-token' mints a new, narrowly-scoped Cloudflare API token via
Cloudflare's own REST API and stores it directly in the vault, blind - but
needs a one-time human bootstrap first: a Cloudflare API token with the
"User > API Tokens > Edit" permission, captured once via 'secretctl set',
since creating a token requires an existing token with permission to create
tokens. Use 'cf-list-permission-groups' with that bootstrap token to look
up the exact permission group IDs for whatever policy the new token needs
(e.g. Workers script edit) - don't guess at IDs, Cloudflare's taxonomy can
change. See README.md for a worked example.

'scan-env' lists environment variable NAMES (User/Machine scope) with a
length and a name-based "looks like a secret" heuristic - never values.
Use it to find candidates, then vault one blind with 'capture' (see its
own output for the exact command), then optionally 'clear-env' to remove
the now-duplicated plaintext original.

Vault: $VaultPath (DPAPI-encrypted, bound to this Windows user + machine)
Audit: $AuditPath (hash-chained; 'audit-verify' detects tampering/deletion)
"@ | Write-Output
}

$verb = $args[0]
$rest = @()
if ($args.Length -gt 1) { $rest = @($args[1..($args.Length - 1)]) }

switch ($verb) {
    'generate'     { Cmd-Generate $rest }
    'capture'      { Cmd-Capture $rest }
    'set'          { Cmd-Set $rest }
    'import-file'  { Cmd-ImportFile $rest }
    'cf-list-permission-groups' { Cmd-CfListPermissionGroups $rest }
    'cf-create-token'           { Cmd-CfCreateToken $rest }
    'list'         { Cmd-List $rest }
    'scan-env'     { Cmd-ScanEnv $rest }
    'clear-env'    { Cmd-ClearEnvVar $rest }
    'push'         { Cmd-Push $rest }
    'run'          { Cmd-Run $rest }
    'rotate'       { Cmd-Rotate $rest }
    'delete'       { Cmd-Delete $rest }
    'reveal'       { Cmd-Reveal $rest }
    'allow'        { Cmd-Allow $rest }
    'audit-verify' { Cmd-AuditVerify }
    default        { Cmd-Help }
}
