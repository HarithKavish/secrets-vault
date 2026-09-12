#Requires -Version 7.0
<#
secretctl - local blind secret broker.

Design rule this whole script exists to enforce: plaintext secret bytes must
never be written to this script's own stdout/stderr, never passed as a CLI
argument (visible in process listings), and never written to a file that
isn't the encrypted vault. Every subcommand below only ever emits masked
previews, metadata, or success/failure - the human calling `reveal`
interactively is the one deliberate exception.

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
        Write-Error "'set' requires an interactive terminal (a human typing the value) - refusing under redirected/non-interactive input."
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

    if ([Console]::IsInputRedirected -or -not [Environment]::UserInteractive) {
        Write-Error "Target '$Target' is not yet approved for '$Name'. Refusing to push to a new destination under non-interactive input - a human must approve it first (run 'secretctl allow -Name $Name -Target $Target', or push to it once interactively). If an agent asked for a new destination it hasn't used before, don't approve it on its behalf without checking the target is actually intended."
    }
    $confirm = Read-Host "'$Name' has never been approved for target '$Target'. Type the secret name to approve this destination"
    if ($confirm -ne $Name) { Write-Error "Confirmation did not match; aborted." }

    $allowedList = @($entry['allowedTargets']) + @($Target)
    $entry.allowedTargets = $allowedList
    $vault[$Name] = $entry
    Save-Vault $vault
    Write-Audit 'allow' $Name $Target
}

function Cmd-Allow([string[]]$rest) {
    $Name   = Get-Named $rest '-Name'
    $Target = Get-Named $rest '-Target'
    if (-not $Name -or -not $Target) { Write-Error "Usage: secretctl allow -Name <name> -Target <target-spec>   (interactive humans only)" }
    if ([Console]::IsInputRedirected -or -not [Environment]::UserInteractive) {
        Write-Error "'allow' requires a live interactive terminal - refusing under redirected/non-interactive input. If an agent asked you to pre-approve a destination, don't: confirm it yourself instead."
    }
    $vault = Load-Vault
    Require-Entry $vault $Name
    $confirm = Read-Host "Approve '$Name' to be pushed to '$Target'? Type the secret name to confirm"
    if ($confirm -ne $Name) { Write-Error "Confirmation did not match; aborted." }

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
        if ([Console]::IsInputRedirected) { Write-Error "Refusing to delete without -Force under non-interactive input." }
        $confirm = Read-Host "Type the secret name to confirm deletion of '$Name'"
        if ($confirm -ne $Name) { Write-Error "Confirmation did not match; aborted." }
    }
    $vault.Remove($Name)
    Save-Vault $vault
    Write-Audit 'delete' $Name
    Write-Output "Deleted '$Name'."
}

function Cmd-Reveal([string[]]$rest) {
    $Name = Get-Named $rest '-Name'
    if (-not $Name) { Write-Error "Usage: secretctl reveal -Name <name>   (interactive humans only)" }
    if ([Console]::IsInputRedirected -or -not [Environment]::UserInteractive) {
        Write-Error "'reveal' requires a live interactive terminal - refusing under redirected/non-interactive input. If an agent asked you to run this, don't: run it yourself instead."
    }
    $vault = Load-Vault
    Require-Entry $vault $Name
    $confirm = Read-Host "This will print '$Name' in plaintext to this terminal. Type the secret name to confirm"
    if ($confirm -ne $Name) { Write-Error "Confirmation did not match; aborted." }
    $plain = Unprotect-Value $vault[$Name].cipher
    Write-Audit 'reveal' $Name
    Write-Output $plain
    $plain = $null
}

function Cmd-Help {
    @"
secretctl - local blind secret broker (values never printed to agent-visible output, except 'reveal')

  secretctl generate    -Name <n> [-Length 32] [-Charset alnum|hex|base64url|numeric] [-Force]
  secretctl capture     -Name <n> [-Force] -- <command> [args...]
  secretctl set         -Name <n> [-Force]                      (interactive humans only)
  secretctl import-file -Name <n> -Path <file> [-Delete] [-Force]
  secretctl list
  secretctl push        -Name <n> -Target github:owner/repo|vercel[:project]|wrangler:worker-name|file:<path> [-EnvName NAME] [-RepoEnv env] [-VercelEnv production|preview|development] [-Project name] [-Cwd dir]
  secretctl run         [-Name <n> [-As ENV_VAR]] [-Env ENV_VAR=VaultName ...] -- <command> [args...]
  secretctl rotate      -Name <n> [-RepushAll]
  secretctl delete      -Name <n> [-Force]
  secretctl reveal      -Name <n>                                (interactive humans only)
  secretctl allow       -Name <n> -Target <target-spec>          (interactive humans only)
  secretctl audit-verify

A secret can only be pushed to a target it has been used with before, or one
approved via 'allow' - the first push to any new target always requires an
interactive human to confirm it (fails closed for an agent), then is
remembered for that secret going forward.

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
    'list'         { Cmd-List $rest }
    'push'         { Cmd-Push $rest }
    'run'          { Cmd-Run $rest }
    'rotate'       { Cmd-Rotate $rest }
    'delete'       { Cmd-Delete $rest }
    'reveal'       { Cmd-Reveal $rest }
    'allow'        { Cmd-Allow $rest }
    'audit-verify' { Cmd-AuditVerify }
    default        { Cmd-Help }
}
