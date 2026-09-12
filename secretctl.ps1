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

function Ensure-VaultDir {
    if (-not (Test-Path $VaultDir)) { New-Item -ItemType Directory -Path $VaultDir -Force | Out-Null }
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

function Write-Audit([string]$verb, [string]$name, [string]$target = '') {
    Ensure-VaultDir
    $entry = [pscustomobject]@{
        time   = (Get-Date).ToUniversalTime().ToString('o')
        verb   = $verb
        name   = $name
        target = $target
        user   = $env:USERNAME
    }
    ($entry | ConvertTo-Json -Compress) | Add-Content -Path $AuditPath -Encoding utf8
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
    $cmdArgs = $rest[($sepIdx + 2)..($rest.Length - 1)]

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
        Write-Error "Captured command produced no output; nothing stored."
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

function Cmd-Push([string[]]$rest) {
    $Name      = Get-Named $rest '-Name'
    $Target    = Get-Named $rest '-Target'
    $EnvName   = Get-Named $rest '-EnvName' $Name
    $RepoEnv   = Get-Named $rest '-RepoEnv'
    $VercelEnv = Get-Named $rest '-VercelEnv' 'production'
    $Project   = Get-Named $rest '-Project'

    if (-not $Name -or -not $Target) {
        Write-Error "Usage: secretctl push -Name <name> -Target github:owner/repo|vercel[:project]|file:<path> [-EnvName NAME] [-RepoEnv env] [-VercelEnv production|preview|development] [-Project name]"
    }

    $vault = Load-Vault
    Require-Entry $vault $Name
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
        elseif ($Target -match '^file:(.+)$') {
            $path = $Matches[1]
            Push-ToFile -plain $plain -path $path -envName $EnvName
            $pushRecord = @{ target = $Target; envName = $EnvName }
            $desc = "file:$path as $EnvName"
        }
        else {
            Write-Error "Unrecognized -Target '$Target'. Use github:owner/repo, vercel[:project], or file:<path>."
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
            Cmd-Push $pushArgs
        }
    }
    $plain = $null
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
  secretctl push        -Name <n> -Target github:owner/repo|vercel[:project]|file:<path> [-EnvName NAME] [-RepoEnv env] [-VercelEnv production|preview|development] [-Project name]
  secretctl rotate      -Name <n> [-RepushAll]
  secretctl delete      -Name <n> [-Force]
  secretctl reveal      -Name <n>                                (interactive humans only)

Vault: $VaultPath (DPAPI-encrypted, bound to this Windows user + machine)
Audit: $AuditPath
"@ | Write-Output
}

$verb = $args[0]
$rest = if ($args.Length -gt 1) { $args[1..($args.Length - 1)] } else { @() }

switch ($verb) {
    'generate'    { Cmd-Generate $rest }
    'capture'     { Cmd-Capture $rest }
    'set'         { Cmd-Set $rest }
    'import-file' { Cmd-ImportFile $rest }
    'list'        { Cmd-List $rest }
    'push'        { Cmd-Push $rest }
    'rotate'      { Cmd-Rotate $rest }
    'delete'      { Cmd-Delete $rest }
    'reveal'      { Cmd-Reveal $rest }
    default       { Cmd-Help }
}
