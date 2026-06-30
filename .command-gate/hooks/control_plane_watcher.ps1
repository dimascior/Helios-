# control_plane_watcher.ps1 — Dot-sourced by helios_pretooluse.ps1 and evidence_capture.ps1
# Exports: Get-ControlPlaneSnapshot, Compare-ControlPlaneSnapshots, Test-HookPresence

function Get-FileSnapshot {
    param([string]$Path, [System.Security.Cryptography.SHA256]$Sha)
    if (-not (Test-Path $Path)) {
        return @{ path = $Path; exists = $false; hash = $null }
    }
    try {
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        $hash = ($Sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join ''
        return @{ path = $Path; exists = $true; hash = $hash }
    } catch {
        return @{ path = $Path; exists = $true; hash = $null }
    }
}

function Get-ControlPlaneSnapshot {
    param([string]$GateRoot)

    $OriginPath = Join-Path $GateRoot 'manifest\helios-install-origin.json'
    $ClaudeSettingsPath = Join-Path $env:USERPROFILE '.claude\settings.json'
    $AkashicRoot = $null

    if (Test-Path $OriginPath) {
        try {
            $origin = Get-Content $OriginPath -Raw | ConvertFrom-Json
            if ($origin.claude_settings_path) { $ClaudeSettingsPath = $origin.claude_settings_path }
            if ($origin.akashic_root) { $AkashicRoot = $origin.akashic_root }
        } catch {}
    }

    $sha = [System.Security.Cryptography.SHA256]::Create()
    $files = [ordered]@{}

    $files['claude_settings'] = Get-FileSnapshot $ClaudeSettingsPath $sha

    $heliosWatched = [ordered]@{
        'helios_pretooluse'  = 'hooks\helios_pretooluse.ps1'
        'gate_check'         = 'hooks\gate_check.ps1'
        'tier_classifier'    = 'hooks\tier_classifier.ps1'
        'evidence_capture'   = 'hooks\evidence_capture.ps1'
        'command_decomposer' = 'hooks\command_decomposer.ps1'
    }
    foreach ($key in $heliosWatched.Keys) {
        $files[$key] = Get-FileSnapshot (Join-Path $GateRoot $heliosWatched[$key]) $sha
    }

    $files['command_policy']    = Get-FileSnapshot (Join-Path $GateRoot 'policy\command-policy.json') $sha
    $files['operating_catalog'] = Get-FileSnapshot (Join-Path $GateRoot 'templates\operating-catalog.json') $sha
    $files['helios_envelope']   = Get-FileSnapshot (Join-Path $GateRoot 'manifest\helios-envelope.json') $sha
    $files['helios_sidecar']    = Get-FileSnapshot (Join-Path $GateRoot 'manifest\helios-envelope.sha256') $sha
    $files['helios_install_origin'] = Get-FileSnapshot $OriginPath $sha

    if ($AkashicRoot -and (Test-Path $AkashicRoot)) {
        $files['akashic_envelope'] = Get-FileSnapshot (Join-Path $AkashicRoot 'manifest\akashic-envelope.json') $sha
        $files['akashic_sidecar']  = Get-FileSnapshot (Join-Path $AkashicRoot 'manifest\akashic-envelope.sha256') $sha
    }

    $hookPresence = Test-HookPresence -SettingsPath $ClaudeSettingsPath -GateRoot $GateRoot

    return @{
        timestamp_utc = (Get-Date).ToUniversalTime().ToString('o')
        files         = $files
        hook_presence = $hookPresence
    }
}

function Compare-ControlPlaneSnapshots {
    param($Before, $After)

    $diffs = [ordered]@{}

    $afterFiles = $After.files
    $beforeFiles = $Before.files

    foreach ($key in $afterFiles.Keys) {
        $a = $afterFiles[$key]
        $b = $null
        if ($beforeFiles -is [System.Collections.IDictionary]) {
            if ($beforeFiles.Contains($key)) { $b = $beforeFiles[$key] }
        } elseif ($beforeFiles -is [PSCustomObject]) {
            $prop = $beforeFiles.PSObject.Properties[$key]
            if ($prop) { $b = $prop.Value }
        }

        if ($null -eq $b) {
            $diffs[$key] = @{ changed = $true; reason = 'new_in_after'; after_hash = $a.hash }
            continue
        }

        $bHash = if ($b -is [PSCustomObject]) { $b.hash } else { $b['hash'] }
        $bExists = if ($b -is [PSCustomObject]) { $b.exists } else { $b['exists'] }
        $aHash = if ($a -is [hashtable]) { $a['hash'] } else { $a.hash }
        $aExists = if ($a -is [hashtable]) { $a['exists'] } else { $a.exists }

        if ($aExists -ne $bExists) {
            $diffs[$key] = @{ changed = $true; reason = $(if ($aExists) { 'appeared' } else { 'disappeared' }); before_exists = $bExists; after_exists = $aExists }
        } elseif ($aHash -ne $bHash) {
            $diffs[$key] = @{ changed = $true; reason = 'hash_changed'; before_hash = $bHash; after_hash = $aHash }
        }
    }

    if ($beforeFiles -is [PSCustomObject]) {
        foreach ($prop in $beforeFiles.PSObject.Properties) {
            if (-not $afterFiles.Contains($prop.Name)) {
                $diffs[$prop.Name] = @{ changed = $true; reason = 'removed_from_watched_set' }
            }
        }
    } elseif ($beforeFiles -is [System.Collections.IDictionary]) {
        foreach ($key in $beforeFiles.Keys) {
            if (-not $afterFiles.Contains($key)) {
                $diffs[$key] = @{ changed = $true; reason = 'removed_from_watched_set' }
            }
        }
    }

    $hookChanged = $false
    $bHP = $Before.hook_presence
    $aHP = $After.hook_presence
    if ($bHP -and $aHP) {
        $bPre = if ($bHP -is [PSCustomObject]) { $bHP.pretooluse_present } else { $bHP['pretooluse_present'] }
        $bPost = if ($bHP -is [PSCustomObject]) { $bHP.posttooluse_present } else { $bHP['posttooluse_present'] }
        $bFail = if ($bHP -is [PSCustomObject]) { $bHP.posttoolusefailure_present } else { $bHP['posttoolusefailure_present'] }
        $aPre = if ($aHP -is [hashtable]) { $aHP['pretooluse_present'] } else { $aHP.pretooluse_present }
        $aPost = if ($aHP -is [hashtable]) { $aHP['posttooluse_present'] } else { $aHP.posttooluse_present }
        $aFail = if ($aHP -is [hashtable]) { $aHP['posttoolusefailure_present'] } else { $aHP.posttoolusefailure_present }

        if ($bPre -ne $aPre -or $bPost -ne $aPost -or $bFail -ne $aFail) {
            $hookChanged = $true
            $diffs['hook_configuration'] = @{
                changed = $true
                reason  = 'hook_presence_changed'
                before  = @{ pretooluse = $bPre; posttooluse = $bPost; posttoolusefailure = $bFail }
                after   = @{ pretooluse = $aPre; posttooluse = $aPost; posttoolusefailure = $aFail }
            }
        }
    }

    return @{
        has_changes           = ($diffs.Count -gt 0)
        hook_presence_changed = $hookChanged
        diffs                 = $diffs
    }
}

function Test-HookPresence {
    param([string]$SettingsPath, [string]$GateRoot)

    $result = @{
        settings_exists              = $false
        settings_hash                = $null
        pretooluse_present           = $false
        posttooluse_present          = $false
        posttoolusefailure_present   = $false
        pretooluse_command           = $null
        posttooluse_command          = $null
        posttoolusefailure_command   = $null
        all_hooks_present            = $false
    }

    if (-not (Test-Path $SettingsPath)) { return $result }
    $result.settings_exists = $true

    try {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $bytes = [System.IO.File]::ReadAllBytes($SettingsPath)
        $result.settings_hash = ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join ''
    } catch {}

    try {
        $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json
        if (-not $settings.hooks) { return $result }

        $hookTypes = @(
            @{ Name = 'PreToolUse';         Pattern = 'helios_pretooluse\.ps1'; PresentKey = 'pretooluse_present'; CommandKey = 'pretooluse_command' },
            @{ Name = 'PostToolUse';        Pattern = 'evidence_capture\.ps1';  PresentKey = 'posttooluse_present'; CommandKey = 'posttooluse_command' },
            @{ Name = 'PostToolUseFailure'; Pattern = 'evidence_capture\.ps1';  PresentKey = 'posttoolusefailure_present'; CommandKey = 'posttoolusefailure_command' }
        )

        foreach ($ht in $hookTypes) {
            $hookEntries = $settings.hooks.($ht.Name)
            if (-not $hookEntries) { continue }
            foreach ($entry in $hookEntries) {
                $hooks = $entry.hooks
                if (-not $hooks) { $hooks = @($entry) }
                foreach ($h in $hooks) {
                    if ($h.command -and $h.command -match $ht.Pattern) {
                        $result[$ht.PresentKey] = $true
                        $result[$ht.CommandKey] = $h.command
                    }
                }
            }
        }

        $result.all_hooks_present = $result.pretooluse_present -and $result.posttooluse_present -and $result.posttoolusefailure_present
    } catch {}

    return $result
}
