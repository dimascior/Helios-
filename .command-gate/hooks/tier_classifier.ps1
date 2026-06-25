# tier_classifier.ps1 — Dot-sourced by gate_check.ps1 and evidence_capture.ps1
# Exports: Get-CommandTier, Test-ChainViolation, Test-WriteIndicator
# Loads all patterns from command-policy.json at runtime.

$script:GateRoot = 'C:\Users\dimas\Desktop\MythosJustAFable\.command-gate'
$script:PolicyLoaded = $false
$script:Tier4Patterns = @()
$script:Tier3Patterns = @()
$script:Tier2Patterns = @()
$script:Tier1Patterns = @()
$script:WriteIndicators = @()

function Load-Policy {
    if ($script:PolicyLoaded) { return }
    $PolicyPath = Join-Path $script:GateRoot 'policy\command-policy.json'
    if (-not (Test-Path $PolicyPath)) {
        $script:PolicyLoaded = $true
        return
    }
    try {
        $Policy = Get-Content $PolicyPath -Raw | ConvertFrom-Json

        if ($Policy.tier_4_forbidden) {
            $script:Tier4Patterns = @($Policy.tier_4_forbidden)
        }
        if ($Policy.tier_3_modifying) {
            $script:Tier3Patterns = @($Policy.tier_3_modifying)
        }
        if ($Policy.tier_2_remote_admin) {
            $script:Tier2Patterns = @($Policy.tier_2_remote_admin)
        }
        if ($Policy.tier_1_diagnostic) {
            $script:Tier1Patterns = @($Policy.tier_1_diagnostic)
        }
        if ($Policy.write_indicators) {
            $script:WriteIndicators = @($Policy.write_indicators)
        }
    } catch {}
    $script:PolicyLoaded = $true
}

function Test-ChainViolation {
    param([string]$Command)
    Load-Policy

    $InSingleQuote = $false
    $HasChain = $false
    for ($i = 0; $i -lt $Command.Length; $i++) {
        $c = $Command[$i]
        if ($c -eq "'" -and ($i -eq 0 -or $Command[$i-1] -ne '\')) {
            $InSingleQuote = -not $InSingleQuote
            continue
        }
        if ($InSingleQuote) { continue }

        if ($c -eq ';') { $HasChain = $true; break }
        if ($c -eq '|' -and $i+1 -lt $Command.Length -and $Command[$i+1] -eq '|') { $HasChain = $true; break }
        if ($c -eq '&' -and $i+1 -lt $Command.Length -and $Command[$i+1] -eq '&') { $HasChain = $true; break }
        if ($c -eq '|' -and ($i+1 -ge $Command.Length -or $Command[$i+1] -ne '|')) { $HasChain = $true; break }
    }

    return $HasChain
}

function Test-WriteIndicator {
    param([string]$Command)
    Load-Policy

    foreach ($p in $script:WriteIndicators) {
        if ($Command -match $p) {
            return $true
        }
    }
    return $false
}

function Get-CommandTier {
    param([string]$Command)
    Load-Policy

    foreach ($p in $script:Tier4Patterns) {
        if ($Command -match $p) {
            return @{ Tier = 4; Name = 'forbidden'; MatchedPattern = $p; MatchedTemplate = $null }
        }
    }

    $CatalogPath = Join-Path $script:GateRoot 'templates\operating-catalog.json'
    if (Test-Path $CatalogPath) {
        try {
            $Catalog = Get-Content $CatalogPath -Raw | ConvertFrom-Json
            foreach ($entry in $Catalog) {
                $Pattern = $entry.pattern
                if (-not $Pattern) { $Pattern = $entry.pattern_regex }
                if (-not $Pattern) { continue }

                $TemplateId = $entry.template_id
                if (-not $TemplateId) { $TemplateId = $entry.id }

                $EntryName = $entry.name
                if (-not $EntryName) { $EntryName = $entry.family }

                if ($Command -match $Pattern) {
                    return @{
                        Tier = [int]$entry.tier
                        Name = $EntryName
                        MatchedPattern = $Pattern
                        MatchedTemplate = $TemplateId
                    }
                }
            }
        } catch {}
    }

    foreach ($p in $script:Tier3Patterns) {
        if ($Command -match $p) {
            return @{ Tier = 3; Name = 'modifying'; MatchedPattern = $p; MatchedTemplate = $null }
        }
    }

    foreach ($p in $script:Tier2Patterns) {
        if ($Command -match $p) {
            return @{ Tier = 2; Name = 'remote_admin'; MatchedPattern = $p; MatchedTemplate = $null }
        }
    }

    foreach ($p in $script:Tier1Patterns) {
        if ($Command -match $p) {
            return @{ Tier = 1; Name = 'diagnostic'; MatchedPattern = $p; MatchedTemplate = $null }
        }
    }

    return @{ Tier = 0; Name = 'routine'; MatchedPattern = $null; MatchedTemplate = $null }
}
