# command_decomposer.ps1 — Dot-sourced by gate_check.ps1
# Exports: Get-CommandDecomposition
# Normalizes command text into executable segments and capability markers.

$script:GateRoot = Split-Path $PSScriptRoot -Parent

function Get-CommandDecomposition {
    param(
        [string]$Command,
        [string[]]$DeclaredSegments = @()
    )

    $Result = [ordered]@{
        raw_command              = $Command
        segment_count            = 1
        segments_detected        = @()
        declared_segments        = $DeclaredSegments
        segments_match           = $true
        ambiguous_parse          = $false
        contains_inline_execution = $false
        contains_dynamic_eval    = $false
        contains_nested_shell    = $false
        contains_command_substitution = $false
        contains_control_plane_path = $false
        requires_read_write_impact = $false
        parse_confidence         = 'full'
        separators_found         = @()
    }

    $Segments = Split-CommandSegments $Command
    $Result.segments_detected = $Segments
    $Result.segment_count = $Segments.Count

    if ($Segments.Count -ne $DeclaredSegments.Count -and $DeclaredSegments.Count -gt 0) {
        $Result.segments_match = $false
    } elseif ($DeclaredSegments.Count -gt 0) {
        $Result.segments_match = Test-SegmentsMatch -Detected $Segments -Declared $DeclaredSegments
    }

    $capResult = Test-DecomposedCapabilities $Command
    $Result.contains_inline_execution = $capResult.InlineExecution
    $Result.contains_dynamic_eval = $capResult.DynamicEval
    $Result.contains_nested_shell = $capResult.NestedShell
    $Result.contains_command_substitution = $capResult.CommandSubstitution
    $Result.contains_control_plane_path = $capResult.ControlPlanePath
    $Result.ambiguous_parse = $capResult.Ambiguous
    $Result.parse_confidence = $capResult.Confidence

    if ($capResult.InlineExecution -or $capResult.DynamicEval -or $capResult.Ambiguous) {
        $Result.requires_read_write_impact = $true
    }

    return $Result
}

function Split-CommandSegments {
    param([string]$Command)

    $Segments = [System.Collections.ArrayList]::new()
    $Current = [System.Text.StringBuilder]::new()
    $InSingleQuote = $false
    $InDoubleQuote = $false

    for ($i = 0; $i -lt $Command.Length; $i++) {
        $c = $Command[$i]

        if ($c -eq "'" -and -not $InDoubleQuote -and ($i -eq 0 -or $Command[$i-1] -ne '\')) {
            $InSingleQuote = -not $InSingleQuote
            [void]$Current.Append($c)
            continue
        }
        if ($c -eq '"' -and -not $InSingleQuote -and ($i -eq 0 -or $Command[$i-1] -ne '\')) {
            $InDoubleQuote = -not $InDoubleQuote
            [void]$Current.Append($c)
            continue
        }
        if ($InSingleQuote -or $InDoubleQuote) {
            [void]$Current.Append($c)
            continue
        }

        # Semicolon separator
        if ($c -eq ';') {
            $seg = $Current.ToString().Trim()
            if ($seg.Length -gt 0) { [void]$Segments.Add($seg) }
            [void]$Current.Clear()
            continue
        }

        # && separator
        if ($c -eq '&' -and $i+1 -lt $Command.Length -and $Command[$i+1] -eq '&') {
            $seg = $Current.ToString().Trim()
            if ($seg.Length -gt 0) { [void]$Segments.Add($seg) }
            [void]$Current.Clear()
            $i++
            continue
        }

        # || separator
        if ($c -eq '|' -and $i+1 -lt $Command.Length -and $Command[$i+1] -eq '|') {
            $seg = $Current.ToString().Trim()
            if ($seg.Length -gt 0) { [void]$Segments.Add($seg) }
            [void]$Current.Clear()
            $i++
            continue
        }

        # Pipe (single |)
        if ($c -eq '|') {
            $seg = $Current.ToString().Trim()
            if ($seg.Length -gt 0) { [void]$Segments.Add($seg) }
            [void]$Current.Clear()
            continue
        }

        [void]$Current.Append($c)
    }

    $final = $Current.ToString().Trim()
    if ($final.Length -gt 0) { [void]$Segments.Add($final) }

    if ($Segments.Count -eq 0) { [void]$Segments.Add($Command) }

    return @($Segments)
}

function Test-SegmentsMatch {
    param(
        [string[]]$Detected,
        [string[]]$Declared
    )

    if ($Detected.Count -ne $Declared.Count) { return $false }

    for ($i = 0; $i -lt $Detected.Count; $i++) {
        $d = $Detected[$i].Trim()
        $s = $Declared[$i].Trim()
        if ($d -ne $s) { return $false }
    }

    return $true
}

function Test-DecomposedCapabilities {
    param([string]$Command)

    $InlineExecution = $false
    $DynamicEval = $false
    $NestedShell = $false
    $CommandSubstitution = $false
    $ControlPlanePath = $false
    $Ambiguous = $false
    $Confidence = 'full'

    $InlinePatterns = @(
        'python3?\s+-[ce]',
        '\bnode\s+-e',
        '\bruby\s+-e',
        '\bperl\s+-[eE]',
        '\bpwsh\s+-[Cc]ommand',
        '\bpowershell\s+-[Cc]ommand',
        '\bbash\s+-c',
        '\bsh\s+-c'
    )

    $EvalPatterns = @(
        '\beval\b',
        'Invoke-Expression',
        '\biex\s'
    )

    $EncodedPatterns = @(
        '-[Ee]ncoded[Cc]ommand',
        '-[Ee]nc\s',
        '\bbase64\s+-d.*\|\s*(ba)?sh'
    )

    $SubstitutionPatterns = @(
        '\$\(',
        '\`[^\`]+\`'
    )

    $ControlPlanePatterns = @(
        '\.claude[/\\]settings',
        'command-policy\.json',
        'tier_classifier\.ps1',
        'gate_check\.ps1',
        'evidence_capture\.ps1',
        'helios_pretooluse\.ps1',
        'akashic-envelope'
    )

    foreach ($p in $InlinePatterns) {
        if ($Command -match $p) { $InlineExecution = $true; break }
    }
    foreach ($p in $EvalPatterns) {
        if ($Command -match $p) { $DynamicEval = $true; break }
    }
    foreach ($p in $EncodedPatterns) {
        if ($Command -match $p) { $DynamicEval = $true; break }
    }
    foreach ($p in $SubstitutionPatterns) {
        if ($Command -match $p) { $CommandSubstitution = $true; $NestedShell = $true; break }
    }
    foreach ($p in $ControlPlanePatterns) {
        if ($Command -match $p) { $ControlPlanePath = $true; break }
    }

    if ($InlineExecution -or $DynamicEval) {
        $Confidence = 'partial'
    }
    if ($Command -match '\bhere-string\b' -or $Command -match '@"' -or $Command -match "^@'") {
        $Confidence = 'partial'
        $Ambiguous = $true
    }

    return @{
        InlineExecution    = $InlineExecution
        DynamicEval        = $DynamicEval
        NestedShell        = $NestedShell
        CommandSubstitution = $CommandSubstitution
        ControlPlanePath   = $ControlPlanePath
        Ambiguous          = $Ambiguous
        Confidence         = $Confidence
    }
}
