# gate_check.ps1 — PreToolUse hook (refactored for front-controller support)
# When invoked standalone: reads stdin, loads tier_classifier, runs validation.
# When dot-sourced by helios_pretooluse.ps1: provides Invoke-GateValidation only.
# Exit 0 + {} = allow (normal permission flow). Exit 2 + stderr = block.
#
# Contract sources (single ownership, no drift):
#   - required base fields:  schema/helios-gate.schema.json (canonical, protected)
#   - tier-required fields:  policy/command-policy.json (live policy, protected)
# Both fail CLOSED when missing, malformed, or empty — no hardcoded fallback.
# Denials speak the HELIOS/1 wire grammar: a sentinel line followed by one line
# of compact JSON carrying machine-readable recovery (schema_command,
# scaffold_command, blocked_id, last_correlation_id).

$ErrorActionPreference = 'Stop'

$GateRoot = Split-Path $PSScriptRoot -Parent

$RequiredDirs = @('pending', 'inflight', 'evidence', 'blocked', 'policy', 'templates', 'manifest')

$script:HeliosGateSchemaVersion = 'command-gate.v1'
$script:HeliosSchemaDocVersion  = 'helios-gate-schema.v1'
$script:HeliosSchemaRelPath     = 'schema/helios-gate.schema.json'

function Deny {
    param([string]$Reason)
    $Out = @{
        hookSpecificOutput = @{
            hookEventName = 'PreToolUse'
            permissionDecision = 'deny'
            permissionDecisionReason = $Reason
        }
    }
    Write-Output ($Out | ConvertTo-Json -Depth 5 -Compress)
    exit 0
}

function DenyFatal {
    param([string]$Reason)
    Deny $Reason
}

function Get-Sha256 {
    param([string]$Text)
    $Bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    $Sha = [System.Security.Cryptography.SHA256]::Create()
    $HashBytes = $Sha.ComputeHash($Bytes)
    return ($HashBytes | ForEach-Object { $_.ToString('x2') }) -join ''
}

function Get-SafeGateSlug {
    param([string]$Command)
    $safe = $Command -replace '[''"]', ''
    $safe = $safe -replace '[^a-zA-Z0-9._-]', '-'
    $safe = $safe -replace '-{2,}', '-'
    $safe = $safe.Trim('-')
    $safe = $safe.ToLower()
    if ($safe.Length -gt 80) { $safe = $safe.Substring(0, 80).TrimEnd('-') }
    if ([string]::IsNullOrWhiteSpace($safe)) { $safe = 'command' }
    return $safe
}

function Get-HeliosSchemaSha256 {
    # Prefer the manifest-recorded hash handed over by the front controller;
    # standalone mode hashes the file directly (informational).
    if ($script:HeliosWireContext -and $script:HeliosWireContext.schema_sha256) {
        return $script:HeliosWireContext.schema_sha256
    }
    try {
        $p = Join-Path $GateRoot ($script:HeliosSchemaRelPath -replace '/', '\')
        if (Test-Path $p) {
            $bytes = [System.IO.File]::ReadAllBytes($p)
            $sha = [System.Security.Cryptography.SHA256]::Create()
            return ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join ''
        }
    } catch {}
    return $null
}

function Get-RequiredBaseFields {
    # Canonical schema is the single owner of the base-field list. Fail closed.
    $schemaPath = Join-Path $GateRoot ($script:HeliosSchemaRelPath -replace '/', '\')
    if (-not (Test-Path $schemaPath)) {
        throw "canonical schema missing: $($script:HeliosSchemaRelPath)"
    }
    $doc = $null
    try {
        $doc = Get-Content $schemaPath -Raw | ConvertFrom-Json
    } catch {
        throw "canonical schema unparseable: $($_.Exception.Message)"
    }
    $fields = @($doc.sections.fields.required_base_fields)
    if ($fields.Count -lt 1) {
        throw 'canonical schema malformed: required_base_fields empty'
    }
    return $fields
}

function Get-TierRequiredFields {
    # Live policy is the single owner of tier requirements. Fail closed.
    param([int]$Tier)
    $PolicyPath = Join-Path $GateRoot 'policy\command-policy.json'
    if (-not (Test-Path $PolicyPath)) {
        throw 'command-policy.json missing'
    }
    $Policy = Get-Content $PolicyPath -Raw | ConvertFrom-Json
    $Key = [string][Math]::Min($Tier, 3)
    $Fields = $Policy.tier_required_fields.$Key
    if (-not $Fields) {
        throw "tier_required_fields['$Key'] missing from live policy"
    }
    return @($Fields)
}

function Get-LastExecutableCorrelationId {
    # Root is passed explicitly by callers so this never depends on an ambient
    # $GateRoot that may resolve differently across scopes (front controller vs
    # standalone vs test harness).
    param([string]$SessionId, [string]$Root = $GateRoot)
    if (-not $SessionId) { return $null }
    try {
        if (-not (Get-Command Get-SessionLedger -ErrorAction SilentlyContinue)) {
            $scPath = Join-Path $Root 'hooks\session_continuity.ps1'
            if (Test-Path $scPath) { . $scPath }
        }
        if (Get-Command Get-SessionLedger -ErrorAction SilentlyContinue) {
            $ledger = @(Get-SessionLedger -GateRoot $Root -SessionId $SessionId)
            for ($li = $ledger.Count - 1; $li -ge 0; $li--) {
                if ($ledger[$li].event_type -eq 'posttooluse_evidence_written') {
                    return $ledger[$li].correlation_id
                }
            }
        }
    } catch {}
    return $null
}

function Write-HeliosBlockedRecord {
    # Atomic: build -> serialize -> write tmp -> File.Move rename. Only a
    # successful rename may be advertised as a scaffoldable blocked_id.
    param([Parameter(Mandatory)]$Record, [Parameter(Mandatory)][string]$Hash, [string]$ToolUseId)

    $ts = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $id = "$ts-$($Hash.Substring(0, 12))"
    $blockedDir = Join-Path $GateRoot 'blocked'
    $final = Join-Path $blockedDir "$id.blocked.json"
    $tmp = $null
    try {
        $tmp = Join-Path $blockedDir (".tmp-" + [guid]::NewGuid().ToString('N'))
        [System.IO.File]::WriteAllText($tmp, ($Record | ConvertTo-Json -Depth 6), [System.Text.Encoding]::UTF8)
        if (Test-Path $final) {
            # Collision grammar: append a sanitized, bounded tool-use suffix.
            $suffix = ("$ToolUseId" -replace '[^A-Za-z0-9_-]', '')
            if ($suffix.Length -gt 24) { $suffix = $suffix.Substring($suffix.Length - 24) }
            if (-not $suffix) { $suffix = [guid]::NewGuid().ToString('N').Substring(0, 8) }
            $id = "$id-$suffix"
            $final = Join-Path $blockedDir "$id.blocked.json"
            if (Test-Path $final) { throw "blocked record collision persists: $id" }
        }
        [System.IO.File]::Move($tmp, $final)
        return @{ ok = $true; blocked_id = $id; path = $final }
    } catch {
        try { if ($tmp -and (Test-Path $tmp)) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue } } catch {}
        return @{ ok = $false; error = "$($_.Exception.Message)"; code = 'PERSISTENCE_ERROR' }
    }
}

function New-HeliosDenyReason {
    # Builds the two-line HELIOS/1 denial envelope used as the deny reason.
    param(
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Message,
        [string]$Hash,
        $Tier,
        [string]$Shell,
        [string]$Cwd,
        $BlockedResult,
        [string]$LastCorrelationId,
        $Extra
    )
    $body = [ordered]@{
        code                = $Code
        message             = $Message
        command_sha256      = $Hash
        detected_tier       = $Tier
        shell               = $Shell
        working_directory   = $Cwd
        gate_schema_version = $script:HeliosGateSchemaVersion
        schema_doc_version  = $script:HeliosSchemaDocVersion
        schema_sha256       = (Get-HeliosSchemaSha256)
        last_correlation_id = $LastCorrelationId
    }
    $tierArg = 0
    if ($null -ne $Tier -and "$Tier" -match '^\d+$') { $tierArg = [Math]::Min([Math]::Max([int]$Tier, 0), 3) }
    $shellArg = 'bash'
    if ($Shell -in @('bash', 'powershell')) { $shellArg = $Shell }
    $body.schema_command = "helios gate schema --tier $tierArg --shell $shellArg"

    if ($null -ne $BlockedResult -and $BlockedResult.ok) {
        $body.blocked_id = $BlockedResult.blocked_id
        $body.scaffold_available = $true
        $body.scaffold_command = "helios gate scaffold --blocked-id $($BlockedResult.blocked_id)"
        # Destination discovery: recover from this denial alone, without prior
        # knowledge of the absolute Helios root. Paths derive solely from the
        # front controller's own $GateRoot, never from request/record contents.
        $body.gate_root = "$GateRoot"
        $pendingDir = Join-Path $GateRoot 'pending'
        $body.pending_directory = "$pendingDir"
        $body.suggested_gate_path = (Join-Path $pendingDir '<correlation-id>.gate.json')
    } else {
        $body.scaffold_available = $false
        if ($null -ne $BlockedResult -and $BlockedResult.error) {
            $body.persistence_error = $BlockedResult.code
        }
    }
    if ($Extra) {
        foreach ($k in $Extra.Keys) { $body[$k] = $Extra[$k] }
    }
    $json = $body | ConvertTo-Json -Depth 6 -Compress
    return "HELIOS/1 DENY $Code`n$json"
}

# --- Gate Validation Function ---
# Returns a hashtable: { action, reason, message, hash, tier, correlation_id }
# action values: passthrough, allow, deny, fatal

function Invoke-GateValidation {
    param([Parameter(Mandatory)]$Payload)

    $ToolName = $Payload.tool_name
    if ($ToolName -notin @('Bash', 'PowerShell')) {
        return @{ action = 'passthrough' }
    }

    $Command = $null
    if ($Payload.tool_input -and $Payload.tool_input.command) {
        $Command = $Payload.tool_input.command
    }
    if ([string]::IsNullOrWhiteSpace($Command)) {
        return @{ action = 'fatal'; message = 'No command field in tool_input' }
    }

    # Effective working directory: tool_input.workdir when present (Codex),
    # otherwise the hook payload cwd. Used for gate identity, blocked records,
    # scaffolds, and retry matching.
    $Cwd = $Payload.cwd
    if ($Payload.tool_input.PSObject.Properties['workdir'] -and $Payload.tool_input.workdir) {
        $Cwd = "$($Payload.tool_input.workdir)"
    }
    $ToolUseId = $Payload.tool_use_id
    $SessionId = $Payload.session_id
    $Shell = $ToolName.ToLower()

    # Directory integrity check
    if (-not (Test-Path $GateRoot -PathType Container)) {
        return @{ action = 'fatal'; message = "Gate root missing: $GateRoot" }
    }
    $RootAttrs = [System.IO.File]::GetAttributes($GateRoot)
    if ($RootAttrs -band [System.IO.FileAttributes]::ReparsePoint) {
        return @{ action = 'fatal'; message = 'Gate root is a reparse point (junction/symlink)' }
    }
    foreach ($dir in $RequiredDirs) {
        $DirPath = Join-Path $GateRoot $dir
        if (-not (Test-Path $DirPath -PathType Container)) {
            return @{ action = 'fatal'; message = "Required directory missing: $dir" }
        }
        $DirAttrs = [System.IO.File]::GetAttributes($DirPath)
        if ($DirAttrs -band [System.IO.FileAttributes]::ReparsePoint) {
            return @{ action = 'fatal'; message = "Directory is a reparse point: $dir" }
        }
    }

    # Step 0: Contract sources (fail closed — no fallback copies)
    $RequiredBaseFields = $null
    try {
        $RequiredBaseFields = Get-RequiredBaseFields
    } catch {
        return @{ action = 'fatal'; message = "INTEGRITY: $($_.Exception.Message)" }
    }

    # Step 1: Compute hash (needed for gate matching and blocked records)
    $Hash = Get-Sha256 $Command

    # Chain context (also surfaced in denial envelopes for recovery)
    $LastCorrelationId = Get-LastExecutableCorrelationId -SessionId $SessionId -Root $GateRoot

    # Step 2: Tier 4 check (before gate matching — unconditional block)
    $TierResult = Get-CommandTier $Command
    if ($TierResult.Tier -eq 4) {
        $Message = "TIER 4 FORBIDDEN: pattern '$($TierResult.MatchedPattern)' matched. This command is unconditionally blocked and cannot be authorized by any gate."
        $record = [ordered]@{
            timestamp_utc     = (Get-Date).ToUniversalTime().ToString('o')
            command           = $Command
            command_sha256    = $Hash
            detected_tier     = 4
            session_id        = $SessionId
            tool_use_id       = $ToolUseId
            tool_name         = $ToolName
            shell             = $Shell
            working_directory = $Cwd
            reason_code       = 'TIER4_FORBIDDEN'
            reason            = $Message
        }
        $blockedResult = Write-HeliosBlockedRecord -Record $record -Hash $Hash -ToolUseId $ToolUseId
        $Reason = New-HeliosDenyReason -Code 'TIER4_FORBIDDEN' -Message $Message -Hash $Hash -Tier 4 `
            -Shell $Shell -Cwd $Cwd -BlockedResult $null -LastCorrelationId $LastCorrelationId
        return @{ action = 'deny'; reason = $Reason; hash = $Hash; tier = 4 }
    }

    $DetectedTier = $TierResult.Tier
    $RequiredFields = $null
    try {
        $RequiredFields = Get-TierRequiredFields $DetectedTier
    } catch {
        return @{ action = 'fatal'; message = "INTEGRITY: $($_.Exception.Message)" }
    }
    $HasWriteIndicator = Test-WriteIndicator $Command

    # Shared builder for the enriched blocked record
    $NewBlockedRecord = {
        param([string]$ReasonCode, [string]$ReasonText, $Diag)
        $r = [ordered]@{
            timestamp_utc       = (Get-Date).ToUniversalTime().ToString('o')
            command             = $Command
            command_sha256      = $Hash
            detected_tier       = $DetectedTier
            session_id          = $SessionId
            tool_use_id         = $ToolUseId
            tool_name           = $ToolName
            shell               = $Shell
            working_directory   = $Cwd
            matched_category    = $TierResult.Name
            matched_template    = $TierResult.MatchedTemplate
            reason_code         = $ReasonCode
            reason              = $ReasonText
            last_correlation_id = $LastCorrelationId
        }
        if ($Diag) {
            $r.closest_gate_file = $Diag.file
            $r.closest_match_type = $Diag.match_type
            $r.reject_reasons = @($Diag.reasons)
            $r.expected_schema_hint = @{ required_base_fields = $RequiredBaseFields }
        }
        return $r
    }

    # Step 3: Scan pending/ for candidate gate by identity, while collecting diagnostics
    $PendingDir = Join-Path $GateRoot 'pending'
    $NowUtc = (Get-Date).ToUniversalTime()
    $MatchedGate = $null
    $MatchedGateFile = $null
    $CandidateDiagnostics = @()

    foreach ($gateFile in (Get-ChildItem $PendingDir -Filter '*.gate.json' -ErrorAction SilentlyContinue)) {
        try {
            $gate = Get-Content $gateFile.FullName -Raw | ConvertFrom-Json
        } catch {
            continue
        }

        $ShaMatch = ($gate.command_sha256 -eq $Hash)
        $CmdMatch = ($gate.command -eq $Command)

        if (-not $ShaMatch -and -not $CmdMatch) {
            continue
        }

        $MatchType = 'command'
        if ($ShaMatch) {
            $MatchType = 'sha256'
        }

        $Reasons = @()

        if (-not $CmdMatch) {
            $Reasons += 'command text mismatch: command_sha256 matched but command text differs'
        }

        if (-not $ShaMatch) {
            $Reasons += "command_sha256 mismatch: gate='$($gate.command_sha256)' expected='$Hash'"
        }

        # Exact schema-version enforcement (canonical value; self-correcting denial)
        if ("$($gate.schema_version)" -ne $script:HeliosGateSchemaVersion) {
            $Reasons += "schema_version mismatch: expected '$($script:HeliosGateSchemaVersion)', found '$($gate.schema_version)'"
        }

        if ($gate.working_directory -ne $Cwd) {
            $Reasons += "working_directory mismatch`n  gate:   $($gate.working_directory)`n  actual: $Cwd"
        }

        if ($gate.shell -ne $Shell) {
            $Reasons += "shell mismatch: gate='$($gate.shell)' actual='$Shell'"
        }

        $PropNames = @($gate.PSObject.Properties.Name)

        if ($PropNames -contains 'tier' -and -not ($PropNames -contains 'risk_tier')) {
            $Reasons += 'field name error: found "tier"; expected "risk_tier"'
        }

        $MissingBase = @()
        foreach ($f in $RequiredBaseFields) {
            if (-not ($PropNames -contains $f)) {
                $MissingBase += $f
                continue
            }

            $val = $gate.$f
            if ($null -eq $val) {
                $MissingBase += $f
            } elseif ($val -is [string] -and [string]::IsNullOrWhiteSpace($val)) {
                $MissingBase += $f
            }
        }

        if ($MissingBase.Count -gt 0) {
            $Reasons += "missing base fields: $($MissingBase -join ', ')"
        }

        $ExpiresUtc = $null
        try {
            $ExpiresUtc = [DateTime]::Parse($gate.expires_utc).ToUniversalTime()
            if ($ExpiresUtc -le $NowUtc) {
                $Reasons += "expired gate`n  expires_utc: $($gate.expires_utc)`n  now_utc:     $($NowUtc.ToString('o'))"
            }
        } catch {
            $Reasons += "expires_utc is missing or unparseable: '$($gate.expires_utc)'"
        }

        $GateTier = $null
        try {
            $GateTier = [int]$gate.risk_tier
            if ($GateTier -lt $DetectedTier) {
                $Reasons += "risk_tier too low: gate=$GateTier detected=$DetectedTier"
            }
        } catch {
            $Reasons += "risk_tier is missing or not an integer: '$($gate.risk_tier)'"
        }

        $MissingRequired = @()
        foreach ($f in $RequiredFields) {
            $val = $gate.$f
            if ($null -eq $val) {
                $MissingRequired += $f
            } elseif ($val -is [string] -and [string]::IsNullOrWhiteSpace($val)) {
                $MissingRequired += $f
            }
        }

        if ($MissingRequired.Count -gt 0) {
            $Reasons += "missing tier-required fields: $($MissingRequired -join ', ')"
        }

        if ($HasWriteIndicator) {
            $rwi = $gate.read_write_impact
            if ($null -eq $rwi -or $null -eq $rwi.writes) {
                $Reasons += 'write indicator detected but read_write_impact.writes is missing'
            } else {
                $writes = @($rwi.writes)
                if ($writes.Count -eq 0) {
                    $Reasons += 'write indicator detected but read_write_impact.writes is empty'
                } elseif ($writes.Count -eq 1 -and $writes[0] -eq 'none') {
                    $Reasons += 'write indicator detected but read_write_impact.writes is ["none"]'
                }
            }
        }

        # Capability-flag enforcement: hidden execution power requires read_write_impact
        if ($TierResult.CapabilityFlags) {
            $HasCapability = $false
            foreach ($flagKey in $TierResult.CapabilityFlags.Keys) {
                if ($TierResult.CapabilityFlags[$flagKey] -eq $true) {
                    $HasCapability = $true
                    break
                }
            }
            if ($HasCapability) {
                $rwi = $gate.read_write_impact
                if ($null -eq $rwi -or $null -eq $rwi.writes) {
                    $capNames = @($TierResult.CapabilityFlags.Keys | Where-Object { $TierResult.CapabilityFlags[$_] -eq $true })
                    $Reasons += "capability detection ($($capNames -join ', ')) requires read_write_impact.writes"
                } else {
                    $writes = @($rwi.writes)
                    if ($writes.Count -eq 0) {
                        $Reasons += 'capability detection active but read_write_impact.writes is empty'
                    } elseif ($writes.Count -eq 1 -and $writes[0] -eq 'none') {
                        $Reasons += 'capability detection active but read_write_impact.writes is ["none"]'
                    }
                }
            }
        }

        if ($Reasons.Count -eq 0) {
            $MatchedGate = $gate
            $MatchedGateFile = $gateFile
            break
        }

        $CandidateDiagnostics += [pscustomobject]@{
            file = $gateFile.Name
            match_type = $MatchType
            reasons = @($Reasons)
        }
    }

    if ($null -eq $MatchedGate) {
        $BestDiag = $null

        foreach ($d in $CandidateDiagnostics) {
            if ($null -eq $BestDiag) {
                $BestDiag = $d
                continue
            }

            if ($d.match_type -eq 'sha256' -and $BestDiag.match_type -ne 'sha256') {
                $BestDiag = $d
            }
        }

        if ($null -ne $BestDiag) {
            $DiagLines = @(
                "GATE REJECTED: closest gate $($BestDiag.file) matched $($BestDiag.match_type) but failed validation:"
            )
            foreach ($r in $BestDiag.reasons) {
                $DiagLines += "- $r"
            }
            $Message = $DiagLines -join "`n"

            $record = & $NewBlockedRecord 'GATE_REJECTED' $Message $BestDiag
            $blockedResult = Write-HeliosBlockedRecord -Record $record -Hash $Hash -ToolUseId $ToolUseId

            $Reason = New-HeliosDenyReason -Code 'GATE_REJECTED' -Message $Message -Hash $Hash `
                -Tier $DetectedTier -Shell $Shell -Cwd $Cwd -BlockedResult $blockedResult `
                -LastCorrelationId $LastCorrelationId -Extra ([ordered]@{
                    closest_gate = $BestDiag.file
                    reject_reasons = @($BestDiag.reasons)
                })
            return @{ action = 'deny'; reason = $Reason; display = $Message; hash = $Hash; tier = $DetectedTier }
        }

        # --- Template mode: reuse existing functions to build a gate template ---
        $TemplateSegments = @($Command)
        $TemplateMultiCommand = $false
        try {
            . (Join-Path $GateRoot 'hooks\command_decomposer.ps1')
            $Decomp = Get-CommandDecomposition -Command $Command -DeclaredSegments @()
            $TemplateSegments = @($Decomp.segments_detected)
            $TemplateMultiCommand = ($Decomp.segment_count -gt 1)
        } catch {}

        $TemplateEnabled = $false
        $TemplateExitSuffixes = @()
        $TemplateNaReasons = @()
        try {
            $TemplatePolicyPath = Join-Path $GateRoot 'policy\command-policy.json'
            if (Test-Path $TemplatePolicyPath) {
                $TemplatePolicy = Get-Content $TemplatePolicyPath -Raw | ConvertFrom-Json
                if ($TemplatePolicy.exit_capture_suffixes.$Shell) {
                    $TemplateExitSuffixes = @($TemplatePolicy.exit_capture_suffixes.$Shell)
                }
                if ($TemplatePolicy.exit_capture_not_applicable_reasons) {
                    $TemplateNaReasons = @($TemplatePolicy.exit_capture_not_applicable_reasons)
                }
                if ($TemplatePolicy.template_mode -eq $true) {
                    $TemplateEnabled = $true
                }
            }
        } catch {}

        $TemplateSuggestion = ''
        if ($TierResult.MatchedTemplate) {
            $TemplateSuggestion = $TierResult.MatchedTemplate
        } elseif ($TierResult.Name) {
            $TemplateSuggestion = $TierResult.Name
        }

        $ChainRequired = ($null -ne $LastCorrelationId -and $LastCorrelationId.Length -gt 0)
        $ChainDisplay = if ($ChainRequired) { "yes (previous: $LastCorrelationId)" } else { 'no' }

        $HeaderLines = @(
            "GATE REQUIRED"
            "  Tier           : $DetectedTier ($TemplateSuggestion)"
            "  CWD            : $Cwd"
            "  Shell          : $Shell"
            "  Multi-command  : $($TemplateMultiCommand.ToString().ToLower())"
            "  Write indicator: $($HasWriteIndicator.ToString().ToLower())"
            "  Chain required : $ChainDisplay"
        )

        $Extra = $null
        if ($TemplateEnabled) {
            $HasSuffix = $false
            foreach ($s in $TemplateExitSuffixes) {
                if ($Command.EndsWith($s)) { $HasSuffix = $true; break }
            }
            $NaReasonList = $TemplateNaReasons -join ' | '

            $GateTemplate = [ordered]@{
                schema_version    = $script:HeliosGateSchemaVersion
                correlation_id    = '<unique-id e.g. 20260913-task-001>'
                created_utc       = '<ISO 8601 UTC e.g. 2026-09-13T14:00:00Z>'
                expires_utc       = '<ISO 8601 UTC must be in the future>'
                command           = $Command
                command_sha256    = '<leave empty - returned on valid schema submission>'
                working_directory = $Cwd
                shell             = $Shell
                risk_tier         = $DetectedTier
                multi_command     = $TemplateMultiCommand
                segments          = $TemplateSegments
            }
            if ($HasSuffix) {
                $GateTemplate['exit_capture'] = 'suffix'
            } else {
                $GateTemplate['exit_capture'] = 'not_applicable'
                $GateTemplate['exit_capture_reason'] = "<$NaReasonList>"
            }
            $GateTemplate['need']         = '<why this command is needed right now>'
            $GateTemplate['expected']     = '<what output or result you expect>'
            $GateTemplate['actual_means'] = '<what this command actually does and what its output means>'
            $GateTemplate['next_logic']   = '<what happens after this command based on the result>'
            if ($DetectedTier -ge 2) {
                $GateTemplate['stop_conditions'] = '<when to stop or abort - error thresholds, failure criteria>'
            }
            if ($DetectedTier -ge 3 -or $HasWriteIndicator) {
                $GateTemplate['read_write_impact'] = [ordered]@{
                    reads  = @('<paths or resources read>')
                    writes = @('<paths or resources created, modified, or deleted>')
                }
            }
            $GateTemplate['approval_boundary'] = '<scope of what this gate authorizes e.g. read-only diagnostic>'
            if ($ChainRequired) {
                $GateTemplate['previous_correlation_id'] = $LastCorrelationId
            } else {
                $GateTemplate['new_chain'] = $true
            }

            $GateSlug = Get-SafeGateSlug $Command
            $PendingDir = Join-Path $GateRoot 'pending'
            $GatePath = Join-Path $PendingDir "$GateSlug.gate.json"
            $TemplateDisplay = ($GateTemplate | ConvertTo-Json -Depth 3)

            $HeaderLines += ""
            $HeaderLines += "Complete the template below, write to: $GatePath, then retry the same command."

            $Extra = [ordered]@{ template = $GateTemplate }
        } else {
            $HeaderLines += "  Template       : off (set template_mode:true in command-policy.json)"
        }

        if ($TemplateEnabled) {
            $HeaderBlock = ($HeaderLines -join "`n")
            $Message = "$HeaderBlock`n$TemplateDisplay"
        } else {
            $Message = $HeaderLines -join "`n"
        }
        $record = & $NewBlockedRecord 'GATE_REQUIRED' $Message $null
        if ($TemplateEnabled) { $record['template'] = $GateTemplate }
        $blockedResult = Write-HeliosBlockedRecord -Record $record -Hash $Hash -ToolUseId $ToolUseId

        $Reason = New-HeliosDenyReason -Code 'GATE_REQUIRED' -Message $Message -Hash $Hash `
            -Tier $DetectedTier -Shell $Shell -Cwd $Cwd -BlockedResult $blockedResult `
            -LastCorrelationId $LastCorrelationId -Extra $Extra
        return @{ action = 'deny'; reason = $Reason; display = $Message; hash = $Hash; tier = $DetectedTier }
    }

    # Step 4: Exit-capture mode enforcement
    $PolicyPath = Join-Path $GateRoot 'policy\command-policy.json'
    $ExitSuffixes = @()
    $ValidNaReasons = @()
    $WrapperMustContain = $null
    $WrapperMustEndWith = $null
    try {
        $PolicyJson = Get-Content $PolicyPath -Raw | ConvertFrom-Json
        if ($PolicyJson.exit_capture_suffixes.$Shell) {
            $ExitSuffixes = @($PolicyJson.exit_capture_suffixes.$Shell)
        }
        if ($PolicyJson.exit_capture_not_applicable_reasons) {
            $ValidNaReasons = @($PolicyJson.exit_capture_not_applicable_reasons)
        }
        if ($PolicyJson.wrapper_validators.$Shell) {
            $WrapperMustContain = $PolicyJson.wrapper_validators.$Shell.must_contain
            $WrapperMustEndWith = $PolicyJson.wrapper_validators.$Shell.must_end_with
        }
    } catch {}

    $DenyRejected = {
        param([string]$ReasonText)
        $record = & $NewBlockedRecord 'GATE_REJECTED' $ReasonText $null
        $blockedResult = Write-HeliosBlockedRecord -Record $record -Hash $Hash -ToolUseId $ToolUseId
        $Reason = New-HeliosDenyReason -Code 'GATE_REJECTED' -Message $ReasonText -Hash $Hash `
            -Tier $DetectedTier -Shell $Shell -Cwd $Cwd -BlockedResult $blockedResult `
            -LastCorrelationId $LastCorrelationId
        return @{ action = 'deny'; reason = $Reason; hash = $Hash; tier = $DetectedTier }
    }

    $ExitCaptureMode = $MatchedGate.exit_capture
    $IsWrapperMode = $false

    if ($ExitCaptureMode -eq 'wrapper_required') {
        $IsWrapperMode = $true
        $WrapperOk = $true
        $WrapperFail = ''
        if ($WrapperMustContain -and -not $Command.Contains($WrapperMustContain)) {
            $WrapperOk = $false
            $WrapperFail = "command does not contain '$WrapperMustContain'"
        }
        $TrimmedCommand = $Command.TrimEnd()
        if ($WrapperMustEndWith -and -not $TrimmedCommand.EndsWith($WrapperMustEndWith)) {
            $WrapperOk = $false
            $WrapperFail = "command does not end with '$WrapperMustEndWith'"
        }
        if (-not $WrapperOk) {
            return (& $DenyRejected "WRAPPER VALIDATION FAILED: exit_capture=wrapper_required but $WrapperFail. SHA256: $Hash")
        }
        $WrappedCmd = $MatchedGate.wrapped_command
        $WrappedHash = $MatchedGate.wrapped_command_sha256
        $WrapperReason = $MatchedGate.wrapper_reason
        if ([string]::IsNullOrWhiteSpace($WrappedCmd)) {
            return (& $DenyRejected "WRAPPER IDENTITY: exit_capture=wrapper_required but no wrapped_command declared. The gate must document the semantic command being wrapped. SHA256: $Hash")
        }
        if ([string]::IsNullOrWhiteSpace($WrappedHash)) {
            return (& $DenyRejected "WRAPPER IDENTITY: exit_capture=wrapper_required but no wrapped_command_sha256 declared. SHA256: $Hash")
        }
        $ExpectedWrappedHash = Get-Sha256 $WrappedCmd
        if ($WrappedHash -ne $ExpectedWrappedHash) {
            return (& $DenyRejected "WRAPPER IDENTITY: wrapped_command_sha256 does not match the hash of wrapped_command. Declared: $WrappedHash, Computed: $ExpectedWrappedHash. SHA256: $Hash")
        }
        if (-not $Command.Contains($WrappedCmd)) {
            return (& $DenyRejected "WRAPPER IDENTITY: wrapped_command is not found inside the full command. The wrapper must contain the declared semantic command. SHA256: $Hash")
        }
        if ([string]::IsNullOrWhiteSpace($WrapperReason)) {
            return (& $DenyRejected "WRAPPER IDENTITY: exit_capture=wrapper_required but no wrapper_reason declared. SHA256: $Hash")
        }
    } elseif ($ExitCaptureMode -eq 'not_applicable') {
        $ecReason = $MatchedGate.exit_capture_reason
        if ([string]::IsNullOrWhiteSpace($ecReason)) {
            return (& $DenyRejected "EXIT CAPTURE: gate declares exit_capture=not_applicable but no exit_capture_reason provided. SHA256: $Hash")
        }
        if ($ValidNaReasons.Count -gt 0 -and $ecReason -notin $ValidNaReasons) {
            return (& $DenyRejected "EXIT CAPTURE: exit_capture_reason '$ecReason' is not in the approved list ($($ValidNaReasons -join ', ')). SHA256: $Hash")
        }
    } else {
        $HasExitSuffix = $false
        foreach ($suffix in $ExitSuffixes) {
            if ($Command.EndsWith($suffix)) {
                $HasExitSuffix = $true
                break
            }
        }
        if (-not $HasExitSuffix) {
            $SuffixHint = ($ExitSuffixes | ForEach-Object { "'$_'" }) -join ' or '
            return (& $DenyRejected "EXIT CAPTURE REQUIRED: command does not end with an approved exit-capture suffix ($SuffixHint) and gate does not declare exit_capture=wrapper_required or not_applicable. SHA256: $Hash")
        }
    }

    # Step 5: Chain validation and segment decomposition
    . (Join-Path $GateRoot 'hooks\command_decomposer.ps1')

    $DeclaredSegments = @()
    if ($MatchedGate.segments) { $DeclaredSegments = @($MatchedGate.segments) }
    $Decomposition = Get-CommandDecomposition -Command $Command -DeclaredSegments $DeclaredSegments

    if (-not $IsWrapperMode) {
        $IsChained = Test-ChainViolation $Command
        if ($IsChained) {
            if ($MatchedGate.multi_command -ne $true -or $DeclaredSegments.Count -eq 0) {
                return (& $DenyRejected "UNDECLARED CHAINING: command contains chained operators (;, &&, ||, |) but the gate does not declare multi_command:true with segments. SHA256: $Hash")
            }
            if (-not $Decomposition.segments_match) {
                $detectedList = ($Decomposition.segments_detected | ForEach-Object { "'$_'" }) -join ', '
                $declaredList = ($DeclaredSegments | ForEach-Object { "'$_'" }) -join ', '
                return (& $DenyRejected "SEGMENT MISMATCH: declared segments do not match decomposed command structure. Detected: [$detectedList] Declared: [$declaredList]. SHA256: $Hash")
            }
        }

        if ($Decomposition.ambiguous_parse -and $DetectedTier -lt 1) {
            $rwi = $MatchedGate.read_write_impact
            if ($null -eq $rwi -or $null -eq $rwi.writes) {
                return (& $DenyRejected "AMBIGUOUS COMMAND: cannot safely decompose; requires tier >= 1 or explicit read_write_impact. SHA256: $Hash")
            }
        }
    }

    # Step 5b: Evidence chain linkage
    if ($SessionId -and $null -ne $LastCorrelationId) {
        $hasPrevCorr = ($null -ne $MatchedGate.previous_correlation_id -and $MatchedGate.previous_correlation_id.Length -gt 0)
        $hasNewChain = ($MatchedGate.new_chain -eq $true)
        if (-not $hasPrevCorr -and -not $hasNewChain) {
            return (& $DenyRejected "CHAIN LINKAGE: previous evidence exists (correlation_id: $LastCorrelationId) but gate declares neither previous_correlation_id nor new_chain:true. SHA256: $Hash")
        }
    }

    # Step 6: Terminal write field verification
    # The gate declares data_sha256, terminal_id, enter for /term/*/write.
    # The hook recomputes from the command AST (Parser.ParseInput) and rejects
    # on mismatch. Non-write commands must not carry these fields. The hook
    # always overwrites the gate's declared values with the computed ones, so
    # an agent-declared hash can never survive unchecked into inflight/.
    $IsTermWrite = $Command -match '/term/[^/]+/write'
    $GateDataSha = $MatchedGate.data_sha256
    $GateTermId  = $MatchedGate.terminal_id
    $GateEnter   = $MatchedGate.enter

    if (-not $IsTermWrite) {
        if ($null -ne $GateDataSha -or $null -ne $GateTermId -or $null -ne $GateEnter) {
            return (& $DenyRejected "WRITE FIELD: gate declares terminal write fields (data_sha256/terminal_id/enter) but command is not a terminal write. SHA256: $Hash")
        }
    } else {
        if ($null -eq $GateDataSha) {
            return (& $DenyRejected "WRITE FIELD: terminal write requires data_sha256 in gate. SHA256: $Hash")
        }
        if ($null -eq $GateTermId) {
            return (& $DenyRejected "WRITE FIELD: terminal write requires terminal_id in gate. SHA256: $Hash")
        }
        if ($null -eq $GateEnter) {
            return (& $DenyRejected "WRITE FIELD: terminal write requires enter in gate. SHA256: $Hash")
        }

        $tokens = $null; $parseErrors = $null
        $cmdAst = [System.Management.Automation.Language.Parser]::ParseInput(
            $Command, [ref]$tokens, [ref]$parseErrors
        ).FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true) |
            Select-Object -First 1

        $ActualTermId = $null; $ActualData = $null; $ActualEnter = $null

        if ($cmdAst) {
            $elements = @($cmdAst.CommandElements)
            for ($i = 0; $i -lt $elements.Count; $i++) {
                $el = $elements[$i]
                if ($el -isnot [System.Management.Automation.Language.CommandParameterAst]) { continue }
                $pName = $el.ParameterName
                $argAst = if ($el.Argument) { $el.Argument }
                          elseif ($i + 1 -lt $elements.Count -and
                                  $elements[$i + 1] -isnot [System.Management.Automation.Language.CommandParameterAst]) {
                              $elements[$i + 1]
                          } else { $null }

                if ($pName -ieq 'Uri' -and $argAst) {
                    $uriText = $argAst.Extent.Text.Trim("'`"")
                    if ($uriText -match '/term/([^/]+)/write') {
                        $ActualTermId = $Matches[1]
                    }
                }

                if ($pName -ieq 'Body' -and $argAst) {
                    $htAst = $argAst.FindAll(
                        { $args[0] -is [System.Management.Automation.Language.HashtableAst] }, $true
                    ) | Select-Object -First 1
                    if ($htAst) {
                        foreach ($kvp in $htAst.KeyValuePairs) {
                            $kText = $kvp.Item1.Extent.Text.Trim("'`"")
                            if ($kText -eq 'data') {
                                $vText = $kvp.Item2.Extent.Text
                                if ($vText.Length -ge 2 -and $vText[0] -eq "'") {
                                    $ActualData = $vText.Substring(1, $vText.Length - 2) -replace "''", "'"
                                }
                            }
                            if ($kText -eq 'enter') {
                                $eText = $kvp.Item2.Extent.Text.Trim()
                                if ($eText -eq '$true'  -or $eText -match '^\(\s*1\s+-eq\s+1\s*\)$') { $ActualEnter = $true }
                                if ($eText -eq '$false' -or $eText -match '^\(\s*1\s+-eq\s+0\s*\)$') { $ActualEnter = $false }
                            }
                        }
                    }
                }
            }
        }

        if ($null -eq $ActualTermId) {
            return (& $DenyRejected "WRITE FIELD: cannot extract terminal_id from command URI. SHA256: $Hash")
        }
        if ($GateTermId -ne $ActualTermId) {
            return (& $DenyRejected "WRITE FIELD: terminal_id mismatch: gate='$GateTermId' command='$ActualTermId'. SHA256: $Hash")
        }
        if ($null -eq $ActualEnter) {
            return (& $DenyRejected "WRITE FIELD: cannot extract enter from command body. SHA256: $Hash")
        }
        if ($GateEnter -ne $ActualEnter) {
            return (& $DenyRejected "WRITE FIELD: enter mismatch: gate=$GateEnter command=$ActualEnter. SHA256: $Hash")
        }
        if ($null -eq $ActualData) {
            return (& $DenyRejected "WRITE FIELD: cannot extract data from command body. SHA256: $Hash")
        }
        $ActualDataSha = Get-Sha256 -Text $ActualData
        if ($GateDataSha -ne $ActualDataSha) {
            return (& $DenyRejected "WRITE FIELD: data_sha256 mismatch: gate='$GateDataSha' computed='$ActualDataSha'. SHA256: $Hash")
        }

        try {
            $Utf8NoBom = [System.Text.UTF8Encoding]::new($false)
            $gateText = [System.IO.File]::ReadAllText($MatchedGateFile.FullName, [System.Text.Encoding]::UTF8)
            $gateObj = $gateText | ConvertFrom-Json
            $gateObj | Add-Member -NotePropertyName 'data_sha256'  -NotePropertyValue $ActualDataSha  -Force
            $gateObj | Add-Member -NotePropertyName 'terminal_id'  -NotePropertyValue $ActualTermId   -Force
            $gateObj | Add-Member -NotePropertyName 'enter'        -NotePropertyValue $ActualEnter    -Force
            [System.IO.File]::WriteAllText(
                $MatchedGateFile.FullName,
                ($gateObj | ConvertTo-Json -Depth 10),
                $Utf8NoBom)
        } catch {
            return (& $DenyRejected "WRITE FIELD: failed to stamp verified fields into gate: $_. SHA256: $Hash")
        }
    }

    $InflightDir = Join-Path $GateRoot 'inflight'
    $InflightName = $MatchedGateFile.Name
    if ($ToolUseId) {
        $InflightName = "$ToolUseId-$InflightName"
    }
    $InflightPath = Join-Path $InflightDir $InflightName
    Move-Item -Path $MatchedGateFile.FullName -Destination $InflightPath -Force

    return @{
        action              = 'allow'
        hash                = $Hash
        tier                = $DetectedTier
        correlation_id      = $MatchedGate.correlation_id
        capability_flags    = $TierResult.CapabilityFlags
        reason_codes        = $TierResult.ReasonCodes
        capability_escalated = $TierResult.CapabilityEscalated
        control_plane_paths = $TierResult.ControlPlanePaths
        decomposition       = $Decomposition
    }
}

# --- Standalone execution ---
# When invoked directly (not dot-sourced by helios_pretooluse.ps1),
# load tier_classifier, read stdin, and run gate validation.
if (-not $HeliosFrontControllerActive) {
    . (Join-Path $GateRoot 'hooks\tier_classifier.ps1')

    $RawInput = $null
    try {
        $RawInput = [Console]::In.ReadToEnd()
    } catch {
        DenyFatal 'Cannot read stdin'
    }

    if ([string]::IsNullOrWhiteSpace($RawInput)) {
        DenyFatal 'Empty stdin'
    }

    $StandalonePayload = $null
    try {
        $StandalonePayload = $RawInput | ConvertFrom-Json
    } catch {
        DenyFatal "Cannot parse hook payload: $($_.Exception.Message)"
    }

    $Result = Invoke-GateValidation -Payload $StandalonePayload

    switch ($Result.action) {
        'passthrough' { Write-Output '{}'; exit 0 }
        'allow'       { Write-Output '{}'; exit 0 }
        'deny'        { Deny $Result.reason }
        'fatal'       { DenyFatal $Result.message }
        default       { DenyFatal "Unexpected gate result: $($Result.action)" }
    }
}
