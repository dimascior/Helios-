# session_continuity.ps1 — Dot-sourced by helios_pretooluse.ps1 and evidence_capture.ps1
# Exports: Write-SessionLedgerEntry, Test-SessionContinuity, Get-SessionLedger

$script:Utf8NoBomLedger = New-Object System.Text.UTF8Encoding($false)

function Write-SessionLedgerEntry {
    param(
        [string]$GateRoot,
        [string]$SessionId,
        [string]$EventType,
        [hashtable]$Data
    )

    $SessionDir = Join-Path $GateRoot 'session'
    if (-not (Test-Path $SessionDir)) {
        New-Item -ItemType Directory -Path $SessionDir -Force | Out-Null
    }

    $LedgerPath = Join-Path $SessionDir "session-ledger-$SessionId.jsonl"

    $Entry = [ordered]@{
        event_type    = $EventType
        timestamp_utc = (Get-Date).ToUniversalTime().ToString('o')
        session_id    = $SessionId
    }
    foreach ($key in $Data.Keys) {
        $Entry[$key] = $Data[$key]
    }

    $line = ($Entry | ConvertTo-Json -Depth 5 -Compress)
    [System.IO.File]::AppendAllText($LedgerPath, "$line`n", $script:Utf8NoBomLedger)
}

function Get-SessionLedger {
    param(
        [string]$GateRoot,
        [string]$SessionId
    )

    $LedgerPath = Join-Path $GateRoot "session\session-ledger-$SessionId.jsonl"
    if (-not (Test-Path $LedgerPath)) { return @() }

    $entries = @()
    foreach ($line in (Get-Content $LedgerPath)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        try { $entries += ($line | ConvertFrom-Json) } catch {}
    }
    return $entries
}

function Test-SessionContinuity {
    param(
        [string]$GateRoot,
        [string]$SessionId
    )

    $Entries = Get-SessionLedger -GateRoot $GateRoot -SessionId $SessionId
    if ($Entries.Count -eq 0) {
        return @{
            status             = 'no_ledger'
            total_commands     = 0
            evidence_gaps      = @()
            continuity_verdict = 'NO_DATA'
        }
    }

    $gaps = @()
    $commandCount = 0
    $pendingPre = $null
    $pendingGate = $null
    $forcefieldDroppedAt = $null

    foreach ($entry in $Entries) {
        switch ($entry.event_type) {
            'pretooluse_seen' {
                if ($null -ne $pendingPre -and $null -eq $pendingGate) {
                    $gaps += @{
                        type           = 'pretooluse_without_gate'
                        command_sha256 = $pendingPre.command_sha256
                        timestamp      = $pendingPre.timestamp_utc
                    }
                }
                $pendingPre = $entry
                $pendingGate = $null
                $commandCount++
            }
            'gate_consumed' {
                $pendingGate = $entry
            }
            'posttooluse_evidence_written' {
                $hookAfter = $true
                if ($null -ne $entry.hook_presence_after) {
                    $hookAfter = [bool]$entry.hook_presence_after
                }
                if (-not $hookAfter -and $null -eq $forcefieldDroppedAt) {
                    $forcefieldDroppedAt = $entry.correlation_id
                    $gaps += @{
                        type           = 'forcefield_dropped'
                        correlation_id = $entry.correlation_id
                        timestamp      = $entry.timestamp_utc
                    }
                }
                $pendingPre = $null
                $pendingGate = $null
            }
        }
    }

    if ($null -ne $pendingPre) {
        $gaps += @{
            type           = 'pretooluse_without_posttooluse'
            command_sha256 = $pendingPre.command_sha256
            timestamp      = $pendingPre.timestamp_utc
        }
    }

    $verdict = if ($gaps.Count -eq 0) { 'CONTINUOUS' } else { 'BROKEN' }

    return @{
        status                = 'checked'
        total_commands        = $commandCount
        evidence_gaps         = $gaps
        continuity_verdict    = $verdict
        forcefield_dropped_at = $forcefieldDroppedAt
    }
}
