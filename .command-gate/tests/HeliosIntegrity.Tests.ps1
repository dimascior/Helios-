#requires -Module Pester

Describe "Helios Integrity Bridge" {

    BeforeAll {
        $script:GateRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
        $BridgePath = Join-Path $script:GateRoot '.command-gate\hooks\lib\HeliosIntegrityBridge.ps1'

        $script:TestRoot = Join-Path ([System.IO.Path]::GetTempPath()) "helios-test-$([guid]::NewGuid().ToString('N').Substring(0,8))"
        New-Item -ItemType Directory -Path $script:TestRoot -Force | Out-Null

        foreach ($dir in @('hooks', 'hooks\lib', 'policy', 'manifest', 'pending', 'inflight', 'evidence', 'blocked')) {
            New-Item -ItemType Directory -Path (Join-Path $script:TestRoot $dir) -Force | Out-Null
        }

        . $BridgePath

        $script:ProtectedFiles = @{
            'hooks/gate_check.ps1'      = 'gate_check content'
            'hooks/tier_classifier.ps1' = 'tier_classifier content'
            'policy/command-policy.json' = '{"schema_version":"command-policy.v1"}'
        }

        $sha = [System.Security.Cryptography.SHA256]::Create()
        $script:ExpectedHashes = @{}
        foreach ($relPath in $script:ProtectedFiles.Keys) {
            $fullPath = Join-Path $script:TestRoot ($relPath -replace '/', '\')
            $content = $script:ProtectedFiles[$relPath]
            [System.IO.File]::WriteAllBytes($fullPath, [System.Text.Encoding]::UTF8.GetBytes($content))
            $bytes = [System.IO.File]::ReadAllBytes($fullPath)
            $hash = ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join ''
            $script:ExpectedHashes[$relPath] = $hash
        }

        New-Item -ItemType File -Path (Join-Path $script:TestRoot 'pending\test.gate.json') -Force | Out-Null
        New-Item -ItemType File -Path (Join-Path $script:TestRoot 'evidence\test.result.json') -Force | Out-Null
    }

    AfterAll {
        if ($script:TestRoot -and (Test-Path $script:TestRoot)) {
            Remove-Item -Recurse -Force $script:TestRoot -ErrorAction SilentlyContinue
        }
    }

    Context "Get-FileSha256" {
        It "produces lowercase 64-char hex hash" {
            $testFile = Join-Path $script:TestRoot 'hooks\gate_check.ps1'
            $hash = Get-FileSha256 -Path $testFile
            $hash | Should -Match '^[0-9a-f]{64}$'
        }

        It "produces consistent hashes for same content" {
            $testFile = Join-Path $script:TestRoot 'hooks\gate_check.ps1'
            $hash1 = Get-FileSha256 -Path $testFile
            $hash2 = Get-FileSha256 -Path $testFile
            $hash1 | Should -Be $hash2
        }
    }

    Context "Get-HeliosEnvelopeSnapshot" {
        It "returns protected file hashes and mutable directory state" {
            $snapshot = Get-HeliosEnvelopeSnapshot -GateRoot $script:TestRoot -ManifestHashes $script:ExpectedHashes `
                -SessionId 'test-session' -ToolUseId 'test-tool' -CommandSha256 'abc123'

            $snapshot.protected.Count | Should -Be $script:ExpectedHashes.Count
            $snapshot.mutable.Keys | Should -Contain 'pending'
            $snapshot.mutable.Keys | Should -Contain 'evidence'
            $snapshot.mutable.Keys | Should -Contain 'inflight'
            $snapshot.mutable.Keys | Should -Contain 'blocked'
            $snapshot.mutable.pending.count | Should -BeGreaterThan 0
            $snapshot.session_id | Should -Be 'test-session'
            $snapshot.tool_use_id | Should -Be 'test-tool'
        }
    }

    Context "Compare-HeliosProtectedEnvelope" {
        It "returns CLEAN when all hashes match" {
            $snapshot = Get-HeliosEnvelopeSnapshot -GateRoot $script:TestRoot -ManifestHashes $script:ExpectedHashes

            $result = Compare-HeliosProtectedEnvelope -CurrentSnapshot $snapshot -ManifestHashes $script:ExpectedHashes

            $result.verdict | Should -Be 'CLEAN'
            $result.checked_against_manifest | Should -Be $true
            $result.details.Count | Should -Be $script:ExpectedHashes.Count
            foreach ($d in $result.details) {
                $d.drift_source.Count | Should -Be 0
            }
        }

        It "returns DRIFT when one hash differs" {
            $snapshot = Get-HeliosEnvelopeSnapshot -GateRoot $script:TestRoot -ManifestHashes $script:ExpectedHashes

            $tamperedHashes = @{}
            foreach ($k in $script:ExpectedHashes.Keys) { $tamperedHashes[$k] = $script:ExpectedHashes[$k] }
            $tamperedHashes['hooks/gate_check.ps1'] = 'aaaa' + $tamperedHashes['hooks/gate_check.ps1'].Substring(4)

            $result = Compare-HeliosProtectedEnvelope -CurrentSnapshot $snapshot -ManifestHashes $tamperedHashes

            $result.verdict | Should -Be 'DRIFT'
            # PS 5.1: a single filtered result is not auto-wrapped, so $x.Count would
            # return the hashtable key-count (6) and $x[0] would be $null. Coerce to array.
            $drifted = @($result.details | Where-Object { $_.drift_source.Count -gt 0 })
            $drifted.Count | Should -Be 1
            $drifted[0].path | Should -Be 'hooks/gate_check.ps1'
            $drifted[0].drift_source | Should -Contain 'MANIFEST'
        }

        It "checks baseline when provided" {
            $snapshot = Get-HeliosEnvelopeSnapshot -GateRoot $script:TestRoot -ManifestHashes $script:ExpectedHashes

            $baselineHashes = @{}
            foreach ($k in $script:ExpectedHashes.Keys) { $baselineHashes[$k] = $script:ExpectedHashes[$k] }
            $baselineHashes['policy/command-policy.json'] = '0000000000000000000000000000000000000000000000000000000000000000'

            $result = Compare-HeliosProtectedEnvelope -CurrentSnapshot $snapshot -ManifestHashes $script:ExpectedHashes -BaselineHashes $baselineHashes

            $result.verdict | Should -Be 'DRIFT'
            $result.checked_against_baseline | Should -Be $true
            $drifted = @($result.details | Where-Object { 'BASELINE' -in $_.drift_source })
            $drifted.Count | Should -Be 1
            $drifted[0].path | Should -Be 'policy/command-policy.json'
        }
    }

    Context "Compare-HeliosRuntimeTransition" {
        It "returns EXPECTED for valid ALLOW_POSTTOOL movement" {
            $before = @{
                pending  = @{ count = 2; files = @('test.gate.json', 'other.gate.json') }
                inflight = @{ count = 1; files = @('running.gate.json') }
                evidence = @{ count = 5; files = @('a.json','b.json','c.json','d.json','e.json') }
                blocked  = @{ count = 0; files = @() }
            }
            $after = @{
                pending  = @{ count = 2; files = @('test.gate.json', 'other.gate.json') }
                inflight = @{ count = 0; files = @() }
                evidence = @{ count = 7; files = @('a.json','b.json','c.json','d.json','e.json','running.gate.json','running.result.json') }
                blocked  = @{ count = 0; files = @() }
            }

            $result = Compare-HeliosRuntimeTransition -BeforeMutable $before -AfterMutable $after -ExpectedMutationProfile 'ALLOW_POSTTOOL'

            $result.verdict | Should -Be 'EXPECTED'
            $result.profile | Should -Be 'ALLOW_POSTTOOL'
        }

        It "returns UNEXPECTED when evidence loses files during ALLOW_POSTTOOL" {
            $before = @{
                pending  = @{ count = 1; files = @('a.json') }
                inflight = @{ count = 0; files = @() }
                evidence = @{ count = 5; files = @('a.json','b.json','c.json','d.json','e.json') }
                blocked  = @{ count = 0; files = @() }
            }
            $after = @{
                pending  = @{ count = 1; files = @('a.json') }
                inflight = @{ count = 0; files = @() }
                evidence = @{ count = 3; files = @('a.json','b.json','c.json') }
                blocked  = @{ count = 0; files = @() }
            }

            $result = Compare-HeliosRuntimeTransition -BeforeMutable $before -AfterMutable $after -ExpectedMutationProfile 'ALLOW_POSTTOOL'

            $result.verdict | Should -Be 'UNEXPECTED'
        }
    }

    Context "New-HeliosSessionBaseline" {
        It "creates baseline only when manifest is clean" {
            $result = New-HeliosSessionBaseline -GateRoot $script:TestRoot -ManifestHashes $script:ExpectedHashes `
                -SessionId 'baseline-test' -ToolUseId 'tool-001' -CommandSha256 'deadbeef'

            $result.created | Should -Be $true
            $result.path | Should -Not -BeNullOrEmpty
            Test-Path $result.path | Should -Be $true

            $baseline = Get-Content $result.path -Raw | ConvertFrom-Json
            $baseline.schema_version | Should -Be 'helios-baseline.v1'
            $baseline.session_id | Should -Be 'baseline-test'
            @($baseline.protected_hashes.PSObject.Properties).Count | Should -Be $script:ExpectedHashes.Count
        }

        It "refuses baseline when manifest has drift" {
            $wrongHashes = @{}
            foreach ($k in $script:ExpectedHashes.Keys) { $wrongHashes[$k] = '0' * 64 }

            $result = New-HeliosSessionBaseline -GateRoot $script:TestRoot -ManifestHashes $wrongHashes `
                -SessionId 'fail-test' -ToolUseId 'tool-002'

            $result.created | Should -Be $false
            $result.reason | Should -Match 'does not match'
        }
    }

    Context "Test-HeliosIntegrity" {
        It "returns true when all files match" {
            $result = Test-HeliosIntegrity -GateRoot $script:TestRoot -ManifestHashes $script:ExpectedHashes
            $result | Should -Be $true
        }

        It "returns false when a file has been modified" {
            $targetPath = Join-Path $script:TestRoot 'hooks\gate_check.ps1'
            $original = [System.IO.File]::ReadAllBytes($targetPath)
            try {
                [System.IO.File]::WriteAllBytes($targetPath, [System.Text.Encoding]::UTF8.GetBytes('tampered content'))
                $result = Test-HeliosIntegrity -GateRoot $script:TestRoot -ManifestHashes $script:ExpectedHashes
                $result | Should -Be $false
            } finally {
                [System.IO.File]::WriteAllBytes($targetPath, $original)
            }
        }

        It "returns false when a file is missing" {
            $targetPath = Join-Path $script:TestRoot 'hooks\gate_check.ps1'
            $original = [System.IO.File]::ReadAllBytes($targetPath)
            try {
                Remove-Item $targetPath -Force
                $result = Test-HeliosIntegrity -GateRoot $script:TestRoot -ManifestHashes $script:ExpectedHashes
                $result | Should -Be $false
            } finally {
                [System.IO.File]::WriteAllBytes($targetPath, $original)
            }
        }
    }

    Context "Write-HeliosIntegrityEvidence" {
        It "writes before, decision, after, and compare files" {
            $sessionId = 'evidence-test'
            $toolUseId = 'tool-ev-001'

            foreach ($type in @('before', 'decision', 'after', 'compare')) {
                $data = @{ type = $type; tool_use_id = $toolUseId; timestamp = (Get-Date).ToString('o') }
                $path = Write-HeliosIntegrityEvidence -GateRoot $script:TestRoot -SessionId $sessionId `
                    -ToolUseId $toolUseId -EvidenceType $type -Data $data

                $path | Should -Not -BeNullOrEmpty
                Test-Path $path | Should -Be $true
                $content = Get-Content $path -Raw | ConvertFrom-Json
                $content.type | Should -Be $type
            }
        }
    }
}

Describe "Helios Maintenance Corridor" {

    BeforeAll {
        $script:GateRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
        $script:HookPath = Join-Path $script:GateRoot '.command-gate\hooks\helios_pretooluse.ps1'

        $script:MaintRoot = Join-Path ([System.IO.Path]::GetTempPath()) "helios-maint-test-$([guid]::NewGuid().ToString('N').Substring(0,8))"
        foreach ($dir in @('hooks', 'hooks\lib', 'policy', 'manifest', 'pending', 'inflight', 'evidence', 'evidence\maintenance', 'evidence\integrity', 'blocked', 'maintenance', 'templates')) {
            New-Item -ItemType Directory -Path (Join-Path $script:MaintRoot $dir) -Force | Out-Null
        }

        $script:TestFiles = @{
            'hooks/gate_check.ps1'                = 'gc content for maint test'
            'hooks/tier_classifier.ps1'           = 'tc content for maint test'
            'hooks/helios_pretooluse.ps1'         = 'hp content for maint test'
            'hooks/evidence_capture.ps1'          = 'ec content for maint test'
            'hooks/lib/HeliosIntegrityBridge.ps1' = 'bridge content for maint test'
            'policy/command-policy.json'           = '{"schema_version":"command-policy.v1"}'
        }
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $script:FileHashes = @{}
        $Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        foreach ($relPath in $script:TestFiles.Keys) {
            $fullPath = Join-Path $script:MaintRoot ($relPath -replace '/', '\')
            [System.IO.File]::WriteAllText($fullPath, $script:TestFiles[$relPath], $Utf8NoBom)
            $bytes = [System.IO.File]::ReadAllBytes($fullPath)
            $hash = ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join ''
            $script:FileHashes[$relPath] = $hash
        }

        $manifest = [ordered]@{
            schema_version = 'helios-envelope.v1'
            created_utc    = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            rebaselined_by = 'test'
            protected      = [ordered]@{
                description = 'Must not change during gated execution'
                paths       = @('hooks/gate_check.ps1','hooks/evidence_capture.ps1','hooks/tier_classifier.ps1','hooks/helios_pretooluse.ps1','hooks/lib/HeliosIntegrityBridge.ps1','policy/command-policy.json','manifest/helios-envelope.json','manifest/helios-envelope.sha256')
                hashes      = [ordered]@{}
            }
            mutable        = [ordered]@{
                description = 'Must change as part of gate lifecycle'
                dirs        = @('pending/','inflight/','evidence/','blocked/')
            }
        }
        foreach ($relPath in ($script:FileHashes.Keys | Sort-Object)) {
            $manifest.protected.hashes[$relPath] = $script:FileHashes[$relPath]
        }
        $mPath = Join-Path $script:MaintRoot 'manifest\helios-envelope.json'
        $mJson = $manifest | ConvertTo-Json -Depth 5
        [System.IO.File]::WriteAllText($mPath, $mJson, $Utf8NoBom)
        $mBytes = [System.IO.File]::ReadAllBytes($mPath)
        $script:ManifestHash = ($sha.ComputeHash($mBytes) | ForEach-Object { $_.ToString('x2') }) -join ''
        $sPath = Join-Path $script:MaintRoot 'manifest\helios-envelope.sha256'
        [System.IO.File]::WriteAllText($sPath, $script:ManifestHash, $Utf8NoBom)

        $HeliosDotSourceFunctionsOnly = $true
        . (Join-Path $script:GateRoot '.command-gate\hooks\helios_pretooluse.ps1')
    }

    AfterAll {
        if ($script:MaintRoot -and (Test-Path $script:MaintRoot)) {
            Remove-Item -Recurse -Force $script:MaintRoot -ErrorAction SilentlyContinue
        }
    }

    Context "Integrity ownership (item 8: no self-rebaseline)" {
        BeforeAll {
            $script:FcSource = Get-Content (Join-Path $script:GateRoot '.command-gate\hooks\helios_pretooluse.ps1') -Raw
        }

        It "front controller defines no internal rebaseline authority" {
            Get-Command Invoke-InternalRebaseline -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
            Get-Command Test-MaintenanceRebaselineRequest -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
            Get-Command Read-MaintenanceRebaselineRequest -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        }

        It "front controller source contains no internal-rebaseline functions" {
            $script:FcSource | Should -Not -Match 'function Invoke-InternalRebaseline'
            $script:FcSource | Should -Not -Match 'function Test-MaintenanceRebaselineRequest'
        }

        It "drift is denied with HELIOS/1 DENY INTEGRITY_DRIFT and points to Akashic" {
            $script:FcSource | Should -Match 'HELIOS/1 DENY INTEGRITY_DRIFT'
            $script:FcSource | Should -Match 'Akashic'
        }
    }

    Context "BOM-safe manifest parsing" {
        It "Get-Content -Raw strips BOM from manifest JSON" {
            $testManifest = Join-Path ([System.IO.Path]::GetTempPath()) "bom-test-$([guid]::NewGuid().ToString('N').Substring(0,8)).json"
            try {
                $bomBytes = [byte[]](0xEF, 0xBB, 0xBF) + [System.Text.Encoding]::UTF8.GetBytes('{"test":"value"}')
                [System.IO.File]::WriteAllBytes($testManifest, $bomBytes)

                $parsed = Get-Content $testManifest -Raw | ConvertFrom-Json
                $parsed.test | Should -Be 'value'
            } finally {
                Remove-Item $testManifest -Force -ErrorAction SilentlyContinue
            }
        }

        It "UTF8.GetString preserves BOM and breaks ConvertFrom-Json" {
            $bomBytes = [byte[]](0xEF, 0xBB, 0xBF) + [System.Text.Encoding]::UTF8.GetBytes('{"test":"value"}')
            $rawString = [System.Text.Encoding]::UTF8.GetString($bomBytes)

            { $rawString | ConvertFrom-Json } | Should -Throw
        }
    }
}

Describe "Helios Tools" {

    BeforeAll {
        $script:GateRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
        $script:ToolsDir = Join-Path $script:GateRoot '.command-gate\tools'

        $script:ToolTestRoot = Join-Path ([System.IO.Path]::GetTempPath()) "helios-tool-test-$([guid]::NewGuid().ToString('N').Substring(0,8))"

        foreach ($dir in @('hooks', 'hooks\lib', 'policy', 'manifest', 'pending', 'inflight', 'evidence', 'blocked')) {
            New-Item -ItemType Directory -Path (Join-Path $script:ToolTestRoot $dir) -Force | Out-Null
        }

        $testFiles = @{
            'hooks\gate_check.ps1'                = 'gc content'
            'hooks\tier_classifier.ps1'           = 'tc content'
            'hooks\helios_pretooluse.ps1'         = 'hp content'
            'hooks\evidence_capture.ps1'          = 'ec content'
            'hooks\lib\HeliosIntegrityBridge.ps1' = 'bridge content'
            'policy\command-policy.json'           = '{}'
        }
        foreach ($rel in $testFiles.Keys) {
            $p = Join-Path $script:ToolTestRoot $rel
            [System.IO.File]::WriteAllBytes($p, [System.Text.Encoding]::UTF8.GetBytes($testFiles[$rel]))
        }
    }

    AfterAll {
        if ($script:ToolTestRoot -and (Test-Path $script:ToolTestRoot)) {
            Remove-Item -Recurse -Force $script:ToolTestRoot -ErrorAction SilentlyContinue
        }
    }

    Context "New-HeliosEnvelopeManifest" {
        It "writes manifest and sidecar with matching hash" {
            $rebaselineScript = Join-Path $script:ToolsDir 'New-HeliosEnvelopeManifest.ps1'
            $result = & $rebaselineScript -GateRoot $script:ToolTestRoot -RebaselinedBy 'test'

            $result.manifest_path | Should -Not -BeNullOrEmpty
            $result.sidecar_path | Should -Not -BeNullOrEmpty
            Test-Path $result.manifest_path | Should -Be $true
            Test-Path $result.sidecar_path | Should -Be $true

            $sha = [System.Security.Cryptography.SHA256]::Create()
            $manifestBytes = [System.IO.File]::ReadAllBytes($result.manifest_path)
            $computedHash = ($sha.ComputeHash($manifestBytes) | ForEach-Object { $_.ToString('x2') }) -join ''
            $sidecarHash = (Get-Content $result.sidecar_path -Raw).Trim()

            $computedHash | Should -Be $sidecarHash
            $result.manifest_hash | Should -Be $computedHash
        }
    }

    Context "Test-HeliosEnvelopeIntegrity" {
        It "reports CLEAN after fresh rebaseline" {
            & (Join-Path $script:ToolsDir 'New-HeliosEnvelopeManifest.ps1') -GateRoot $script:ToolTestRoot -RebaselinedBy 'test' | Out-Null

            $verifyScript = Join-Path $script:ToolsDir 'Test-HeliosEnvelopeIntegrity.ps1'
            $result = & $verifyScript -GateRoot $script:ToolTestRoot

            $result.verdict | Should -Be 'CLEAN'
            $result.sidecar_valid | Should -Be $true
        }

        It "reports DRIFT after protected file modification" {
            & (Join-Path $script:ToolsDir 'New-HeliosEnvelopeManifest.ps1') -GateRoot $script:ToolTestRoot -RebaselinedBy 'test' | Out-Null

            $targetPath = Join-Path $script:ToolTestRoot 'hooks\gate_check.ps1'
            $original = [System.IO.File]::ReadAllBytes($targetPath)
            try {
                [System.IO.File]::WriteAllBytes($targetPath, [System.Text.Encoding]::UTF8.GetBytes('tampered'))

                $verifyScript = Join-Path $script:ToolsDir 'Test-HeliosEnvelopeIntegrity.ps1'
                $result = & $verifyScript -GateRoot $script:ToolTestRoot

                $result.verdict | Should -Be 'DRIFT'
                $drifted = @($result.file_details | Where-Object { $_.status -ne 'CLEAN' })
                $drifted.Count | Should -BeGreaterThan 0
                $drifted[0].path | Should -Be 'hooks/gate_check.ps1'
            } finally {
                [System.IO.File]::WriteAllBytes($targetPath, $original)
            }
        }
    }

    Context "Move-HeliosStaleGateArtifacts" {
        It "dry-run reports stale files without moving" {
            $staleTestRoot = Join-Path ([System.IO.Path]::GetTempPath()) "helios-stale-test-$([guid]::NewGuid().ToString('N').Substring(0,8))"
            foreach ($dir in @('pending', 'inflight', 'evidence')) {
                New-Item -ItemType Directory -Path (Join-Path $staleTestRoot $dir) -Force | Out-Null
            }
            New-Item -ItemType File -Path (Join-Path $staleTestRoot 'pending\old.gate.json') -Force | Out-Null
            New-Item -ItemType File -Path (Join-Path $staleTestRoot 'inflight\stuck.gate.json') -Force | Out-Null

            try {
                $moveScript = Join-Path $script:ToolsDir 'Move-HeliosStaleGateArtifacts.ps1'
                $result = & $moveScript -GateRoot $staleTestRoot -DryRun

                $result.dry_run | Should -Be $true
                $result.artifacts.Count | Should -Be 2
                Test-Path (Join-Path $staleTestRoot 'pending\old.gate.json') | Should -Be $true
                Test-Path (Join-Path $staleTestRoot 'inflight\stuck.gate.json') | Should -Be $true
            } finally {
                Remove-Item -Recurse -Force $staleTestRoot -ErrorAction SilentlyContinue
            }
        }

        It "moves stale files to evidence/stale/" {
            $staleTestRoot = Join-Path ([System.IO.Path]::GetTempPath()) "helios-stale-test2-$([guid]::NewGuid().ToString('N').Substring(0,8))"
            foreach ($dir in @('pending', 'inflight', 'evidence')) {
                New-Item -ItemType Directory -Path (Join-Path $staleTestRoot $dir) -Force | Out-Null
            }
            New-Item -ItemType File -Path (Join-Path $staleTestRoot 'pending\old.gate.json') -Force | Out-Null

            try {
                $moveScript = Join-Path $script:ToolsDir 'Move-HeliosStaleGateArtifacts.ps1'
                $result = & $moveScript -GateRoot $staleTestRoot

                $result.dry_run | Should -Be $false
                Test-Path (Join-Path $staleTestRoot 'pending\old.gate.json') | Should -Be $false
                Test-Path (Join-Path $staleTestRoot 'evidence\stale\pending-old.gate.json') | Should -Be $true
                Test-Path (Join-Path $staleTestRoot 'evidence\stale\cleanup-summary.json') | Should -Be $true
            } finally {
                Remove-Item -Recurse -Force $staleTestRoot -ErrorAction SilentlyContinue
            }
        }
    }

    Context "Test-HeliosEvidenceChain" {
        It "reports COMPLETE for a full evidence chain" {
            $chainTestRoot = Join-Path ([System.IO.Path]::GetTempPath()) "helios-chain-test-$([guid]::NewGuid().ToString('N').Substring(0,8))"
            $sessionDir = Join-Path $chainTestRoot 'evidence\integrity\sessions\chain-test\commands'
            New-Item -ItemType Directory -Path $sessionDir -Force | Out-Null

            $toolId = 'tool-chain-001'
            @{ type = 'before' } | ConvertTo-Json | Set-Content (Join-Path $sessionDir "$toolId.before.json") -Encoding UTF8
            @{ verdict = 'ALLOW' } | ConvertTo-Json | Set-Content (Join-Path $sessionDir "$toolId.decision.json") -Encoding UTF8
            @{ type = 'after' } | ConvertTo-Json | Set-Content (Join-Path $sessionDir "$toolId.after.json") -Encoding UTF8
            @{ type = 'compare' } | ConvertTo-Json | Set-Content (Join-Path $sessionDir "$toolId.compare.json") -Encoding UTF8

            try {
                $chainScript = Join-Path $script:ToolsDir 'Test-HeliosEvidenceChain.ps1'
                $result = & $chainScript -GateRoot $chainTestRoot -SessionId 'chain-test'

                $result.verdict | Should -Be 'COMPLETE'
                $result.command_count | Should -Be 1
                @($result.commands)[0].tool_use_id | Should -Be $toolId
            } finally {
                Remove-Item -Recurse -Force $chainTestRoot -ErrorAction SilentlyContinue
            }
        }

        It "reports INCOMPLETE when after is missing for ALLOW verdict" {
            $chainTestRoot = Join-Path ([System.IO.Path]::GetTempPath()) "helios-chain-test2-$([guid]::NewGuid().ToString('N').Substring(0,8))"
            $sessionDir = Join-Path $chainTestRoot 'evidence\integrity\sessions\chain-test2\commands'
            New-Item -ItemType Directory -Path $sessionDir -Force | Out-Null

            $toolId = 'tool-chain-002'
            @{ type = 'before' } | ConvertTo-Json | Set-Content (Join-Path $sessionDir "$toolId.before.json") -Encoding UTF8
            @{ verdict = 'ALLOW' } | ConvertTo-Json | Set-Content (Join-Path $sessionDir "$toolId.decision.json") -Encoding UTF8

            try {
                $chainScript = Join-Path $script:ToolsDir 'Test-HeliosEvidenceChain.ps1'
                $result = & $chainScript -GateRoot $chainTestRoot -SessionId 'chain-test2'

                $result.verdict | Should -Be 'INCOMPLETE'
                @($result.commands)[0].missing | Should -Contain 'after'
                @($result.commands)[0].missing | Should -Contain 'compare'
            } finally {
                Remove-Item -Recurse -Force $chainTestRoot -ErrorAction SilentlyContinue
            }
        }

        It "reports COMPLETE_WITH_ORPHANS for orphan after-only files" {
            $chainTestRoot = Join-Path ([System.IO.Path]::GetTempPath()) "helios-chain-test4-$([guid]::NewGuid().ToString('N').Substring(0,8))"
            $sessionDir = Join-Path $chainTestRoot 'evidence\integrity\sessions\chain-test4\commands'
            New-Item -ItemType Directory -Path $sessionDir -Force | Out-Null

            $gatedId = 'tool-gated-001'
            @{ type = 'before' } | ConvertTo-Json | Set-Content (Join-Path $sessionDir "$gatedId.before.json") -Encoding UTF8
            @{ verdict = 'DENY' } | ConvertTo-Json | Set-Content (Join-Path $sessionDir "$gatedId.decision.json") -Encoding UTF8

            $orphanId = 'tool-orphan-001'
            @{ type = 'after' } | ConvertTo-Json | Set-Content (Join-Path $sessionDir "$orphanId.after.json") -Encoding UTF8

            try {
                $chainScript = Join-Path $script:ToolsDir 'Test-HeliosEvidenceChain.ps1'
                $result = & $chainScript -GateRoot $chainTestRoot -SessionId 'chain-test4'

                $result.verdict | Should -Be 'COMPLETE_WITH_ORPHANS'
                $result.complete_count | Should -Be 1
                $result.orphan_count | Should -Be 1
                $result.incomplete_count | Should -Be 0

                $orphanCmd = $result.commands | Where-Object { $_.tool_use_id -eq $orphanId }
                $orphanCmd.verdict | Should -Be 'ORPHAN'
                $orphanCmd.classification | Should -Be 'cross_session_posttool'
            } finally {
                Remove-Item -Recurse -Force $chainTestRoot -ErrorAction SilentlyContinue
            }
        }

        It "reports INCOMPLETE only for genuinely missing evidence" {
            $chainTestRoot = Join-Path ([System.IO.Path]::GetTempPath()) "helios-chain-test5-$([guid]::NewGuid().ToString('N').Substring(0,8))"
            $sessionDir = Join-Path $chainTestRoot 'evidence\integrity\sessions\chain-test5\commands'
            New-Item -ItemType Directory -Path $sessionDir -Force | Out-Null

            $allowedId = 'tool-missing-after'
            @{ type = 'before' } | ConvertTo-Json | Set-Content (Join-Path $sessionDir "$allowedId.before.json") -Encoding UTF8
            @{ verdict = 'ALLOW' } | ConvertTo-Json | Set-Content (Join-Path $sessionDir "$allowedId.decision.json") -Encoding UTF8

            $orphanId = 'tool-orphan-002'
            @{ type = 'after' } | ConvertTo-Json | Set-Content (Join-Path $sessionDir "$orphanId.after.json") -Encoding UTF8

            try {
                $chainScript = Join-Path $script:ToolsDir 'Test-HeliosEvidenceChain.ps1'
                $result = & $chainScript -GateRoot $chainTestRoot -SessionId 'chain-test5'

                $result.verdict | Should -Be 'INCOMPLETE'
                $result.incomplete_count | Should -Be 1
                $result.orphan_count | Should -Be 1

                $incompleteCmd = $result.commands | Where-Object { $_.tool_use_id -eq $allowedId }
                $incompleteCmd.verdict | Should -Be 'INCOMPLETE'
                $incompleteCmd.classification | Should -Be 'allow'
                $incompleteCmd.missing | Should -Contain 'after'
            } finally {
                Remove-Item -Recurse -Force $chainTestRoot -ErrorAction SilentlyContinue
            }
        }

        It "reports NO_SESSION for missing session" {
            $chainTestRoot = Join-Path ([System.IO.Path]::GetTempPath()) "helios-chain-test3-$([guid]::NewGuid().ToString('N').Substring(0,8))"
            New-Item -ItemType Directory -Path $chainTestRoot -Force | Out-Null

            try {
                $chainScript = Join-Path $script:ToolsDir 'Test-HeliosEvidenceChain.ps1'
                $result = & $chainScript -GateRoot $chainTestRoot -SessionId 'nonexistent'

                $result.verdict | Should -Be 'NO_SESSION'
            } finally {
                Remove-Item -Recurse -Force $chainTestRoot -ErrorAction SilentlyContinue
            }
        }
    }
}

Describe "HELIOS/1 Ingress Adapters and Virtual Corridor" {

    BeforeAll {
        $script:CGRoot = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) '.command-gate'
        $HeliosDotSourceFunctionsOnly = $true
        . (Join-Path $script:CGRoot 'hooks\helios_pretooluse.ps1')
        . (Join-Path $script:CGRoot 'hooks\session_continuity.ps1')

        # Temp gate root with the canonical schema, live policy, and helpers.
        $script:VRoot = Join-Path ([System.IO.Path]::GetTempPath()) "helios-virt-$([guid]::NewGuid().ToString('N').Substring(0,8))"
        foreach ($d in @('hooks', 'schema', 'adapters', 'policy', 'blocked', 'pending', 'session', 'manifest')) {
            New-Item -ItemType Directory -Path (Join-Path $script:VRoot $d) -Force | Out-Null
        }
        Copy-Item (Join-Path $script:CGRoot 'schema\helios-gate.schema.json') (Join-Path $script:VRoot 'schema\helios-gate.schema.json')
        Copy-Item (Join-Path $script:CGRoot 'policy\command-policy.json') (Join-Path $script:VRoot 'policy\command-policy.json')
        Copy-Item (Join-Path $script:CGRoot 'hooks\command_decomposer.ps1') (Join-Path $script:VRoot 'hooks\command_decomposer.ps1')
        Copy-Item (Join-Path $script:CGRoot 'hooks\session_continuity.ps1') (Join-Path $script:VRoot 'hooks\session_continuity.ps1')

        $sha = [System.Security.Cryptography.SHA256]::Create()
        $schemaBytes = [System.IO.File]::ReadAllBytes((Join-Path $script:VRoot 'schema\helios-gate.schema.json'))
        $script:SchemaSha = ($sha.ComputeHash($schemaBytes) | ForEach-Object { $_.ToString('x2') }) -join ''
        $script:VManifest = @{ 'schema/helios-gate.schema.json' = $script:SchemaSha }

        $script:NowUtc = (Get-Date).ToUniversalTime()
        function New-TestBlockedRecord {
            param([string]$Id, [string]$SessionId, [datetime]$When, [string]$Command = 'ls /tmp')
            $rec = [ordered]@{
                timestamp_utc     = $When.ToString('o')
                command           = $Command
                command_sha256    = ('a' * 64)
                detected_tier     = 1
                session_id        = $SessionId
                tool_use_id       = 'toolu_test'
                tool_name         = 'Bash'
                shell             = 'bash'
                working_directory = 'C:\work'
                reason_code       = 'GATE_REQUIRED'
                reason            = 'test'
            }
            $path = Join-Path $script:VRoot "blocked\$Id.blocked.json"
            [System.IO.File]::WriteAllText($path, ($rec | ConvertTo-Json -Depth 4), [System.Text.Encoding]::UTF8)
        }
    }

    AfterAll {
        if ($script:VRoot -and (Test-Path $script:VRoot)) {
            Remove-Item -Recurse -Force $script:VRoot -ErrorAction SilentlyContinue
        }
    }

    Context "Ingress adapter normalization (required tests 3-8)" {
        It "normalizes Claude Bash payload (test 4)" {
            $p = [PSCustomObject]@{ tool_name = 'Bash'; cwd = 'C:\w'; session_id = 's1'; tool_use_id = 't1'
                tool_input = [PSCustomObject]@{ command = 'echo hi' } }
            $r = Get-HeliosCanonicalRequest -Payload $p
            $r.is_exec_tool | Should -Be $true
            $r.shell | Should -Be 'bash'
            $r.command | Should -Be 'echo hi'
            $r.effective_cwd | Should -Be 'C:\w'
        }

        It "normalizes Claude PowerShell payload (test 5)" {
            $p = [PSCustomObject]@{ tool_name = 'PowerShell'; cwd = 'C:\w'; session_id = 's1'; tool_use_id = 't1'
                tool_input = [PSCustomObject]@{ command = 'Get-Date' } }
            $r = Get-HeliosCanonicalRequest -Payload $p
            $r.shell | Should -Be 'powershell'
            $r.command | Should -Be 'Get-Date'
        }

        It "normalizes the confirmed Codex payload shape (test 6: tool_name Bash, cwd=workdir)" {
            $p = [PSCustomObject]@{ tool_name = 'Bash'; cwd = 'C:\Users\dimas\Desktop\CODEAPI'
                session_id = '019f528e-f009-7831-b59b-636c13462573'; tool_use_id = 'exec-77f6109e'
                tool_input = [PSCustomObject]@{ command = 'echo helios-capture-test' } }
            $r = Get-HeliosCanonicalRequest -Payload $p
            $r.is_exec_tool | Should -Be $true
            $r.command | Should -Be 'echo helios-capture-test'
            $r.effective_cwd | Should -Be 'C:\Users\dimas\Desktop\CODEAPI'
            $r.tool_use_id | Should -Be 'exec-77f6109e'
        }

        It "does not accept a non-string (argv) command; no argv subsystem needed" {
            $p = [PSCustomObject]@{ tool_name = 'Bash'; cwd = 'C:\w'; session_id = 's'; tool_use_id = 't'
                tool_input = [PSCustomObject]@{ command = @('bash', '-lc', 'echo hi') } }
            $r = Get-HeliosCanonicalRequest -Payload $p
            $r.command | Should -BeNullOrEmpty
        }

        It "uses tool_input.workdir as effective cwd when present (test 8)" {
            $p = [PSCustomObject]@{ tool_name = 'Bash'; cwd = 'C:\hook-cwd'; session_id = 's'; tool_use_id = 't'
                tool_input = [PSCustomObject]@{ command = 'ls'; workdir = 'C:\real-workdir' } }
            $r = Get-HeliosCanonicalRequest -Payload $p
            $r.effective_cwd | Should -Be 'C:\real-workdir'
        }

        It "non-exec tools are not exec tools (passthrough class)" {
            $p = [PSCustomObject]@{ tool_name = 'Read'; cwd = 'C:\w'; session_id = 's'; tool_use_id = 't'
                tool_input = [PSCustomObject]@{ file_path = 'x' } }
            $r = Get-HeliosCanonicalRequest -Payload $p
            $r.is_exec_tool | Should -Be $false
            $r.command | Should -BeNullOrEmpty
        }

        It "existing Bash|PowerShell matcher is preserved (no catch-all, no second hook system)" {
            # The production Codex integration relies on tool_name 'Bash'; confirm
            # the front controller recognizes exactly the Claude-compatible exec tools.
            (Get-HeliosCanonicalRequest -Payload ([PSCustomObject]@{ tool_name = 'Bash'; tool_input = [PSCustomObject]@{ command = 'x' } })).is_exec_tool | Should -Be $true
            (Get-HeliosCanonicalRequest -Payload ([PSCustomObject]@{ tool_name = 'PowerShell'; tool_input = [PSCustomObject]@{ command = 'x' } })).is_exec_tool | Should -Be $true
        }
    }

    Context "Virtual grammar (tests 11, 17-21)" {
        It "recognizes bare schema request" {
            $r = Get-HeliosVirtualRequest -Command 'helios gate schema'
            $r.valid | Should -Be $true
            $r.op | Should -Be 'schema'
        }

        It "rejects pipes, redirection, chaining, substitution, extra args (test 21)" {
            foreach ($bad in @(
                'helios gate schema | cat',
                'helios gate schema > out.txt',
                'helios gate schema; ls',
                'helios gate schema && ls',
                'helios gate schema $(ls)',
                'helios gate schema --tier 2 --shell bash --bogus',
                'helios gate schema --tier 9 --shell bash',
                'helios gate schema --tier 2',
                'helios gate destroy'
            )) {
                $r = Get-HeliosVirtualRequest -Command $bad
                $r | Should -Not -BeNullOrEmpty
                $r.valid | Should -Be $false
            }
        }

        It "does not claim non-helios commands" {
            Get-HeliosVirtualRequest -Command 'echo helios gate schema' | Should -BeNullOrEmpty
            Get-HeliosVirtualRequest -Command 'ls' | Should -BeNullOrEmpty
        }

        It "bare schema returns index only, two-line envelope, no gate consumed (tests 13, 17, 18)" {
            New-TestBlockedRecord -Id '20260711-000000-aaaaaaaaaaaa' -SessionId 'vsess' -When ($script:NowUtc.AddMinutes(-20))
            $pendingProbe = Join-Path $script:VRoot 'pending\probe.gate.json'
            [System.IO.File]::WriteAllText($pendingProbe, '{"schema_version":"command-gate.v1"}', [System.Text.Encoding]::UTF8)

            $req = Get-HeliosVirtualRequest -Command 'helios gate schema'
            $resp = Invoke-HeliosVirtualOperation -Request $req -Root $script:VRoot -ManifestHashes $script:VManifest -SessionId 'vsess' -ToolUseId 'tv1'

            $resp.sentinel | Should -Be 'HELIOS/1 VIRTUAL schema OK'
            $resp.body.executed | Should -Be $false
            $resp.body.result.index | Should -Not -BeNullOrEmpty
            $resp.body.result.PSObject.Properties['sections'] | Should -BeNullOrEmpty
            $resp.body.schema_sha256 | Should -Be $script:SchemaSha
            Test-Path $pendingProbe | Should -Be $true
        }

        It "tier/shell projection merges live policy fields and stays bounded (tests 19, 20)" {
            $req = Get-HeliosVirtualRequest -Command 'helios gate schema --tier 3 --shell powershell --example'
            $resp = Invoke-HeliosVirtualOperation -Request $req -Root $script:VRoot -ManifestHashes $script:VManifest -SessionId 'vsess' -ToolUseId 'tv2'

            $resp.sentinel | Should -Be 'HELIOS/1 VIRTUAL schema OK'
            @($resp.body.result.tier_required_fields) | Should -Contain 'read_write_impact'
            @($resp.body.result.tier_required_fields) | Should -Contain 'stop_conditions'
            @($resp.body.result.required_base_fields).Count | Should -Be 17
            $wire = "$($resp.sentinel)`n" + ($resp.body | ConvertTo-Json -Depth 10 -Compress)
            $wire.Length | Should -BeLessThan 8192
        }

        It "every section projection stays under the hard cap (test 20)" {
            $doc = (Get-Content (Join-Path $script:VRoot 'schema\helios-gate.schema.json') -Raw | ConvertFrom-Json)
            foreach ($sec in $doc.sections.PSObject.Properties) {
                $req = Get-HeliosVirtualRequest -Command "helios gate schema --section $($sec.Name)"
                $resp = Invoke-HeliosVirtualOperation -Request $req -Root $script:VRoot -ManifestHashes $script:VManifest -SessionId 'vsess' -ToolUseId 'tv3'
                $wire = "$($resp.sentinel)`n" + ($resp.body | ConvertTo-Json -Depth 10 -Compress)
                $wire.Length | Should -BeLessThan 8192
            }
        }

        It "fails closed when the canonical schema is unmanifested (test 11 fail-closed contract)" {
            { Read-HeliosCanonicalSchema -Root $script:VRoot -ManifestHashes @{} } | Should -Throw
        }

        It "validator and responder read the same canonical schema (test 37)" {
            $GateRoot = $script:VRoot
            $HeliosFrontControllerActive = $true
            . (Join-Path $script:CGRoot 'hooks\gate_check.ps1')
            $GateRoot = $script:VRoot
            $fromValidator = @(Get-RequiredBaseFields)
            $fromResponder = @((Read-HeliosCanonicalSchema -Root $script:VRoot -ManifestHashes $script:VManifest).doc.sections.fields.required_base_fields)
            ($fromValidator -join ',') | Should -Be ($fromResponder -join ',')
        }
    }

    Context "Scaffold binding (tests 26-34)" {
        It "rejects malformed and traversal ids (tests 26, 27)" {
            foreach ($bad in @('not-an-id', '..\..\evil', '20260711-000000-zzzzzzzzzzzz', 'x/20260711-000000-aaaaaaaaaaaa')) {
                $r = Resolve-HeliosBlockedRecord -Root $script:VRoot -BlockedId $bad -SessionId 'vsess'
                $r.ok | Should -Be $false
                $r.code | Should -Be 'BAD_ID'
            }
        }

        It "rejects expired records (test 28)" {
            New-TestBlockedRecord -Id '20260711-000001-bbbbbbbbbbbb' -SessionId 'vsess' -When ($script:NowUtc.AddMinutes(-45))
            $r = Resolve-HeliosBlockedRecord -Root $script:VRoot -BlockedId '20260711-000001-bbbbbbbbbbbb' -SessionId 'vsess'
            $r.ok | Should -Be $false
            $r.code | Should -Be 'EXPIRED'
        }

        It "rejects another session's record (test 29)" {
            New-TestBlockedRecord -Id '20260711-000002-cccccccccccc' -SessionId 'other-session' -When $script:NowUtc
            $r = Resolve-HeliosBlockedRecord -Root $script:VRoot -BlockedId '20260711-000002-cccccccccccc' -SessionId 'vsess'
            $r.ok | Should -Be $false
            $r.code | Should -Be 'SESSION_MISMATCH'
        }

        It "returns STALE_RECORD for legacy records without session ids (test 30)" {
            $legacy = [ordered]@{ timestamp_utc = $script:NowUtc.ToString('o'); command = 'ls'; command_sha256 = ('b' * 64); tier = 1; reason = 'legacy' }
            [System.IO.File]::WriteAllText((Join-Path $script:VRoot 'blocked\20260711-000003-dddddddddddd.blocked.json'), ($legacy | ConvertTo-Json), [System.Text.Encoding]::UTF8)
            $r = Resolve-HeliosBlockedRecord -Root $script:VRoot -BlockedId '20260711-000003-dddddddddddd' -SessionId 'vsess'
            $r.ok | Should -Be $false
            $r.code | Should -Be 'STALE_RECORD'
        }

        It "bare scaffold selects the newest in-TTL record for the session (test 31)" {
            New-TestBlockedRecord -Id '20260711-000004-eeeeeeeeeeee' -SessionId 'vsess' -When ($script:NowUtc.AddMinutes(-10)) -Command 'older'
            New-TestBlockedRecord -Id '20260711-000005-ffffffffffff' -SessionId 'vsess' -When ($script:NowUtc.AddMinutes(-1)) -Command 'newer'
            $r = Resolve-HeliosBlockedRecord -Root $script:VRoot -BlockedId $null -SessionId 'vsess'
            $r.ok | Should -Be $true
            $r.id | Should -Be '20260711-000005-ffffffffffff'
        }

        It "scaffold prefills observed values, leaves semantics unresolved, writes nothing to pending (tests 32-34)" {
            $pendingBefore = @(Get-ChildItem (Join-Path $script:VRoot 'pending') -File).Count
            $req = Get-HeliosVirtualRequest -Command 'helios gate scaffold --blocked-id 20260711-000005-ffffffffffff'
            $resp = Invoke-HeliosVirtualOperation -Request $req -Root $script:VRoot -ManifestHashes $script:VManifest -SessionId 'vsess' -ToolUseId 'tv4'

            $resp.sentinel | Should -Be 'HELIOS/1 VIRTUAL scaffold OK'
            $resp.body.result.observed.shell | Should -Be 'bash'
            $resp.body.result.observed.working_directory | Should -Be 'C:\work'
            $resp.body.result.gate.need | Should -Be ''
            $resp.body.result.gate.expected | Should -Be ''
            @($resp.body.result.unresolved) | Should -Contain 'need'
            @($resp.body.result.unresolved) | Should -Contain 'previous_correlation_id OR new_chain'
            @(Get-ChildItem (Join-Path $script:VRoot 'pending') -File).Count | Should -Be $pendingBefore
        }

        It "scaffold response carries absolute destination-discovery fields inside the gate root (gap 1)" {
            New-TestBlockedRecord -Id '20260711-000010-1a1a1a1a1a1a' -SessionId 'vsess' -When ($script:NowUtc.AddMinutes(-2)) -Command 'ls /tmp'
            $req = Get-HeliosVirtualRequest -Command 'helios gate scaffold --blocked-id 20260711-000010-1a1a1a1a1a1a'
            $resp = Invoke-HeliosVirtualOperation -Request $req -Root $script:VRoot -ManifestHashes $script:VManifest -SessionId 'vsess' -ToolUseId 'tvd1'
            $resp.body.result.gate_root | Should -Be $script:VRoot
            [System.IO.Path]::IsPathRooted($resp.body.result.pending_directory) | Should -Be $true
            $resp.body.result.pending_directory | Should -Be (Join-Path $script:VRoot 'pending')
            $resp.body.result.suggested_gate_path | Should -Be (Join-Path (Join-Path $script:VRoot 'pending') '<correlation-id>.gate.json')
            $resp.body.result.write_instruction | Should -Match 'suggested_gate_path'
            $wire = "$($resp.sentinel)`n" + ($resp.body | ConvertTo-Json -Depth 10 -Compress)
            $wire.Length | Should -BeLessThan 8192
        }

        It "scaffold destination cannot be redirected by blocked-record working_directory (gap 1)" {
            New-TestBlockedRecord -Id '20260711-000011-2b2b2b2b2b2b' -SessionId 'vsess' -When ($script:NowUtc.AddMinutes(-2)) -Command 'ls'
            $bp = Join-Path $script:VRoot 'blocked\20260711-000011-2b2b2b2b2b2b.blocked.json'
            $b = Get-Content $bp -Raw | ConvertFrom-Json
            $b.working_directory = 'C:\evil\attacker'
            [System.IO.File]::WriteAllText($bp, ($b | ConvertTo-Json -Depth 4), [System.Text.Encoding]::UTF8)
            $req = Get-HeliosVirtualRequest -Command 'helios gate scaffold --blocked-id 20260711-000011-2b2b2b2b2b2b'
            $resp = Invoke-HeliosVirtualOperation -Request $req -Root $script:VRoot -ManifestHashes $script:VManifest -SessionId 'vsess' -ToolUseId 'tvd2'
            $resp.body.result.observed.working_directory | Should -Be 'C:\evil\attacker'
            $resp.body.result.suggested_gate_path.StartsWith((Join-Path $script:VRoot 'pending')) | Should -Be $true
            $resp.body.result.suggested_gate_path | Should -Not -Match 'evil'
        }
    }

    Context "Continuity neutrality (tests 14-16)" {
        It "virtual_op_answered creates no gap and no break (test 16)" {
            $sid = "neutral-$([guid]::NewGuid().ToString('N').Substring(0,8))"
            Write-SessionLedgerEntry -GateRoot $script:VRoot -SessionId $sid -EventType 'pretooluse_seen' -Data @{ command_sha256 = 'x' }
            Write-SessionLedgerEntry -GateRoot $script:VRoot -SessionId $sid -EventType 'gate_consumed' -Data @{ correlation_id = 'c1' }
            Write-SessionLedgerEntry -GateRoot $script:VRoot -SessionId $sid -EventType 'posttooluse_evidence_written' -Data @{ correlation_id = 'c1'; hook_presence_after = $true }
            Write-SessionLedgerEntry -GateRoot $script:VRoot -SessionId $sid -EventType 'virtual_op_answered' -Data @{ operation = 'schema'; executed = $false }

            $c = Test-SessionContinuity -GateRoot $script:VRoot -SessionId $sid
            $c.continuity_verdict | Should -Be 'CONTINUOUS'
            $c.total_commands | Should -Be 1
        }

        It "virtual event never becomes the executable chain predecessor (test 35 support)" {
            $sid = "chain-$([guid]::NewGuid().ToString('N').Substring(0,8))"
            Write-SessionLedgerEntry -GateRoot $script:VRoot -SessionId $sid -EventType 'posttooluse_evidence_written' -Data @{ correlation_id = 'exec-corr-1'; hook_presence_after = $true }
            Write-SessionLedgerEntry -GateRoot $script:VRoot -SessionId $sid -EventType 'virtual_op_answered' -Data @{ operation = 'schema'; executed = $false }

            $GateRoot = $script:VRoot
            $HeliosFrontControllerActive = $true
            . (Join-Path $script:CGRoot 'hooks\gate_check.ps1')
            $GateRoot = $script:VRoot
            Get-LastExecutableCorrelationId -SessionId $sid -Root $script:VRoot | Should -Be 'exec-corr-1'
        }
    }
}

Describe "HELIOS/1 Validator Enforcement" {

    BeforeAll {
        $script:CGRoot = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) '.command-gate'

        # Full temp gate root for Invoke-GateValidation.
        $script:GRoot = Join-Path ([System.IO.Path]::GetTempPath()) "helios-gv-$([guid]::NewGuid().ToString('N').Substring(0,8))"
        foreach ($d in @('hooks', 'schema', 'policy', 'pending', 'inflight', 'evidence', 'blocked', 'templates', 'manifest', 'session')) {
            New-Item -ItemType Directory -Path (Join-Path $script:GRoot $d) -Force | Out-Null
        }
        Copy-Item (Join-Path $script:CGRoot 'schema\helios-gate.schema.json') (Join-Path $script:GRoot 'schema\helios-gate.schema.json')
        Copy-Item (Join-Path $script:CGRoot 'policy\command-policy.json') (Join-Path $script:GRoot 'policy\command-policy.json')
        Copy-Item (Join-Path $script:CGRoot 'hooks\command_decomposer.ps1') (Join-Path $script:GRoot 'hooks\command_decomposer.ps1')
        Copy-Item (Join-Path $script:CGRoot 'hooks\session_continuity.ps1') (Join-Path $script:GRoot 'hooks\session_continuity.ps1')

        . (Join-Path $script:CGRoot 'hooks\tier_classifier.ps1')
        . (Join-Path $script:CGRoot 'hooks\session_continuity.ps1')
        $HeliosFrontControllerActive = $true
        . (Join-Path $script:CGRoot 'hooks\gate_check.ps1')
        $GateRoot = $script:GRoot

        function New-TestPayload {
            param([string]$Command, [string]$SessionId = 'gv-sess')
            return [PSCustomObject]@{
                tool_name = 'Bash'
                cwd = 'C:\work'
                session_id = $SessionId
                tool_use_id = "t-$([guid]::NewGuid().ToString('N').Substring(0,8))"
                tool_input = [PSCustomObject]@{ command = $Command }
            }
        }

        function New-TestGate {
            param([string]$Command, [string]$SchemaVersion = 'command-gate.v1', [string]$Name = 'test-gate')
            $sha = [System.Security.Cryptography.SHA256]::Create()
            $hash = ($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Command)) | ForEach-Object { $_.ToString('x2') }) -join ''
            $gate = [ordered]@{
                schema_version    = $SchemaVersion
                correlation_id    = "$Name-corr"
                created_utc       = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                expires_utc       = (Get-Date).ToUniversalTime().AddHours(1).ToString('yyyy-MM-ddTHH:mm:ssZ')
                command           = $Command
                command_sha256    = $hash
                working_directory = 'C:\work'
                shell             = 'bash'
                risk_tier         = 1
                exit_capture      = 'suffix'
                multi_command     = $true
                segments          = @('ls /tmp', 'echo EXIT=$?')
                need              = 'n'
                expected          = 'e'
                actual_means      = 'a'
                next_logic        = 'x'
                approval_boundary = 'read-only'
            }
            $path = Join-Path $script:GRoot "pending\$Name.gate.json"
            [System.IO.File]::WriteAllText($path, ($gate | ConvertTo-Json -Depth 4), [System.Text.Encoding]::UTF8)
            return $hash
        }
    }

    AfterAll {
        if ($script:GRoot -and (Test-Path $script:GRoot)) {
            Remove-Item -Recurse -Force $script:GRoot -ErrorAction SilentlyContinue
        }
    }

    Context "Schema-version enforcement (tests 9, 10)" {
        It "accepts exactly command-gate.v1 (test 9)" {
            $cmd = 'ls /tmp; echo EXIT=$?'
            $null = New-TestGate -Command $cmd -Name 'sv-ok'
            $r = Invoke-GateValidation -Payload (New-TestPayload -Command $cmd)
            $r.action | Should -Be 'allow'
            $r.correlation_id | Should -Be 'sv-ok-corr'
        }

        It "denies '1.0' with the canonical replacement in the envelope (test 10)" {
            $cmd = 'ls /tmp; echo EXIT=$?'
            $null = New-TestGate -Command $cmd -SchemaVersion '1.0' -Name 'sv-old'
            $r = Invoke-GateValidation -Payload (New-TestPayload -Command $cmd)
            $r.action | Should -Be 'deny'
            $r.reason | Should -Match 'HELIOS/1 DENY GATE_REJECTED'
            # ConvertTo-Json -Compress escapes single quotes as ', so match
            # the unquoted tokens rather than literal quotes.
            $r.reason | Should -Match 'schema_version mismatch'
            $r.reason | Should -Match 'command-gate\.v1'
            $r.reason | Should -Match '1\.0'
            Remove-Item (Join-Path $script:GRoot 'pending\sv-old.gate.json') -Force
        }

        It "denies helios-gate.v1 and other unknown versions (test 10)" {
            $cmd = 'ls /var; echo EXIT=$?'
            $null = New-TestGate -Command $cmd -SchemaVersion 'helios-gate.v1' -Name 'sv-bad'
            $gatePath = Join-Path $script:GRoot 'pending\sv-bad.gate.json'
            $g = Get-Content $gatePath -Raw | ConvertFrom-Json
            $g.segments = @('ls /var', 'echo EXIT=$?')
            [System.IO.File]::WriteAllText($gatePath, ($g | ConvertTo-Json -Depth 4), [System.Text.Encoding]::UTF8)
            $r = Invoke-GateValidation -Payload (New-TestPayload -Command $cmd)
            $r.action | Should -Be 'deny'
            $r.reason | Should -Match 'schema_version mismatch'
            Remove-Item $gatePath -Force
        }
    }

    Context "Structured recovery envelopes (tests 22, 23, 24, 35)" {
        It "GATE_REQUIRED returns the HELIOS/1 envelope with an atomically-written blocked id (tests 22, 24)" {
            $cmd = 'cat /etc/hosts; echo EXIT=$?'
            $r = Invoke-GateValidation -Payload (New-TestPayload -Command $cmd)
            $r.action | Should -Be 'deny'
            $lines = $r.reason -split "`n", 2
            $lines[0] | Should -Be 'HELIOS/1 DENY GATE_REQUIRED'
            $body = $lines[1] | ConvertFrom-Json
            $body.scaffold_available | Should -Be $true
            $body.blocked_id | Should -Match '^\d{8}-\d{6}-[a-f0-9]{12}'
            $body.schema_command | Should -Match '^helios gate schema --tier \d --shell bash$'
            Test-Path (Join-Path $script:GRoot "blocked\$($body.blocked_id).blocked.json") | Should -Be $true
            $rec = Get-Content (Join-Path $script:GRoot "blocked\$($body.blocked_id).blocked.json") -Raw | ConvertFrom-Json
            $rec.session_id | Should -Be 'gv-sess'
            $rec.shell | Should -Be 'bash'
            $rec.working_directory | Should -Be 'C:\work'
        }

        It "GATE_REQUIRED denial carries absolute destination-discovery metadata (gap 1)" {
            $cmd = 'ps aux; echo EXIT=$?'
            $r = Invoke-GateValidation -Payload (New-TestPayload -Command $cmd)
            $r.action | Should -Be 'deny'
            $body = ($r.reason -split "`n", 2)[1] | ConvertFrom-Json
            $body.scaffold_available | Should -Be $true
            $body.gate_root | Should -Be $script:GRoot
            $body.pending_directory | Should -Be (Join-Path $script:GRoot 'pending')
            $body.suggested_gate_path.StartsWith((Join-Path $script:GRoot 'pending')) | Should -Be $true
        }

        It "closest-gate rejection uses the same grammar with reject_reasons (test 23)" {
            $cmd = 'grep foo bar; echo EXIT=$?'
            $hash = New-TestGate -Command $cmd -Name 'rej'
            $gatePath = Join-Path $script:GRoot 'pending\rej.gate.json'
            $g = Get-Content $gatePath -Raw | ConvertFrom-Json
            $g.PSObject.Properties.Remove('need')
            $g.segments = @('grep foo bar', 'echo EXIT=$?')
            [System.IO.File]::WriteAllText($gatePath, ($g | ConvertTo-Json -Depth 4), [System.Text.Encoding]::UTF8)

            $r = Invoke-GateValidation -Payload (New-TestPayload -Command $cmd)
            $r.action | Should -Be 'deny'
            $lines = $r.reason -split "`n", 2
            $lines[0] | Should -Be 'HELIOS/1 DENY GATE_REJECTED'
            $body = $lines[1] | ConvertFrom-Json
            @($body.reject_reasons) -join ' ' | Should -Match 'missing base fields'
            Remove-Item $gatePath -Force
        }

        It "chain recovery carries the latest executable correlation id (test 35)" {
            $sid = 'gv-chain-sess'
            Write-SessionLedgerEntry -GateRoot $script:GRoot -SessionId $sid -EventType 'posttooluse_evidence_written' -Data @{ correlation_id = 'prev-exec-7'; hook_presence_after = $true }
            $cmd = 'df -h; echo EXIT=$?'
            $r = Invoke-GateValidation -Payload (New-TestPayload -Command $cmd -SessionId $sid)
            $r.action | Should -Be 'deny'
            $body = ($r.reason -split "`n", 2)[1] | ConvertFrom-Json
            $body.last_correlation_id | Should -Be 'prev-exec-7'
        }

        It "blocked-record persistence failure degrades to scaffold_available=false (test 25)" {
            $cmd = 'uname -a; echo EXIT=$?'
            $blockedDir = Join-Path $script:GRoot 'blocked'
            $null = icacls $blockedDir /deny "Everyone:(W)" 2>&1
            try {
                $r = Invoke-GateValidation -Payload (New-TestPayload -Command $cmd)
                $r.action | Should -Be 'deny'
                $body = ($r.reason -split "`n", 2)[1] | ConvertFrom-Json
                $body.scaffold_available | Should -Be $false
                $body.persistence_error | Should -Be 'PERSISTENCE_ERROR'
                $body.schema_command | Should -Match '^helios gate schema'
            } finally {
                $null = icacls $blockedDir /remove:d "Everyone" 2>&1
            }
        }
    }

    # Stale-artifact archival is Akashic-owned installation-lifecycle behavior. Its
    # byte-identical archival acceptance lives in the Akashic suite against a
    # disposable gate root; the historical archive of the stray '1.0' Codex gate is
    # preserved as deployment evidence under evidence/stale/ in the live runtime.
}
