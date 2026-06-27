$root = $PSScriptRoot
$files = @(
    'hooks\gate_check.ps1',
    'hooks\evidence_capture.ps1',
    'hooks\tier_classifier.ps1',
    'hooks\helios_pretooluse.ps1',
    'hooks\lib\HeliosIntegrityBridge.ps1',
    'policy\command-policy.json'
)
foreach ($f in $files) {
    $p = Join-Path $root $f
    $h = (Get-FileHash $p -Algorithm SHA256).Hash.ToLower()
    Write-Output "${f}: ${h}"
}
