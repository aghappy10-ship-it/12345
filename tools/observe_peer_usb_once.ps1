# This observer never switches USB or installs a driver. Run before/around the
# separately approved worker launch. One fixed read-only ADB query at most.
param([switch]$ObserveApprovedWindow)
$ErrorActionPreference = 'Stop'
if (-not $ObserveApprovedWindow) { throw 'Explicit approved-window observation required' }
$projectPath = Split-Path $PSScriptRoot -Parent
$sourcePath = Join-Path $projectPath 'build/peer-usb-access/X2d2PeerAdb.cs'
if ((Get-FileHash -Algorithm SHA256 -LiteralPath $sourcePath).Hash -ne '6b93f727a08bf7ecfd893f1ba93d2f85bbbe55d35f651e7283d8016d30ca1c2c') {
    throw 'Reviewed host checker changed'
}
Add-Type -Path $sourcePath
$elapsed = [Diagnostics.Stopwatch]::StartNew()
$attempted = $false
$probeFailed = $false
$lastCount = -1
$lastPnp = ''
$nextPnp = 0
while ($elapsed.Elapsed.TotalSeconds -lt 125) {
    if (-not $probeFailed) {
        try {
            $probe = [X2d2PeerAdb.AdbUsbCheck]::Probe()
            if ($probe.MatchingInterfaces -ne $lastCount) {
                [pscustomobject]@{Utc=[DateTime]::UtcNow.ToString('o'); Kind='probe'; Result=$probe} | ConvertTo-Json -Compress
                $lastCount = $probe.MatchingInterfaces
            }
            if ($probe.MatchingInterfaces -gt 0 -and -not $attempted) {
                $attempted = $true
                try {
                    $identity = [X2d2PeerAdb.AdbUsbCheck]::Query()
                    [pscustomobject]@{Utc=[DateTime]::UtcNow.ToString('o'); Kind='query'; Result=$identity} | ConvertTo-Json -Compress
                } catch {
                    [pscustomobject]@{Utc=[DateTime]::UtcNow.ToString('o'); Kind='query-failed-no-retry'; Error=$_.Exception.ToString()} | ConvertTo-Json -Compress
                }
            }
        } catch {
            $probeFailed = $true
            [pscustomobject]@{Utc=[DateTime]::UtcNow.ToString('o'); Kind='probe-failed'; Error=$_.Exception.ToString()} | ConvertTo-Json -Compress
        }
    }
    if ($elapsed.Elapsed.TotalSeconds -ge $nextPnp) {
        $entries = @(Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -like 'USB\VID_2756&PID_000B*' } | Sort-Object InstanceId | Select-Object Status,Class,FriendlyName,InstanceId,Problem)
        $encoded = ConvertTo-Json -InputObject $entries -Compress
        if ($encoded -ne $lastPnp) {
            [pscustomobject]@{Utc=[DateTime]::UtcNow.ToString('o'); Kind='pnp'; Result=$entries} | ConvertTo-Json -Depth 5 -Compress
            $lastPnp = $encoded
        }
        $nextPnp = $elapsed.Elapsed.TotalSeconds + 8
    }
    Start-Sleep -Seconds 1
}
[pscustomobject]@{Utc=[DateTime]::UtcNow.ToString('o'); Kind='observer-finished'; QueryAttempted=$attempted; PhysicalRestoreVerified=$false} | ConvertTo-Json -Compress
