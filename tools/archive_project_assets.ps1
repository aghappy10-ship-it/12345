param(
    [Parameter(Mandatory=$true)][string]$Source,
    [Parameter(Mandatory=$true)][string]$Label,
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [string[]]$ExcludeRelative = @()
)

# Research archive only. Reads source files; never writes, cleans or executes them.
# Generated volumes and records go exclusively into a separate output directory.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$sevenZip = 'C:\Program Files\7-Zip\7z.exe'
$sourceItem = Get-Item -LiteralPath $Source -Force
$sourceRoot = $sourceItem.FullName.TrimEnd('\')
$outputRoot = [IO.Path]::GetFullPath($OutputDirectory).TrimEnd('\')
if ($Label -notmatch '^[a-z0-9][a-z0-9-]{0,80}$') { throw 'Invalid archive label' }
if ($outputRoot.Equals($sourceRoot, [StringComparison]::OrdinalIgnoreCase) -or
    $outputRoot.StartsWith($sourceRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Archive output cannot be inside a source root'
}
# Never let a C/F alias or another parent junction defeat output isolation.
foreach ($basePath in @($sourceRoot, $outputRoot)) {
    $ancestor = $basePath
    while ($ancestor) {
        if (Test-Path -LiteralPath $ancestor) {
            $ancestorItem = Get-Item -LiteralPath $ancestor -Force
            if (($ancestorItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Use a physical root; ancestor is a reparse point: $ancestor"
            }
        }
        $parentPath = Split-Path -Parent $ancestor
        if ($parentPath -eq $ancestor) { break }
        $ancestor = $parentPath
    }
}
if (-not (Test-Path -LiteralPath $sevenZip -PathType Leaf)) { throw '7-Zip is absent' }
foreach ($relative in $ExcludeRelative) {
    if ([IO.Path]::IsPathRooted($relative) -or $relative -match '(^|[\\/])\.\.([\\/]|$)' -or
        $relative.IndexOfAny([char[]]'*?') -ge 0) { throw 'Only exact relative exclusions are supported' }
}
New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null
if (@(Get-ChildItem -LiteralPath $outputRoot -Filter "$Label*" -Force).Count) {
    throw 'Archive outputs already exist; do not overwrite or silently resume'
}
$utf8 = [Text.UTF8Encoding]::new($false)
$statePath = Join-Path $outputRoot "$Label.state.json"
$started = (Get-Date).ToUniversalTime().ToString('o')
$record = [ordered]@{
    schema='x2dii-complete-root-archive-v1'; label=$Label; source=$sourceRoot;
    started_utc=$started; state='PREPARING'; installable=$false;
    excluded_relative_paths=$ExcludeRelative;
    archive_format='7z'; volume_limit_bytes=1073741824;
    source_writes=0; source_programs_executed=0;
    archiver_script_sha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLower();
    seven_zip_sha256=(Get-FileHash -LiteralPath $sevenZip -Algorithm SHA256).Hash.ToLower();
    link_storage='Reparse entries excluded from 7z payload; preserved as path/type/target/attributes in uploaded inventories and state'
    integrity_limit='Archive CRC and stable source entries/size/mtime/link targets; not independent source SHA256 per file or NTFS forensic image'
}
function Save-State {
    [IO.File]::WriteAllText($statePath, ($record | ConvertTo-Json -Depth 8), $utf8)
}
function Write-Inventory([string]$destination) {
    [string[]]$paths = @(if ($sourceItem.PSIsContainer) {
        Get-ChildItem -LiteralPath $sourceRoot -Recurse -Force | ForEach-Object FullName
    } else { $sourceRoot })
    [Array]::Sort($paths, [StringComparer]::Ordinal)
    $writer = [IO.StreamWriter]::new($destination, $false, $utf8, 131072)
    $count = 0L; $bytes = 0L; $directories = 0L
    $links = [Collections.Generic.List[object]]::new()
    try {
        foreach ($path in $paths) {
            $relative = if ($sourceItem.PSIsContainer) { $path.Substring($sourceRoot.Length + 1) } else { $sourceItem.Name }
            if ($ExcludeRelative -contains $relative) { continue }
            $item = Get-Item -LiteralPath $path -Force
            $isDirectory = $item.PSIsContainer
            $isLink = ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
            $length = if ($isDirectory) { 0L } else { $item.Length }
            $row = [ordered]@{path=$relative.Replace('\','/');kind=$(if ($isDirectory) {'directory'} else {'file'});bytes=$length;
                mtime_utc=$item.LastWriteTimeUtc.ToString('o');attributes=[int]$item.Attributes}
            if ($isLink) {
                $row['link_type'] = $item.LinkType
                $row['link_target'] = @($item.Target)
                if (-not $item.LinkType -or -not $item.Target) { throw "Unknown reparse metadata: $relative" }
                $links.Add($row)
            }
            $writer.WriteLine(($row | ConvertTo-Json -Compress))
            if ($isDirectory) { $directories++ } else { $count++; $bytes += $length }
        }
    } finally { $writer.Dispose() }
    return [ordered]@{files=$count;directories=$directories;bytes=$bytes;reparse_entries=@($links.ToArray());
        sha256=(Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLower()}
}
Save-State
try {
    $beforePath = Join-Path $outputRoot "$Label.source-before.ndjson"
    $record['source_before'] = Write-Inventory $beforePath
    $record['state'] = 'ARCHIVING'; Save-State
    $parent = Split-Path -Parent $sourceRoot
    $leaf = Split-Path -Leaf $sourceRoot
    $archive = Join-Path $outputRoot "$Label.7z"
    $arguments = @('a','-t7z','-mx=1','-md=256m','-ms=on','-mmt=2','-v1024m','-bd','-bsp0',$archive)
    foreach ($relative in $ExcludeRelative) { $arguments += '-x!' + $leaf + '\' + $relative }
    foreach ($link in $record.source_before.reparse_entries) {
        $arguments += '-x!' + $leaf + '\' + $link.path.Replace('/','\')
    }
    $arguments += @('--', $leaf)
    Push-Location -LiteralPath $parent
    try {
        & $sevenZip @arguments 2>&1 | Tee-Object -FilePath (Join-Path $outputRoot "$Label.archive.log")
        $archiveExit = $LASTEXITCODE
    } finally { Pop-Location }
    $record['archive_exit_code'] = $archiveExit
    if ($archiveExit -ne 0) { throw "Archive failed or warned: exit $archiveExit" }
    $record['state'] = 'VERIFYING_ARCHIVE'; Save-State
    $firstVolume = $archive + '.001'
    if (-not (Test-Path -LiteralPath $firstVolume -PathType Leaf)) { throw 'First archive volume is absent' }
    & $sevenZip t '-bd' '-bsp0' '-mmt=2' $firstVolume 2>&1 |
        Tee-Object -FilePath (Join-Path $outputRoot "$Label.archive-test.log")
    $testExit = $LASTEXITCODE
    $record['archive_test_exit_code'] = $testExit
    if ($testExit -ne 0) { throw "Archive integrity check failed: exit $testExit" }
    $record['source_after'] = Write-Inventory (Join-Path $outputRoot "$Label.source-after.ndjson")
    if ($record.source_before.sha256 -ne $record.source_after.sha256) {
        throw 'Source changed while archiving; retain artifacts but do not upload as complete'
    }
    $volumes = @(Get-ChildItem -LiteralPath $outputRoot -Filter "$Label.7z.*" -File | Sort-Object Name)
    $rows = [Collections.Generic.List[object]]::new()
    for ($i=0; $i -lt $volumes.Count; $i++) {
        $volume = $volumes[$i]
        if ($volume.Name -ne ("$Label.7z." + ($i + 1).ToString('000')) -or
            $volume.Length -le 0 -or $volume.Length -gt 1073741824) {
            throw 'Archive volume numbering or size is invalid'
        }
        $rows.Add([ordered]@{name=$volume.Name;bytes=$volume.Length;
            sha256=(Get-FileHash -LiteralPath $volume.FullName -Algorithm SHA256).Hash.ToLower()})
    }
    $record['volumes'] = @($rows.ToArray())
    $record['finished_utc'] = (Get-Date).ToUniversalTime().ToString('o')
    $record['state'] = 'VERIFIED_LOCAL_NOT_UPLOADED'; Save-State
    Write-Output ($record | ConvertTo-Json -Depth 8 -Compress)
} catch {
    $record['state'] = 'FAILED_LOCAL_NOT_UPLOADED'
    $record['error'] = $_.Exception.Message
    $record['failed_utc'] = (Get-Date).ToUniversalTime().ToString('o')
    Save-State
    throw
}
