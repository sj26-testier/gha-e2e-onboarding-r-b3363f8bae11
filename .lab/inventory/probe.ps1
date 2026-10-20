param([ValidateSet('baseline','bridge','final')][string]$Phase)
$ErrorActionPreference = 'Stop'

function Version($Exe) {
    $output = & $Exe --version 2>&1 | Out-String
    [ordered]@{path=$Exe; exit_code=$LASTEXITCODE; output=$output.Trim()}
}

if ($Phase -eq 'baseline') {
    $java = (Get-Command java -CommandType Application).Source
    $javaHome = [Environment]::GetEnvironmentVariable('JAVA_HOME')
    $javaVersion = & $java -version 2>&1 | Out-String
    $consumer = "$env:JAVA_HOME\bin\java.exe"
    try {
        $consumerOutput = & $consumer -version 2>&1 | Out-String
        $consumerResult = [ordered]@{command=$consumer; exit_code=$LASTEXITCODE; output=$consumerOutput.Trim()}
    } catch {
        $consumerResult = [ordered]@{command=$consumer; error_id=$_.FullyQualifiedErrorId; error_type=$_.Exception.GetType().FullName}
    }
    $trusted = @("$env:ProgramFiles\Git\usr\bin", "$env:ProgramFiles\zstd", "$env:SystemRoot\System32")
    $zstd = (Get-Command zstd -CommandType Application -ErrorAction SilentlyContinue).Source
    $paths = @('C:\tools\zstd\zstd.exe', "$env:ProgramFiles\zstd\zstd.exe", "$env:ProgramFiles\Git\usr\bin\zstd.exe")
    $locations = @($paths | ForEach-Object { [ordered]@{path=$_; exists=(Test-Path -LiteralPath $_ -PathType Leaf)} })
    $before = $env:PATH
    try {
        $env:PATH = $trusted -join ';'
        $isolated = @(Get-Command zstd -CommandType Application -ErrorAction SilentlyContinue | ForEach-Object {$_.Source})
    } finally { $env:PATH = $before }
    $result = [ordered]@{phase=$Phase; java_home=$javaHome; java_path=$java; java_version=$javaVersion.Trim(); java_home_consumer=$consumerResult; zstd_path=$zstd; zstd_locations=$locations; trusted_path=$trusted; trusted_zstd_matches=$isolated}
    $result | ConvertTo-Json -Depth 6 -Compress | Write-Output
    if (Test-Path -LiteralPath '.lab-cache-probe') {throw 'Unexpected existing probe directory'}
    New-Item -ItemType Directory '.lab-cache-probe' | Out-Null
    [IO.File]::WriteAllBytes((Join-Path $PWD '.lab-cache-probe/payload.txt'), [Text.Encoding]::UTF8.GetBytes("cache proof v1`r`n7919`n"))
    $hash = (Get-FileHash '.lab-cache-probe/payload.txt' -Algorithm SHA256).Hash
    "sha256=$hash" >> $env:GITHUB_OUTPUT
    Write-Output "PROBE_PAYLOAD_SHA256=$hash"
}

if ($Phase -eq 'bridge') {
    $source = 'C:\tools\zstd\zstd.exe'
    $destination = "$env:ProgramFiles\zstd\zstd.exe"
    if (-not (Test-Path -LiteralPath $destination)) {
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {throw 'Expected installed zstd not found; no download attempted'}
        if (Test-Path -LiteralPath (Split-Path $destination)) {throw 'Unexpected pre-existing destination directory; refusing mutation'}
        New-Item -ItemType Directory (Split-Path $destination) | Out-Null
        Copy-Item -LiteralPath $source -Destination $destination
        $sourceHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
        $destinationHash = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash
        if ($sourceHash -cne $destinationHash) {throw 'Copied zstd hash mismatch'}
        Write-Output "PROBE_SESSION_ONLY_ZSTD_COPY_SHA256=$sourceHash"
    } else {
        Write-Output 'PROBE_TRUSTED_ZSTD_ALREADY_PRESENT: no copy made'
    }
    $before = $env:PATH
    try {
        $env:PATH = @("$env:ProgramFiles\Git\usr\bin", "$env:ProgramFiles\zstd", "$env:SystemRoot\System32") -join ';'
        $trustedZstd = (Get-Command zstd -CommandType Application).Source
        Version $trustedZstd | ConvertTo-Json -Compress | Write-Output
    } finally { $env:PATH = $before }
    # Exercise the same installed Java without inheriting arbitrary host variables.
    $java = (Get-Command java -CommandType Application).Source
    $discoveredHome = Split-Path (Split-Path $java)
    if (-not (Test-Path -LiteralPath (Join-Path $discoveredHome 'bin\java.exe'))) {throw 'Java command does not expose a direct JDK root; no guess attempted'}
    $env:JAVA_HOME = $discoveredHome
    & "$env:JAVA_HOME\bin\java.exe" -version
    if ($LASTEXITCODE -ne 0) {throw 'Discovered JAVA_HOME consumer failed'}
    Write-Output "PROBE_SESSION_ONLY_JAVA_HOME=$discoveredHome"
}

if ($Phase -eq 'final') {
    Write-Output 'PROBE_COMPLETE: payload and exact cache hits verified by workflow; no new package download, release, publish, signing, service or image change'
}
