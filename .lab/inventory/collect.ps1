param([ValidateSet('host','runtime')][string]$Phase)
$ErrorActionPreference = 'Stop'

function Failure($ErrorRecord) {
    $kind = 'unknown'
    if ($ErrorRecord.Exception -is [UnauthorizedAccessException] -or $ErrorRecord.FullyQualifiedErrorId -match 'Unauthorized|AccessDenied') { $kind = 'permission-denied' }
    elseif ($ErrorRecord.FullyQualifiedErrorId -match 'PathNotFound|ItemNotFound|CommandNotFound') { $kind = 'not-found' }
    return [ordered]@{status=$kind; error_type=$ErrorRecord.Exception.GetType().FullName; error_id=$ErrorRecord.FullyQualifiedErrorId}
}
function FileInfo($Path) {
    try {
        $f = Get-Item -LiteralPath $Path -ErrorAction Stop
        return [ordered]@{status='present'; path=$f.FullName; directory=$f.PSIsContainer; file_version=$f.VersionInfo.FileVersion; product_version=$f.VersionInfo.ProductVersion; length=$f.Length; last_write_utc=$f.LastWriteTimeUtc.ToString('o')}
    } catch { return (Failure $_) }
}
function Dirs($Path) {
    try {
        $d = Get-Item -LiteralPath $Path -ErrorAction Stop
        $items = @(Get-ChildItem -LiteralPath $Path -Directory -ErrorAction Stop | Select-Object -First 41)
        return [ordered]@{status='present'; path=$d.FullName; directories=@($items | Select-Object -First 40 -ExpandProperty Name); truncated=($items.Count -gt 40)}
    } catch { return (Failure $_) }
}
function Probe($Exe, $Arguments, [int]$Timeout=8000) {
    # Only version/list operations. These child-only flags prevent tool bootstrap/telemetry.
    $si = New-Object System.Diagnostics.ProcessStartInfo
    $si.FileName=$Exe; $si.Arguments=$Arguments; $si.UseShellExecute=$false
    $si.RedirectStandardOutput=$true; $si.RedirectStandardError=$true; $si.CreateNoWindow=$true
    $si.EnvironmentVariables['GOTOOLCHAIN']='local'
    $si.EnvironmentVariables['DOTNET_SKIP_FIRST_TIME_EXPERIENCE']='1'
    $si.EnvironmentVariables['DOTNET_CLI_TELEMETRY_OPTOUT']='1'
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo=$si
    try {
        [void]$p.Start()
        $out=$p.StandardOutput.ReadToEndAsync(); $err=$p.StandardError.ReadToEndAsync()
        if (-not $p.WaitForExit($Timeout)) { $p.Kill(); return [ordered]@{status='timeout'; command=$Exe; arguments=$Arguments; timeout_ms=$Timeout} }
        $stdout=$out.Result; $stderr=$err.Result
        return [ordered]@{status='executed'; command=$Exe; arguments=$Arguments; exit_code=$p.ExitCode; stdout=$stdout.Substring(0,[Math]::Min(24000,$stdout.Length)); stderr=$stderr.Substring(0,[Math]::Min(4000,$stderr.Length)); truncated=($stdout.Length -gt 24000 -or $stderr.Length -gt 4000)}
    } catch { return (Failure $_) } finally { $p.Dispose() }
}
function Trusted($Path) {
    if (-not $Path -or $Path -match '\\WindowsApps\\') { return $false }
    foreach ($root in @($env:SystemRoot,$env:ProgramFiles,${env:ProgramFiles(x86)},'C:\tools','C:\hostedtoolcache','C:\Python','C:\msys64','C:\cygwin','D:\cygwin','C:\ProgramData\chocolatey')) {
        if ($root -and $Path.StartsWith($root,[StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

$result=[ordered]@{schema='windows-image-inventory/v1'; phase=$Phase; timestamp_utc=[DateTime]::UtcNow.ToString('o'); computer_name=[Environment]::MachineName; process_id=$PID; process_64bit=[Environment]::Is64BitProcess; os_64bit=[Environment]::Is64BitOperatingSystem; cwd=(Get-Location).Path; collector_note='Read-only queries; bounded version/list probes; no setup actions/install/package refresh/network fallback. File timestamps are not image build dates.'}
$result.identity=[ordered]@{}
foreach($name in @('BUILDKITE_BUILD_ID','BUILDKITE_BUILD_NUMBER','BUILDKITE_BUILD_URL','BUILDKITE_JOB_ID','BUILDKITE_AGENT_ID','BUILDKITE_AGENT_NAME','BUILDKITE_AGENT_VERSION','BUILDKITE_PIPELINE_SLUG','BUILDKITE_COMMIT')) { $result.identity[$name]=[Environment]::GetEnvironmentVariable($name) }
try {
    $os=Get-CimInstance Win32_OperatingSystem
    $result.os=[ordered]@{status='observed'; caption=$os.Caption; version=$os.Version; build=$os.BuildNumber; architecture=$os.OSArchitecture; install_date=$os.InstallDate.ToUniversalTime().ToString('o'); last_boot=$os.LastBootUpTime.ToUniversalTime().ToString('o')}
} catch { $result.os=Failure $_ }
try {
    $v=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $result.os_registry=[ordered]@{status='observed'; product_name=$v.ProductName; current_build=$v.CurrentBuild; ubr=$v.UBR; display_version=$v.DisplayVersion; edition_id=$v.EditionID; build_lab_ex=$v.BuildLabEx}
} catch { $result.os_registry=Failure $_ }
$result.shell=[ordered]@{version=$PSVersionTable.PSVersion.ToString(); edition=$PSVersionTable.PSEdition; ps_home=$PSHOME; clr_version=[string]$PSVersionTable.CLRVersion}
try {
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    $principal=New-Object Security.Principal.WindowsPrincipal($id)
    $result.elevation=[ordered]@{status='observed'; effective_admin=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator); note='Effective token membership, not a claim about UAC configuration or all privileges.'}
} catch { $result.elevation=Failure $_ }
$result.path=@($env:PATH -split ';')
$result.safe_tool_variables=[ordered]@{}
foreach($name in @('JAVA_HOME','JAVA_HOME_8_X64','JAVA_HOME_11_X64','JAVA_HOME_17_X64','JAVA_HOME_21_X64','JAVA_HOME_25_X64','VCPKG_INSTALLATION_ROOT','CONDA','CONDA_PREFIX','ANDROID_HOME','ANDROID_SDK_ROOT','ANDROID_NDK_HOME','RUNNER_TOOL_CACHE','ImageOS','ImageVersion')) {
    $value=[Environment]::GetEnvironmentVariable($name)
    $result.safe_tool_variables[$name]=[ordered]@{present=($null -ne $value); value=$value}
}
$pf=$env:ProgramFiles; $px=${env:ProgramFiles(x86)}; $win=$env:SystemRoot
$known=[ordered]@{
    powershell=@("$win\System32\WindowsPowerShell\v1.0\powershell.exe")
    pwsh=@("$pf\PowerShell\7\pwsh.exe")
    bash=@("$pf\Git\bin\bash.exe","$pf\Git\usr\bin\bash.exe",'C:\msys64\usr\bin\bash.exe','C:\cygwin64\bin\bash.exe','D:\cygwin\bin\bash.exe')
    git=@("$pf\Git\cmd\git.exe","$pf\Git\bin\git.exe")
    'git-lfs'=@("$pf\Git\cmd\git-lfs.exe","$pf\Git\mingw64\bin\git-lfs.exe")
    tar=@("$pf\Git\usr\bin\tar.exe","$win\System32\tar.exe")
    '7z'=@("$pf\7-Zip\7z.exe",'C:\tools\7zip\7z.exe')
    zstd=@("$pf\zstd\zstd.exe","$pf\Git\usr\bin\zstd.exe",'C:\tools\zstd\zstd.exe','C:\msys64\usr\bin\zstd.exe')
    node=@("$pf\nodejs\node.exe",'C:\nodejs\node.exe')
    python=@('C:\Python312\python.exe','C:\Python313\python.exe',"$pf\Python312\python.exe","$pf\Python313\python.exe")
    python3=@('C:\Python312\python3.exe','C:\Python313\python3.exe')
    go=@("$pf\Go\bin\go.exe",'C:\Go\bin\go.exe')
    java=@("$pf\Java\jdk-17\bin\java.exe")
    dotnet=@("$pf\dotnet\dotnet.exe","$px\dotnet\dotnet.exe")
    cmake=@("$pf\CMake\bin\cmake.exe")
    ninja=@("$pf\CMake\bin\ninja.exe",'C:\tools\ninja\ninja.exe')
    vswhere=@("$px\Microsoft Visual Studio\Installer\vswhere.exe")
}
$argsByName=@{powershell='-NoProfile -NonInteractive -Command "$PSVersionTable.PSVersion.ToString()"';pwsh='--version';bash='--version';git='--version';'git-lfs'='version';tar='--version';'7z'='i';zstd='--version';node='--version';python='--version';python3='--version';go='version';java='-version';dotnet='--list-sdks';cmake='--version';ninja='--version';vswhere='-all -products * -format json -utf8'}
$result.tools=[ordered]@{}
foreach($name in $known.Keys) {
    $commands=@(); $lookup='resolved'
    try { $commands=@(Get-Command -Name $name -All -CommandType Application -ErrorAction Stop | Select-Object -First 12) }
    catch { $lookup=(Failure $_).status }
    $entry=[ordered]@{lookup_status=$lookup; resolved=@($commands | ForEach-Object { $_.Source }); known_locations=[ordered]@{}; version_probes=@()}
    $paths=@(@($known[$name])+@($commands | ForEach-Object {$_.Source}) | Select-Object -Unique)
    foreach($path in $paths) {
        $info=FileInfo $path; $entry.known_locations[$path]=$info
        if($info.status -eq 'present' -and -not $info.directory) {
            if(Trusted $path) { $entry.version_probes+=,(Probe $path $argsByName[$name]) }
            else { $entry.version_probes+=,[ordered]@{status='not-executed'; command=$path; reason='Outside trusted installation roots or Windows Store alias'} }
        }
    }
    $result.tools[$name]=$entry
}
$result.dotnet_runtimes=@()
foreach($exe in $known.dotnet) { if((FileInfo $exe).status -eq 'present') { $result.dotnet_runtimes+=,(Probe $exe '--list-runtimes') } }
try {
    $fx=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full'
    $result.framework_v4_full=[ordered]@{status='observed'; release=$fx.Release; version=$fx.Version; install=$fx.Install}
} catch { $result.framework_v4_full=Failure $_ }
$directoryPaths=@("$px\Reference Assemblies\Microsoft\Framework\.NETFramework","$pf\dotnet\packs","$px\Windows Kits\10\Include","$px\Windows Kits\10\bin","$px\Windows Kits\NETFXSDK",'C:\hostedtoolcache','C:\hostedtoolcache\windows','C:\actions\_work\_tool','C:\tools','C:\msys64','C:\msys64\usr\bin','C:\cygwin64','D:\cygwin',"$pf\Java","$pf\Eclipse Adoptium","$pf\Microsoft\jdk",'C:\ProgramData\chocolatey\lib')
foreach($root in @("$pf\Microsoft Visual Studio\2022","$px\Microsoft Visual Studio\2022")) {
    $directoryPaths+=$root
    try { foreach($edition in @(Get-ChildItem -LiteralPath $root -Directory | Select-Object -First 8)) { $directoryPaths+=($edition.FullName+'\VC\Tools\MSVC'); $directoryPaths+=($edition.FullName+'\MSBuild\Current\Bin') } } catch {}
}
$result.directories=[ordered]@{}
foreach($path in $directoryPaths) { $result.directories[$path]=Dirs $path }
$vs=$known.vswhere[0]; $result.vs_workload_queries=[ordered]@{}
if((FileInfo $vs).status -eq 'present') {
    foreach($workload in @('Microsoft.VisualStudio.Workload.NativeDesktop','Microsoft.VisualStudio.Workload.ManagedDesktop','Microsoft.VisualStudio.Workload.NetWeb','Microsoft.VisualStudio.Workload.VCTools','Microsoft.VisualStudio.Component.VC.Tools.x86.x64')) {
        $result.vs_workload_queries[$workload]=Probe $vs ('-all -products * -requires '+$workload+' -property instanceId')
    }
}
$result.services=[ordered]@{}
foreach($name in @('docker','com.docker.service','sshd','W32Time','postgresql*','MongoDB*')) {
    try { $s=@(Get-Service -Name $name -ErrorAction Stop); $result.services[$name]=[ordered]@{status='observed'; matches=@($s | Select-Object Name,Status,StartType)} }
    catch { $result.services[$name]=Failure $_ }
}
$featureScript = "`$ErrorActionPreference='Stop'; foreach (`$n in @('Microsoft-Windows-Subsystem-Linux','Containers','Microsoft-Hyper-V-All','VirtualMachinePlatform')) { try { Get-WindowsOptionalFeature -Online -FeatureName `$n | Select-Object FeatureName,State | ConvertTo-Json -Compress } catch { [ordered]@{name=`$n;status='unknown';error_type=`$_.Exception.GetType().FullName;error_id=`$_.FullyQualifiedErrorId} | ConvertTo-Json -Compress } }"
$encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($featureScript))
$result.optional_features=Probe "$win\System32\WindowsPowerShell\v1.0\powershell.exe" ('-NoProfile -NonInteractive -EncodedCommand '+$encoded) 20000
$result.provider_image_identity=[ordered]@{status='unknown'; note='No cloud metadata endpoints queried. ImageOS/ImageVersion above and safe agent API metadata are the only candidate provider identifiers; OS/file install timestamps are not image provenance.'}
Write-Output ('INVENTORY_JSON_BEGIN_'+$Phase)
$result | ConvertTo-Json -Depth 12 -Compress
Write-Output ('INVENTORY_JSON_END_'+$Phase)
