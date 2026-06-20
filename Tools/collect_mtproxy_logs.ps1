param(
    [string] $Package = "org.zastogram.messenger",
    [string] $OutDir = "",
    [string] $Adb = "",
    [string] $Serial = "",
    [int] $Seconds = 0,
    [switch] $NoClear,
    [switch] $PullOnly
)

$ErrorActionPreference = "Stop"

function Resolve-AdbPath {
    $candidates = @()
    if (-not [string]::IsNullOrWhiteSpace($Adb)) {
        $candidates += $Adb
    }
    if (-not [string]::IsNullOrWhiteSpace($env:ANDROID_HOME)) {
        $candidates += (Join-Path $env:ANDROID_HOME "platform-tools\adb.exe")
    }
    if (-not [string]::IsNullOrWhiteSpace($env:ANDROID_SDK_ROOT)) {
        $candidates += (Join-Path $env:ANDROID_SDK_ROOT "platform-tools\adb.exe")
    }
    if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        $candidates += (Join-Path $env:LOCALAPPDATA "Android\Sdk\platform-tools\adb.exe")
    }

    $pathAdb = Get-Command adb.exe -ErrorAction SilentlyContinue
    if ($pathAdb) {
        $candidates += $pathAdb.Source
    }

    foreach ($candidate in $candidates) {
        if (-not [string]::IsNullOrWhiteSpace($candidate) -and (Test-Path $candidate)) {
            return (Resolve-Path $candidate).Path
        }
    }

    throw "adb.exe not found. Pass -Adb C:\path\to\adb.exe or install Android SDK platform-tools."
}

$script:AdbExe = Resolve-AdbPath
$script:AdbPrefix = @()
if (-not [string]::IsNullOrWhiteSpace($Serial)) {
    $script:AdbPrefix += @("-s", $Serial)
}

function Invoke-Adb {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]] $Args)

    $allArgs = @()
    $allArgs += $script:AdbPrefix
    $allArgs += $Args
    & $script:AdbExe @allArgs
}

function Test-DevicePackage {
    param([string] $Name)
    if ([string]::IsNullOrWhiteSpace($Name)) {
        return $false
    }
    $result = Invoke-Adb shell pm path $Name 2>$null
    return ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace(($result | Out-String).Trim()))
}

function Resolve-DevicePackage {
    param([string] $RequestedPackage)

    if (Test-DevicePackage $RequestedPackage) {
        return $RequestedPackage
    }

    $knownPackages = @(
        "org.zastogram.messenger.beta",
        "org.zastogram.messenger",
        "org.zastogram.messenger.web",
        "org.telegram.messenger.beta",
        "org.telegram.messenger",
        "org.telegram.messenger.web"
    )
    foreach ($knownPackage in $knownPackages) {
        if ($knownPackage -ne $RequestedPackage -and (Test-DevicePackage $knownPackage)) {
            Write-Warning "Package '$RequestedPackage' was not found; using '$knownPackage'. Pass -Package to override."
            return $knownPackage
        }
    }

    Write-Warning "Package '$RequestedPackage' was not found. Continuing anyway; file-log pull may fail."
    return $RequestedPackage
}

if ([string]::IsNullOrWhiteSpace($OutDir)) {
    $OutDir = Join-Path (Get-Location) "mtproxy-logs"
}

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$sessionDir = Join-Path $OutDir $stamp
New-Item -ItemType Directory -Force -Path $sessionDir | Out-Null

$resolvedPackage = Resolve-DevicePackage $Package
$metaPath = Join-Path $sessionDir "meta.txt"

"adb=$script:AdbExe" | Set-Content -Encoding UTF8 $metaPath
"serial=$Serial" | Add-Content -Encoding UTF8 $metaPath
"package=$resolvedPackage" | Add-Content -Encoding UTF8 $metaPath
"started=$((Get-Date).ToString('o'))" | Add-Content -Encoding UTF8 $metaPath

Invoke-Adb devices -l | Tee-Object -FilePath (Join-Path $sessionDir "adb_devices.txt") | Out-Host
Invoke-Adb shell pm path $resolvedPackage 2>&1 | Tee-Object -FilePath (Join-Path $sessionDir "pm_path.txt") | Out-Null
Invoke-Adb shell dumpsys package $resolvedPackage 2>&1 | Set-Content -Encoding UTF8 (Join-Path $sessionDir "dumpsys_package.txt")

if (-not $PullOnly) {
    if (-not $NoClear) {
        Invoke-Adb logcat -c | Out-Null
    }

    $logcatPath = Join-Path $sessionDir "logcat.txt"
    $logcatErrPath = Join-Path $sessionDir "logcat.stderr.txt"
    $logcatArgs = @()
    $logcatArgs += $script:AdbPrefix
    $logcatArgs += @(
        "logcat",
        "-v",
        "threadtime",
        "-s",
        "tgnet:V",
        "tgnetREF:V",
        "tmessages:V",
        "MTProto:V",
        "AndroidRuntime:E",
        "*:S"
    )

    Write-Host ""
    Write-Host "Recording logcat to $logcatPath"
    if ($Seconds -gt 0) {
        Write-Host "Run the MTProxy test now. Recording will stop in $Seconds seconds."
    } else {
        Write-Host "Run the MTProxy test now, then press Enter here to stop recording."
    }

    $process = Start-Process -FilePath $script:AdbExe -ArgumentList $logcatArgs -RedirectStandardOutput $logcatPath -RedirectStandardError $logcatErrPath -PassThru -WindowStyle Hidden
    try {
        if ($Seconds -gt 0) {
            Start-Sleep -Seconds $Seconds
        } else {
            [void] [Console]::ReadLine()
        }
    } finally {
        if (-not $process.HasExited) {
            $process.Kill()
            $process.WaitForExit()
        }
    }
}

$remoteLogDir = "/sdcard/Android/data/$resolvedPackage/files/logs"
$deviceLogsDir = Join-Path $sessionDir "device_logs"
New-Item -ItemType Directory -Force -Path $deviceLogsDir | Out-Null

Invoke-Adb shell ls -la $remoteLogDir 2>&1 | Tee-Object -FilePath (Join-Path $sessionDir "device_logs_ls.txt") | Out-Null
Invoke-Adb pull $remoteLogDir $deviceLogsDir 2>&1 | Tee-Object -FilePath (Join-Path $sessionDir "adb_pull_logs.txt") | Out-Null

$markerPattern = "connection\(0x[0-9a-fA-F]+, account[0-9]+, dc[0-9]+, type [0-9]+\)|connecting via proxy|mtproxy_startup|mtproxy_disconnect|proxy_check_|proxy_check_scheduler|proxy_rotation|client_hello|client_hello_fragment|server_hello|first_tls|tls_alert|recv_eof|admission_|socket_connected|on_connected|TLS response|TLS server hello|TLS pending|ClientHello pending|socket error|EPOLLHUP|EPOLLRDHUP"
$markerPath = Join-Path $sessionDir "mtproxy_markers.txt"
$textFiles = @(Join-Path $sessionDir "logcat.txt")
$matches = foreach ($file in $textFiles) {
    if (-not (Test-Path $file)) {
        continue
    }
    Select-String -Path $file -Pattern $markerPattern | ForEach-Object {
        "{0}:{1}: {2}" -f $_.Path, $_.LineNumber, $_.Line
    }
}

if ($matches) {
    $matches | Set-Content -Encoding UTF8 $markerPath
} else {
    "No MTProxy markers found." | Set-Content -Encoding UTF8 $markerPath
}

$analysisPath = Join-Path $sessionDir "mtproxy_analysis.txt"
$analyzerPath = Join-Path $PSScriptRoot "analyze_mtproxy_markers.py"
function Convert-ToWslPath {
    param([Parameter(Mandatory=$true)][string]$Path)
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    if ($fullPath -match '^([A-Za-z]):\\(.*)$') {
        $drive = $matches[1].ToLowerInvariant()
        $tail = $matches[2] -replace '\\', '/'
        return "/mnt/$drive/$tail"
    }
    return ($fullPath -replace '\\', '/')
}

$python = Get-Command python3 -ErrorAction SilentlyContinue
if (-not $python) {
    $python = Get-Command python -ErrorAction SilentlyContinue
}
if ($python -and (Test-Path $analyzerPath)) {
    $pythonPath = $python.Source
    $analysisLines = & $pythonPath $analyzerPath $markerPath --out-dir $sessionDir 2>&1
    $analysisLines | Set-Content -Encoding UTF8 $analysisPath
    $analysisLines | Out-Host
} else {
    $wsl = Get-Command wsl.exe -ErrorAction SilentlyContinue
    if ($wsl -and (Test-Path $analyzerPath)) {
        $analyzerUnix = Convert-ToWslPath $analyzerPath
        $markerUnix = Convert-ToWslPath $markerPath
        $sessionUnix = Convert-ToWslPath $sessionDir
        $stdoutPath = Join-Path $sessionDir "mtproxy_analysis_wsl_stdout.tmp"
        $stderrPath = Join-Path $sessionDir "mtproxy_analysis_wsl_stderr.tmp"
        $process = Start-Process -FilePath $wsl.Source -ArgumentList @("python3", $analyzerUnix, $markerUnix, "--out-dir", $sessionUnix) -Wait -PassThru -NoNewWindow -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
        $analysisLines = @()
        if (Test-Path $stdoutPath) {
            $analysisLines += Get-Content $stdoutPath
        }
        if (Test-Path $stderrPath) {
            $analysisLines += Get-Content $stderrPath
        }
        if (-not $analysisLines) {
            $analysisLines = @("WSL analyzer produced no output.")
        }
        $analysisLines | Set-Content -Encoding UTF8 $analysisPath
        $analysisLines | Out-Host
        if ($process.ExitCode -ne 0) {
            "WSL analyzer exited with code $($process.ExitCode)." | Add-Content -Encoding UTF8 $analysisPath
        }
        Remove-Item -Force -ErrorAction SilentlyContinue $stdoutPath, $stderrPath
    } else {
        "Python was not found; skipped MTProxy marker analysis." | Set-Content -Encoding UTF8 $analysisPath
    }
}

"finished=$((Get-Date).ToString('o'))" | Add-Content -Encoding UTF8 $metaPath

Write-Host ""
Write-Host "Done."
Write-Host "Session directory: $sessionDir"
Write-Host "Markers: $markerPath"
Write-Host "Analysis: $analysisPath"
