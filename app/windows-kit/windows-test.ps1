# Veil — Windows check, stage W1: every protocol on a local port, then the
# system proxy (set, used by Windows, restored after a crash). No TUN yet.
# Usage (PowerShell, in this folder):
#   powershell -ExecutionPolicy Bypass -File .\windows-test.ps1 -Subscription "https://your-subscription-url"
param([Parameter(Mandatory = $true)][string]$Subscription)

$ErrorActionPreference = "Continue"
# veil-cli.exe prints UTF-8 (server names are Cyrillic with emoji).
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$veil = Join-Path $here "veil-cli.exe"
$report = Join-Path $here "veil-report.txt"
$port = 23080
Set-Content -Path $report -Value "" -Encoding UTF8
function Log($s) { Write-Output $s; Add-Content -Path $report -Value $s -Encoding UTF8 }

$inet = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
function ProxyState {
    $p = Get-ItemProperty -Path $inet -ErrorAction SilentlyContinue
    "ProxyEnable=$($p.ProxyEnable) ProxyServer=$($p.ProxyServer) AutoConfigURL=$($p.AutoConfigURL) ProxyOverride=$($p.ProxyOverride)"
}
# PowerShell 5.1 web requests use the system (WinINet) proxy.
function IpViaSystem {
    try { (Invoke-WebRequest -UseBasicParsing -TimeoutSec 20 https://api.ipify.org).Content } catch { "FAILED: $($_.Exception.Message)" }
}

Log "=== Veil W1 report $(Get-Date -Format s)"
Log "Windows: $([Environment]::OSVersion.VersionString), $env:PROCESSOR_ARCHITECTURE, PowerShell $($PSVersionTable.PSVersion)"
Log "veil: $(& $veil --version 2>&1)"
$direct = curl.exe -s --max-time 10 https://api.ipify.org
Log "direct IP: $direct"

Log "=== import"
& $veil import $Subscription 2>&1 | Where-Object { $_ -notmatch '^skipped' } | ForEach-Object { Log "$_" }
$list = & $veil list 2>&1
Log "servers: $(($list | Where-Object { $_ -match '^\s*\*?\s*\d+\s' }).Count)"

# One server per protocol: the first line mentioning each.
$working = $null
foreach ($proto in @("vless", "hysteria2", "shadowsocks", "vmess", "trojan")) {
    $line = $list | Where-Object { $_ -match "^\s*\*?\s*(\d+)\s+$proto\s" } | Select-Object -First 1
    if (-not $line) { continue }
    $n = [regex]::Match($line, "^\s*\*?\s*(\d+)").Groups[1].Value
    $name = ($line -replace "^\s*\*?\s*\d+\s+\S+\s+", "") -replace "\s+\(.*\)\s*$", ""
    $log = Join-Path $here "run-$proto.log"
    $p = Start-Process -FilePath $veil -ArgumentList @("run", "--no-sysproxy", "-p", "$port", "--profile", "$n") `
        -RedirectStandardError $log -RedirectStandardOutput "$log.out" -PassThru -WindowStyle Hidden
    Start-Sleep -Seconds 2
    $r = curl.exe -s --max-time 20 -w " (%{time_total}s)" -x "socks5h://127.0.0.1:$port" https://api.ipify.org
    # -w prints the time even when the request fails, so look for an address.
    if ($r -notmatch '^[0-9a-fA-F.:]+ \(') { $r = "FAILED $r" } elseif (-not $working) { $working = $n }
    Log ("{0,-12} #{1,-3} {2,-32} -> {3}" -f $proto, $n, $name, $r)
    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500
    Get-Content $log -ErrorAction SilentlyContinue | Where-Object { $_ -match "WARN|ERROR|panicked" } |
        Select-Object -First 3 | ForEach-Object { Log "    $_" }
}

Log "=== system proxy"
if (-not $working) {
    Log "skipped: no server worked above"
} else {
    $before = ProxyState
    Log "before:   $before"
    $log = Join-Path $here "run-sysproxy.log"
    $p = Start-Process -FilePath $veil -ArgumentList @("run", "-p", "$port", "--profile", "$working") `
        -RedirectStandardError $log -RedirectStandardOutput "$log.out" -PassThru -WindowStyle Hidden
    Start-Sleep -Seconds 3
    Log "running:  $(ProxyState)"
    $ip = IpViaSystem
    $verdict = if ($ip -eq $direct) { "SAME AS DIRECT (system proxy not used?)" } elseif ($ip -match '^FAILED') { "" } else { "ok, differs from direct" }
    Log "IP via system proxy (Invoke-WebRequest): $ip $verdict"
    # Kill it like a crash: the proxy stays set, then `restore-proxy` must undo it.
    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500
    Log "killed:   $(ProxyState)"
    Log "restore-proxy: $(& $veil restore-proxy 2>&1)"
    $after = ProxyState
    Log "restored: $after"
    Log "restored settings equal the original: $($after -eq $before)"
    Log "IP after restore: $(IpViaSystem)"
    Get-Content $log -ErrorAction SilentlyContinue | Where-Object { $_ -match "WARN|ERROR|panicked" } |
        Select-Object -First 5 | ForEach-Object { Log "    $_" }
}
Log "=== done. Now check the app (see README.txt), then send veil-report.txt and %LOCALAPPDATA%\Veil\veil.log."
