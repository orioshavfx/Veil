# Veil rescue: puts the network back after a TUN session that did not clean up
# (sites do not open, DNS does not work, even with Veil closed).
#
# Run it from this folder:
#     powershell -ExecutionPolicy Bypass -File .\veil-rescue.ps1
# It asks for administrator rights by itself. It is safe to run any number of times and
# touches only what Veil created:
#   - DNS policy (NRPT) rules whose comment is 'Veil' (through the DnsClient cmdlets, and
#     straight in the registry when those are missing or leave a rule behind);
#   - the routes 0.0.0.0/1, 128.0.0.0/1, ::/1, 8000::/1 and the DNS servers, only on the
#     adapter named 'Veil' that has the address 198.18.0.1 (Veil's TUN adapter), if it still exists;
#   - host routes to proxy servers, only those listed in Veil's own journal
#     (%LOCALAPPDATA%\Veil\tun-state.json); without a journal no host route is touched;
#   - the DNS cache (ipconfig /flushdns).
# The default route, other adapters and other programs' rules are never changed.
# The state before and after is written to veil-rescue.txt next to this script.
param([switch]$Elevated)

$ErrorActionPreference = 'Continue'
$self = $MyInvocation.MyCommand.Path
$here = Split-Path -Parent $self
$tag = 'Veil'
$tunAddress = '198.18.0.1'
$tunAlias = 'Veil'
# Local NRPT rules: one subkey (a GUID) per rule, with the rule's comment as a value.
$nrptKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig'
$haveNrptCmdlets = [bool](Get-Command Get-DnsClientNrptRule -ErrorAction SilentlyContinue)
$prefixes = @('0.0.0.0/1', '128.0.0.0/1', '::/1', '8000::/1')

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    if ($Elevated) {
        Write-Host 'Still no administrator rights. Open PowerShell with "Run as administrator" and start this script there.'
        exit 2
    }
    Write-Host 'Asking for administrator rights...'
    try {
        $exe = (Get-Process -Id $PID).Path
        $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $self + '"'), '-Elevated')
        $p = Start-Process -FilePath $exe -ArgumentList $argList -Verb RunAs -Wait -PassThru
        exit $p.ExitCode
    } catch {
        Write-Host ('Administrator permission was not given: ' + $_.Exception.Message)
        Write-Host 'Nothing was changed. Run the script again and answer Yes.'
        exit 2
    }
}

$lines = New-Object System.Collections.Generic.List[string]
function Log([string]$text) {
    $lines.Add($text)
    Write-Host $text
}
function LogBlock($object) {
    $text = ($object | Out-String).TrimEnd()
    if ($text) { Log $text } else { Log '  (none)' }
}

function Get-VeilRules {
    if (-not $haveNrptCmdlets) { return @() }
    @(Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object { $_.Comment -eq $tag })
}
function Get-VeilRuleKeys {
    @(Get-ChildItem -LiteralPath $nrptKey -ErrorAction SilentlyContinue | Where-Object {
        (Get-ItemProperty -LiteralPath $_.PSPath -Name Comment -ErrorAction SilentlyContinue).Comment -eq $tag })
}
function Test-VeilRulesLeft {
    (@(Get-VeilRules).Count + @(Get-VeilRuleKeys).Count) -gt 0
}
function Get-TunInterfaces {
    @(Get-NetIPAddress -IPAddress $tunAddress -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceAlias -eq $tunAlias } |
        ForEach-Object { $_.InterfaceIndex } | Select-Object -Unique)
}
function Test-Dns {
    try {
        $r = @(Resolve-DnsName -Name 'example.com' -Type A -DnsOnly -QuickTimeout -ErrorAction Stop |
            Where-Object { $_.IPAddress })
        if ($r.Count -gt 0) { return ('OK: example.com -> ' + $r[0].IPAddress) }
        return 'FAILED: no address in the answer'
    } catch {
        return ('FAILED: ' + $_.Exception.Message)
    }
}
function Show-State([string]$title) {
    Log ''
    Log ('===== ' + $title + ' =====')
    Log '--- all DNS policy (NRPT) rules ---'
    if ($haveNrptCmdlets) {
        LogBlock (Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Format-List Name, Namespace, NameServers, DisplayName, Comment)
    } else {
        Log '  (DnsClient cmdlets not available, showing the registry)'
        LogBlock (Get-ChildItem -LiteralPath $nrptKey -ErrorAction SilentlyContinue | ForEach-Object {
            Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue } |
            Format-List PSChildName, Name, GenericDNSServers, DisplayName, Comment)
    }
    Log ('--- adapters with the address ' + $tunAddress + ' (ours only if named ' + $tunAlias + ') ---')
    LogBlock (Get-NetIPAddress -IPAddress $tunAddress -ErrorAction SilentlyContinue | Format-Table InterfaceIndex, InterfaceAlias, IPAddress, PrefixLength -AutoSize)
    Log '--- split routes (any adapter) ---'
    LogBlock ($prefixes | ForEach-Object { Get-NetRoute -DestinationPrefix $_ -ErrorAction SilentlyContinue } | Format-Table DestinationPrefix, InterfaceIndex, InterfaceAlias, NextHop, RouteMetric -AutoSize)
    Log '--- default routes ---'
    LogBlock (Get-NetRoute -DestinationPrefix '0.0.0.0/0', '::/0' -ErrorAction SilentlyContinue | Format-Table DestinationPrefix, InterfaceIndex, InterfaceAlias, NextHop, RouteMetric -AutoSize)
    Log '--- DNS servers per adapter ---'
    LogBlock (Get-DnsClientServerAddress -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses } | Format-Table InterfaceIndex, InterfaceAlias, AddressFamily, ServerAddresses -AutoSize)
    Log ('--- DNS test: ' + (Test-Dns))
}

Log ('Veil rescue, ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + ', Windows ' + [Environment]::OSVersion.Version)
$running = @(Get-Process -Name 'Veil', 'veil-cli' -ErrorAction SilentlyContinue)
if ($running.Count -gt 0) {
    Log ('NOTE: Veil is running (' + (($running | ForEach-Object { $_.ProcessName + ' ' + $_.Id }) -join ', ') + '). Quit it first if you can: a TUN connection will stop working after this cleanup.')
}

$journalPath = Join-Path (Join-Path $env:LOCALAPPDATA 'Veil') 'tun-state.json'
$journal = $null
if (Test-Path -LiteralPath $journalPath) {
    try { $journal = Get-Content -LiteralPath $journalPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop }
    catch { Log ('Journal ' + $journalPath + ' is unreadable, ignored: ' + $_.Exception.Message) }
}
if ($journal) { Log ('Journal found: ' + $journalPath) } else { Log 'No journal: host routes are left alone.' }

Show-State 'BEFORE'
Log ''
Log '===== CLEANUP ====='
$problems = 0

# 1. The DNS policy rule: the one thing that survives the adapter, the process and a reboot.
if (-not $haveNrptCmdlets) { Log 'NRPT: the DnsClient cmdlets are not available, using the registry.' }
$rules = @(Get-VeilRules)
foreach ($rule in $rules) {
    try {
        Remove-DnsClientNrptRule -Name $rule.Name -Force -ErrorAction Stop
        Log ('NRPT: removed rule ' + $rule.Name + ' (' + ($rule.Namespace -join ',') + ' -> ' + ($rule.NameServers -join ',') + ')')
    } catch {
        Log ('NRPT: could NOT remove rule ' + $rule.Name + ': ' + $_.Exception.Message)
    }
}
# Fallback, and a check of the cmdlets' work: the rule keys themselves.
$keys = @(Get-VeilRuleKeys)
foreach ($key in $keys) {
    try {
        Remove-Item -LiteralPath $key.PSPath -Recurse -Force -ErrorAction Stop
        Log ('NRPT: removed registry key ' + $key.PSChildName)
    } catch {
        Log ('NRPT: could NOT remove registry key ' + $key.PSChildName + ': ' + $_.Exception.Message)
    }
}
if ($rules.Count -eq 0 -and $keys.Count -eq 0) {
    Log ('NRPT: no rule with the comment ' + $tag + '.')
} elseif (Test-VeilRulesLeft) {
    $problems++; Log 'NRPT: a Veil rule is STILL present.'
}

# 2. Split routes and DNS, only on the adapter that owns Veil's TUN address.
$tunIfs = @(Get-TunInterfaces)
if ($tunIfs.Count -eq 0) {
    Log ('TUN adapter: none is named ' + $tunAlias + ' with the address ' + $tunAddress + ' (it disappears with Veil), nothing to do.')
}
foreach ($i in $tunIfs) {
    foreach ($p in $prefixes) {
        $routes = @(Get-NetRoute -DestinationPrefix $p -InterfaceIndex $i -ErrorAction SilentlyContinue)
        if ($routes.Count -eq 0) { continue }
        Remove-NetRoute -DestinationPrefix $p -InterfaceIndex $i -Confirm:$false -ErrorAction SilentlyContinue
        if (@(Get-NetRoute -DestinationPrefix $p -InterfaceIndex $i -ErrorAction SilentlyContinue).Count -eq 0) {
            Log ('Route: removed ' + $p + ' on interface ' + $i)
        } else {
            $problems++; Log ('Route: could NOT remove ' + $p + ' on interface ' + $i)
        }
    }
    try {
        Set-DnsClientServerAddress -InterfaceIndex $i -ResetServerAddresses -ErrorAction Stop
        Log ('DNS: reset on interface ' + $i)
    } catch {
        Log ('DNS: could not reset on interface ' + $i + ': ' + $_.Exception.Message)
    }
}

# 3. Host routes to proxy servers: only the ones the journal names, through its gateway.
if ($journal -and $journal.host_routes) {
    foreach ($ip in @($journal.host_routes)) {
        $ip = [string]$ip
        $parsed = $null
        if (-not [System.Net.IPAddress]::TryParse($ip, [ref]$parsed)) { continue }
        $v6 = $parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6
        if ($v6) { $prefix = $ip + '/128' } else { $prefix = $ip + '/32' }
        $found = @(Get-NetRoute -DestinationPrefix $prefix -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
            Where-Object { $_.RouteMetric -eq 1 -and ($v6 -or -not $journal.gateway -or $_.NextHop -eq [string]$journal.gateway) })
        foreach ($r in $found) {
            Remove-NetRoute -InputObject $r -Confirm:$false -ErrorAction SilentlyContinue
            Log ('Host route: removed ' + $prefix + ' via ' + $r.NextHop)
        }
    }
}

# 4. The journal has done its job once the rule is gone.
if ($journal -and -not (Test-VeilRulesLeft)) {
    Remove-Item -LiteralPath $journalPath -Force -ErrorAction SilentlyContinue
    Log 'Journal: removed.'
}

# 5. Cached answers may still point at Veil's fake addresses (198.18.x.x).
& ipconfig.exe /flushdns | Out-Null
Log 'DNS cache: flushed.'

Show-State 'AFTER'
Log ''
if ($problems -eq 0) {
    Log 'RESULT: done, nothing of Veil is left in the network settings.'
    Log 'If sites still do not open, the cause is elsewhere: send veil-rescue.txt.'
} else {
    Log ('RESULT: ' + $problems + ' item(s) could not be removed, see above. Send veil-rescue.txt.')
}

$report = Join-Path $here 'veil-rescue.txt'
try {
    $lines | Out-File -FilePath $report -Encoding utf8 -ErrorAction Stop
} catch {
    $report = Join-Path $env:TEMP 'veil-rescue.txt'
    $lines | Out-File -FilePath $report -Encoding utf8
}
Write-Host ''
Write-Host ('Report: ' + $report)
if ($Elevated) { Read-Host 'Press Enter to close' | Out-Null }
if ($problems -eq 0) { exit 0 } else { exit 1 }
