#Requires -Version 5.1
<#
.SYNOPSIS
    Sets or restores Quad9 secured DNS (9.9.9.9) on this machine's active network adapters.

.DESCRIPTION
    Points active network adapters at Quad9's secured resolver (blocks known-malicious
    domains, no EDNS Client Subnet) for both IPv4 and IPv6:
      IPv4: 9.9.9.9, 149.112.112.112
      IPv6: 2620:fe::fe, 2620:fe::9

    DNS is set per-adapter as a static override, so it persists across whatever network
    the adapter later joins (e.g. configured in the office, still applies at home).

    On Windows 11 21H2+, also registers Quad9's DNS-over-HTTPS template for these
    addresses and enforces "Encrypted only" (no fallback to plain UDP). DoH registration
    is machine-wide, not per-adapter. On older Windows where the DoH cmdlets don't exist,
    this step is skipped with a warning and plain DNS is still applied.

.PARAMETER InterfaceAlias
    Name(s) of specific network adapter(s) to target (as shown by Get-NetAdapter).
    Default: every adapter currently in the "Up" state.

.PARAMETER Restore
    Reverts the targeted adapter(s) back to automatic (DHCP-assigned) DNS and removes the
    Quad9 DoH registration, instead of setting Quad9.

.PARAMETER Help
    List all available arguments and exit.

.EXAMPLE
    .\Set-Quad9DNS.ps1

.EXAMPLE
    .\Set-Quad9DNS.ps1 -InterfaceAlias "Wi-Fi"

.EXAMPLE
    .\Set-Quad9DNS.ps1 -Restore

.EXAMPLE
    # Run directly from the web, no parameters:
    irm https://example.com/Set-Quad9DNS.ps1 | iex

.EXAMPLE
    # Run directly from the web, with parameters (bare "irm | iex -Foo" does NOT work,
    # since there's nothing after the pipe to bind -Foo to; wrap it in a script block instead):
    iex "& { $(irm https://example.com/Set-Quad9DNS.ps1) } -Restore"
#>

[CmdletBinding()]
param(
    [string[]]$InterfaceAlias,
    [switch]$Restore,
    [switch]$Help
)

if ($Help) {
    Write-Host @"

Set-Quad9DNS.ps1

SYNOPSIS
    Sets or restores Quad9 secured DNS (9.9.9.9) on this machine's active network adapters.

DESCRIPTION
    Points active network adapters at Quad9's secured resolver (blocks known-malicious
    domains, no EDNS Client Subnet) for both IPv4 and IPv6:
      IPv4: 9.9.9.9, 149.112.112.112
      IPv6: 2620:fe::fe, 2620:fe::9

    DNS is set per-adapter as a static override, so it persists across whatever network
    the adapter later joins (e.g. configured in the office, still applies at home).

    On Windows 11 21H2+, also registers Quad9's DNS-over-HTTPS template for these
    addresses and enforces "Encrypted only" (no fallback to plain UDP). DoH registration
    is machine-wide, not per-adapter. On older Windows where the DoH cmdlets don't exist,
    this step is skipped with a warning and plain DNS is still applied.

PARAMETERS
    -InterfaceAlias <name[]>
        Name(s) of specific network adapter(s) to target (as shown by Get-NetAdapter).
        Default: every adapter currently in the "Up" state.

    -Restore
        Reverts the targeted adapter(s) back to automatic (DHCP-assigned) DNS and removes
        the Quad9 DoH registration, instead of setting Quad9.

    -Help
        Show this help and exit.

EXAMPLES
    .\Set-Quad9DNS.ps1
    .\Set-Quad9DNS.ps1 -InterfaceAlias "Wi-Fi"
    .\Set-Quad9DNS.ps1 -Restore

"@
    return
}

if ($PSVersionTable.PSVersion -lt [Version]'5.1') {
    throw "Set-Quad9DNS requires PowerShell 5.1 or later (detected $($PSVersionTable.PSVersion))."
}

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    return
}

$prevErrorActionPreference = $ErrorActionPreference
$ErrorActionPreference = 'Stop'

try {

$quad9Servers = @('9.9.9.9', '149.112.112.112', '2620:fe::fe', '2620:fe::9')

# --- Determine target adapters ------------------------------------------

if ($InterfaceAlias) {
    $adapters = Get-NetAdapter -Name $InterfaceAlias
} else {
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
}

if (-not $adapters) {
    Write-Warning "No matching network adapters found."
    return
}

# --- Apply / restore DNS -------------------------------------------------

foreach ($adapter in $adapters) {
    try {
        if ($Restore) {
            Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ResetServerAddresses
            Write-Host "$($adapter.Name): restored to automatic (DHCP) DNS." -ForegroundColor Green
        } else {
            Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ServerAddresses $quad9Servers
            Write-Host "$($adapter.Name): set to Quad9 ($($quad9Servers -join ', '))." -ForegroundColor Green
        }
    }
    catch {
        Write-Host "$($adapter.Name): failed - $_" -ForegroundColor Red
    }
}

# --- DNS-over-HTTPS enforcement (Windows 11 21H2+) ------------------------
# DoH registration is machine-wide (keyed by server IP), not per-adapter.

$dohTemplate = 'https://dns.quad9.net/dns-query'

if (-not (Get-Command Add-DnsClientDohServerAddress -ErrorAction SilentlyContinue)) {
    Write-Warning "DNS-over-HTTPS cmdlets not found (requires Windows 11 21H2+) - DNS servers were set without encryption enforcement."
} else {
    foreach ($ip in $quad9Servers) {
        try {
            if ($Restore) {
                Remove-DnsClientDohServerAddress -ServerAddress $ip -ErrorAction SilentlyContinue
            } else {
                $existing = Get-DnsClientDohServerAddress -ServerAddress $ip -ErrorAction SilentlyContinue
                if ($existing) {
                    Set-DnsClientDohServerAddress -ServerAddress $ip -DohTemplate $dohTemplate -AllowFallbackToUdp $false -AutoUpgrade $true
                } else {
                    Add-DnsClientDohServerAddress -ServerAddress $ip -DohTemplate $dohTemplate -AllowFallbackToUdp $false -AutoUpgrade $true
                }
            }
        }
        catch {
            Write-Host "${ip}: DoH registration failed - $_" -ForegroundColor Red
        }
    }
    if ($Restore) {
        Write-Host "DNS-over-HTTPS registration removed for Quad9 servers." -ForegroundColor Green
    } else {
        Write-Host "DNS-over-HTTPS set to 'Encrypted only' for Quad9 servers." -ForegroundColor Green
    }
}

# --- Verify current state --------------------------------------------------
# Re-queries live system state (not just "the calls above didn't error") so you
# can confirm what actually took effect, for both -Restore and normal runs.

Write-Host "`n--- Current DNS servers ---`n" -ForegroundColor Cyan
foreach ($adapter in $adapters) {
    foreach ($entry in (Get-DnsClientServerAddress -InterfaceAlias $adapter.Name)) {
        $servers = if ($entry.ServerAddresses) { $entry.ServerAddresses -join ', ' } else { '(none / automatic)' }
        Write-Host "  $($adapter.Name) [$($entry.AddressFamily)]: $servers"
    }
}

Write-Host "`n--- DNS-over-HTTPS status for Quad9 servers ---`n" -ForegroundColor Cyan
if (-not (Get-Command Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue)) {
    Write-Host "  DNS-over-HTTPS cmdlets not available on this OS - cannot verify encryption state." -ForegroundColor Yellow
} else {
    foreach ($ip in $quad9Servers) {
        $doh = Get-DnsClientDohServerAddress -ServerAddress $ip -ErrorAction SilentlyContinue
        if (-not $doh) {
            Write-Host "  ${ip}: not registered (unencrypted)"
        } elseif ($doh.AllowFallbackToUdp) {
            Write-Host "  ${ip}: encrypted, fallback to unencrypted allowed"
        } else {
            Write-Host "  ${ip}: encrypted only (no fallback)" -ForegroundColor Green
        }
    }
}

}
finally {
    $ErrorActionPreference = $prevErrorActionPreference
}
