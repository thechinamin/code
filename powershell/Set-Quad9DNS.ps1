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

.PARAMETER InterfaceAlias
    Name(s) of specific network adapter(s) to target (as shown by Get-NetAdapter).
    Default: every adapter currently in the "Up" state.

.PARAMETER Restore
    Reverts the targeted adapter(s) back to automatic (DHCP-assigned) DNS instead of
    setting Quad9.

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

PARAMETERS
    -InterfaceAlias <name[]>
        Name(s) of specific network adapter(s) to target (as shown by Get-NetAdapter).
        Default: every adapter currently in the "Up" state.

    -Restore
        Reverts the targeted adapter(s) back to automatic (DHCP-assigned) DNS instead
        of setting Quad9.

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

}
finally {
    $ErrorActionPreference = $prevErrorActionPreference
}
