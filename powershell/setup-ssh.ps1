#Requires -Version 5.1
<#
Installs or removes OpenSSH Server on a Windows machine for remote access.
Run from an admin PowerShell prompt:
  irm <url> | iex
#>

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    return
}

function Install-Ssh {
    Write-Host "Checking OpenSSH Server capability..."
    $capability = Get-WindowsCapability -Online -Name "OpenSSH.Server~~~~0.0.1.0"
    if ($capability.State -ne "Installed") {
        Write-Host "Installing OpenSSH Server..."
        Add-WindowsCapability -Online -Name "OpenSSH.Server~~~~0.0.1.0"
    } else {
        Write-Host "OpenSSH Server already installed."
    }

    Write-Host "Starting sshd service and setting it to auto-start..."
    Start-Service sshd
    Set-Service -Name sshd -StartupType Automatic

    Write-Host "Opening firewall port 22..."
    if (-not (Get-NetFirewallRule -Name sshd -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -Name sshd -DisplayName "OpenSSH Server (sshd)" -Enabled True -Direction Inbound -Protocol TCP -LocalPort 22
    } else {
        Write-Host "Firewall rule already exists."
    }

    Write-Host "Setting PowerShell as the default SSH shell..."
    New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force | Out-Null

    Write-Host "`nDone. SSH is running on this machine."
    Write-Host "Connect from the shop machine with: ssh <username>@<ip-address>`n"
    Write-Host "IP addresses on this machine:"
    Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne "127.0.0.1" } | Select-Object IPAddress, InterfaceAlias
}

function Remove-Ssh {
    Write-Host "Stopping sshd service..."
    Stop-Service sshd -ErrorAction SilentlyContinue
    Set-Service -Name sshd -StartupType Disabled -ErrorAction SilentlyContinue

    Write-Host "Removing firewall rule..."
    if (Get-NetFirewallRule -Name sshd -ErrorAction SilentlyContinue) {
        Remove-NetFirewallRule -Name sshd
    }

    Write-Host "Removing default shell setting..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -ErrorAction SilentlyContinue

    Write-Host "Uninstalling OpenSSH Server..."
    Remove-WindowsCapability -Online -Name "OpenSSH.Server~~~~0.0.1.0"

    Write-Host "`nDone. SSH has been removed from this machine."
}

$choice = ""
while ($choice -notin @("i", "r")) {
    $choice = Read-Host "Install or remove SSH? (i/r)"
    $choice = $choice.Trim().ToLower()
}

if ($choice -eq "i") {
    Install-Ssh
} else {
    Remove-Ssh
}
