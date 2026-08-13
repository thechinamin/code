#Requires -Version 5.1
<#
.SYNOPSIS
    Checks the local Windows system for known RMM/RAT tools listed in the LOLRMM project.

.DESCRIPTION
    Pulls the tool catalog from https://lolrmm.io/api/rmm_tools.json (or a local copy),
    then cross-references it against:
      - Running processes
      - Installed services (and their binary paths)
      - Installed programs (registry Uninstall keys)
      - Known Registry artifacts listed per-tool
      - Known Disk artifacts listed per-tool
      - Optionally, a filesystem sweep of common install directories

    This is a triage/hunting aid, not a definitive verdict - a match means "this box has
    something that looks like a known RMM tool," not "this box is compromised." Some RMM
    tools are legitimately deployed by IT; verify before acting.

.PARAMETER JsonPath
    Path to a locally-downloaded copy of rmm_tools.json. Use this on boxes without internet
    access (download it ahead of time from https://lolrmm.io/api/rmm_tools.json).

.PARAMETER Category
    Filter the catalog: All, RMM, or RAT. Default: All.

.PARAMETER ScanFilesystem
    Also walks common install directories (Program Files, AppData) looking for filenames
    that match known tool binaries. Slower, off by default.

.PARAMETER OutputCsv
    Path to export findings as CSV.

.PARAMETER Remove
    After reporting, walk each individual finding and prompt [y/N] before taking a
    removal action on it: kill the process, stop+delete the service, run the installed
    program's uninstaller, or delete the matched registry key/file. Off by default.

.EXAMPLE
    .\Check-LOLRMM.ps1

.EXAMPLE
    .\Check-LOLRMM.ps1 -JsonPath C:\tools\rmm_tools.json -ScanFilesystem -OutputCsv findings.csv

.EXAMPLE
    .\Check-LOLRMM.ps1 -Remove

.EXAMPLE
    # Run directly from the web, no parameters:
    irm https://example.com/Check-LOLRMM.ps1 | iex

.EXAMPLE
    # Run directly from the web, with parameters (bare "irm | iex -Foo" does NOT work,
    # since there's nothing after the pipe to bind -Foo to; wrap it in a script block instead):
    iex "& { $(irm https://example.com/Check-LOLRMM.ps1) } -ScanFilesystem -OutputCsv findings.csv -Remove"
#>

[CmdletBinding()]
param(
    [string]$JsonPath,
    [ValidateSet('All', 'RMM', 'RAT')]
    [string]$Category = 'All',
    [switch]$ScanFilesystem,
    [string]$OutputCsv,
    [switch]$Remove
)

if ($PSVersionTable.PSVersion -lt [Version]'5.1') {
    throw "Check-LOLRMM requires PowerShell 5.1 or later (detected $($PSVersionTable.PSVersion))."
}

$prevErrorActionPreference = $ErrorActionPreference
$ErrorActionPreference = 'Stop'

try {
$findings = [System.Collections.Generic.List[object]]::new()

function Add-Finding {
    param($ToolName, $ToolCategory, $MatchType, $MatchedOn, $Detail, $RemoveTarget)
    $findings.Add([PSCustomObject]@{
        Tool         = $ToolName
        Category     = $ToolCategory
        MatchType    = $MatchType
        MatchedOn    = $MatchedOn
        Detail       = $Detail
        RemoveTarget = $RemoveTarget
    })
}

function Invoke-Removal {
    # Takes the removal action appropriate for one finding's MatchType.
    # Throws on failure so the caller can report it; RemoveTarget carries whatever
    # raw identifier that action needs (PID, service name, uninstall string, path).
    param($Finding)
    switch ($Finding.MatchType) {
        'Process' {
            Stop-Process -Id $Finding.RemoveTarget -Force
        }
        'Service' {
            Stop-Service -Name $Finding.RemoveTarget -Force -ErrorAction SilentlyContinue
            $scOutput = & sc.exe delete $Finding.RemoveTarget 2>&1
            if ($LASTEXITCODE -ne 0) { throw "sc.exe delete failed: $scOutput" }
        }
        'InstalledProgram' {
            # Runs the vendor's own uninstall string as-is. Many uninstallers show their
            # own UI/prompts since silent-uninstall flags vary by vendor and aren't known here.
            Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', $Finding.RemoveTarget -Wait
        }
        'RegistryArtifact' {
            Remove-Item -Path $Finding.RemoveTarget -Recurse -Force
        }
        { $_ -in 'DiskArtifact', 'FilesystemMatch' } {
            Remove-Item -Path $Finding.RemoveTarget -Force
        }
        default {
            throw "No removal action defined for match type '$($Finding.MatchType)'."
        }
    }
}

# --- Load catalog -----------------------------------------------------------

if ($JsonPath) {
    Write-Verbose "Loading catalog from local file: $JsonPath"
    if (-not (Test-Path $JsonPath)) { throw "File not found: $JsonPath" }
    $tools = Get-Content -Raw -Path $JsonPath | ConvertFrom-Json
}
else {
    Write-Verbose "Downloading catalog from https://lolrmm.io/api/rmm_tools.json"
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $tools = Invoke-RestMethod -Uri 'https://lolrmm.io/api/rmm_tools.json' -TimeoutSec 30
    }
    catch {
        throw "Failed to download LOLRMM catalog (no internet on this box?). " +
              "Download it manually and re-run with -JsonPath. Error: $_"
    }
}

if ($Category -ne 'All') {
    $tools = $tools | Where-Object { $_.Category -eq $Category }
}

Write-Verbose "Loaded $($tools.Count) tool entries."

# --- Gather local system data ------------------------------------------------

Write-Verbose "Enumerating processes..."
$procs = Get-Process | Select-Object Name, Id, @{N='Path';E={ try { $_.Path } catch { $null } }}

Write-Verbose "Enumerating services..."
$services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
    Select-Object Name, DisplayName, PathName

Write-Verbose "Enumerating installed programs..."
$uninstallKeys = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$installedPrograms = foreach ($key in $uninstallKeys) {
    Get-ItemProperty -Path $key -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName } |
        Select-Object DisplayName, InstallLocation, UninstallString
}

# Mount HKEY_USERS so registry artifact paths under HKU can be tested
if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
    New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS -ErrorAction SilentlyContinue | Out-Null
}

function Convert-RegPathToPSPath {
    param([string]$Path)
    ($Path -replace '^HKLM\\', 'HKLM:\' -replace '^HKCU\\', 'HKCU:\' `
           -replace '^HKU\\', 'HKU:\' -replace '^HKEY_LOCAL_MACHINE\\', 'HKLM:\' `
           -replace '^HKEY_CURRENT_USER\\', 'HKCU:\' -replace '^HKEY_USERS\\', 'HKU:\')
}

# --- Cross-reference ---------------------------------------------------------

foreach ($tool in $tools) {

    $indicatorFiles = @()
    if ($tool.Details -and $tool.Details.InstallationPaths) {
        $indicatorFiles = $tool.Details.InstallationPaths | Where-Object { $_ }
    }
    $indicatorBaseNames = $indicatorFiles | ForEach-Object {
        try { [System.IO.Path]::GetFileNameWithoutExtension($_) } catch { $null }
    } | Where-Object { $_ } | Select-Object -Unique

    # 1. Process name/path match
    if ($indicatorFiles.Count -gt 0) {
        foreach ($p in $procs) {
            $procFile = if ($p.Path) { Split-Path $p.Path -Leaf } else { "$($p.Name).exe" }
            if ($indicatorFiles -icontains $procFile -or $indicatorBaseNames -icontains $p.Name) {
                Add-Finding $tool.Name $tool.Category 'Process' $p.Name "PID $($p.Id) - $($p.Path)" -RemoveTarget $p.Id
            }
        }
    }

    # 2. Service match (by binary path)
    if ($indicatorFiles.Count -gt 0) {
        foreach ($svc in $services) {
            if (-not $svc.PathName) { continue }
            $svcExe = try {
                Split-Path (($svc.PathName -replace '^"','' -split '"')[0]) -Leaf
            } catch { $null }
            if ($svcExe -and $indicatorFiles -icontains $svcExe) {
                Add-Finding $tool.Name $tool.Category 'Service' $svc.Name $svc.PathName -RemoveTarget $svc.Name
            }
        }
    }

    # 3. Installed program match (by display name containing the tool name)
    if ($tool.Name) {
        foreach ($prog in $installedPrograms) {
            if ($prog.DisplayName -match [regex]::Escape($tool.Name)) {
                Add-Finding $tool.Name $tool.Category 'InstalledProgram' $prog.DisplayName $prog.InstallLocation -RemoveTarget $prog.UninstallString
            }
        }
    }

    # 4. Known registry artifacts
    if ($tool.Artifacts -and $tool.Artifacts.Registry) {
        foreach ($reg in $tool.Artifacts.Registry) {
            if (-not $reg.Path) { continue }
            $psPath = Convert-RegPathToPSPath $reg.Path
            if (Test-Path $psPath -ErrorAction SilentlyContinue) {
                Add-Finding $tool.Name $tool.Category 'RegistryArtifact' $reg.Path $reg.Description -RemoveTarget $psPath
            }
        }
    }

    # 5. Known disk artifacts
    if ($tool.Artifacts -and $tool.Artifacts.Disk) {
        foreach ($disk in $tool.Artifacts.Disk) {
            if (-not $disk.File) { continue }
            $expanded = [Environment]::ExpandEnvironmentVariables($disk.File)
            if (Test-Path $expanded -ErrorAction SilentlyContinue) {
                Add-Finding $tool.Name $tool.Category 'DiskArtifact' $expanded $disk.Description -RemoveTarget $expanded
            }
        }
    }

    # 6. Optional filesystem sweep for indicator filenames
    if ($ScanFilesystem -and $indicatorFiles.Count -gt 0) {
        $roots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData,
                   "$env:LOCALAPPDATA", "$env:APPDATA") | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique
        foreach ($root in $roots) {
            foreach ($fname in $indicatorFiles) {
                Get-ChildItem -Path $root -Filter $fname -Recurse -File -ErrorAction SilentlyContinue -Force |
                    ForEach-Object {
                        Add-Finding $tool.Name $tool.Category 'FilesystemMatch' $fname $_.FullName -RemoveTarget $_.FullName
                    }
            }
        }
    }
}

# --- Output -------------------------------------------------------------

if ($findings.Count -eq 0) {
    Write-Host "No matches against the LOLRMM catalog." -ForegroundColor Green
}
else {
    Write-Host "`nFound $($findings.Count) potential match(es):`n" -ForegroundColor Yellow
    $findings | Sort-Object Category, Tool | Format-Table Tool, Category, MatchType, MatchedOn, Detail -AutoSize
}

if ($OutputCsv) {
    $findings | Export-Csv -Path $OutputCsv -NoTypeInformation
    Write-Host "Findings exported to $OutputCsv"
}

# --- Removal (opt-in) ---------------------------------------------------

if ($Remove -and $findings.Count -gt 0) {
    Write-Host "`n--- Removal (confirm each entry individually) ---`n" -ForegroundColor Yellow
    foreach ($f in ($findings | Sort-Object Category, Tool)) {
        Write-Host "[$($f.Category)] $($f.Tool) - $($f.MatchType): $($f.MatchedOn)" -ForegroundColor Cyan
        Write-Host "  Detail: $($f.Detail)"
        if (-not $f.RemoveTarget) {
            Write-Host "  No removal target captured for this entry - skipping.`n" -ForegroundColor DarkGray
            continue
        }
        $answer = Read-Host "  Remove this? [y/N]"
        if ($answer -match '^[Yy]') {
            try {
                Invoke-Removal -Finding $f
                Write-Host "  Removed.`n" -ForegroundColor Green
            }
            catch {
                Write-Host "  Failed to remove: $_`n" -ForegroundColor Red
            }
        }
        else {
            Write-Host "  Skipped.`n" -ForegroundColor DarkGray
        }
    }
}
}
finally {
    $ErrorActionPreference = $prevErrorActionPreference
}
