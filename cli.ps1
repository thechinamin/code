#Requires -Version 5.1
<#
CLI launcher for scripts in thechinamin/code.
Run with:
  irm https://raw.githubusercontent.com/thechinamin/code/main/cli.ps1 | iex
#>

$repoRaw = "https://raw.githubusercontent.com/thechinamin/code/main"

$scripts = @(
    @{ Name = "Check-LOLRMM";  Description = "Scan for known RMM/RAT tools (LOLRMM catalog)"; Path = "powershell/Check-LOLRMM.ps1" },
    @{ Name = "Setup-SSH";     Description = "Install/remove OpenSSH Server on Windows";        Path = "powershell/setup-ssh.ps1" },
    @{ Name = "Set-DNS";       Description = "Set/restore encrypted DNS (Quad9/Google) on active adapters"; Path = "powershell/Set-DNS.ps1" }
)

Write-Host "`nAvailable scripts:`n"
for ($i = 0; $i -lt $scripts.Count; $i++) {
    Write-Host ("  [{0}] {1} - {2}" -f ($i + 1), $scripts[$i].Name, $scripts[$i].Description)
}

$choice = Read-Host "`nEnter a number to run"
$index = [int]$choice - 1

if ($index -lt 0 -or $index -ge $scripts.Count) {
    Write-Error "Invalid choice."
    return
}

$selected = $scripts[$index]
$scriptText = Invoke-RestMethod -Uri "$repoRaw/$($selected.Path)"

$paramBlock = [regex]::Match($scriptText, '(?ms)^param\s*\((.*?)^\)')
if ($paramBlock.Success) {
    $paramText = $paramBlock.Groups[1].Value
    $nameMatches = [regex]::Matches($paramText, '\$(\w+)(?:\s*=\s*(''[^'']*''|"[^"]*"|[^,\r\n]+))?')

    $argNames = for ($i = 0; $i -lt $nameMatches.Count; $i++) {
        $m = $nameMatches[$i]
        $name = $m.Groups[1].Value
        $default = $m.Groups[2].Value.Trim().Trim("'", '"')

        # Text between the previous parameter's match and this one holds this
        # parameter's attributes (e.g. [ValidateSet(...)]) - sliced by position
        # rather than regex, since type names like [string[]] have nested
        # brackets that a bracket-matching regex would mishandle.
        $prefixStart = if ($i -eq 0) { 0 } else { $nameMatches[$i - 1].Index + $nameMatches[$i - 1].Length }
        $prefix = $paramText.Substring($prefixStart, $m.Index - $prefixStart)

        $choices = $null
        $validateSet = [regex]::Match($prefix, 'ValidateSet\(([^)]*)\)')
        if ($validateSet.Success) {
            $choices = ([regex]::Matches($validateSet.Groups[1].Value, "'([^']*)'|""([^""]*)""") | ForEach-Object {
                if ($_.Groups[1].Success) { $_.Groups[1].Value } else { $_.Groups[2].Value }
            }) -join '|'
        }

        $label = "-$name"
        if ($choices) { $label += " <$choices>" }
        if ($default) { $label += " (default: $default)" }
        $label
    }
    Write-Host "`nAvailable arguments: $($argNames -join ', ')`n"
}

$argString = Read-Host "Arguments for $($selected.Name) (optional, press Enter to skip)"

$scriptBlock = [scriptblock]::Create($scriptText)

Write-Host "`nRunning $($selected.Name)...`n"
if ($argString) {
    Invoke-Expression "& `$scriptBlock $argString"
} else {
    & $scriptBlock
}
