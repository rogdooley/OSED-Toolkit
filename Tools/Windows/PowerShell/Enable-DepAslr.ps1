# Enable-DepAslr.ps1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Write-Host "Enabling DEP at boot..."
bcdedit /set nx AlwaysOn | Out-Null

Write-Host "Enabling system ASLR mitigations..."
if (Get-Command Set-ProcessMitigation -ErrorAction SilentlyContinue) {
    Set-ProcessMitigation -System -Enable ForceRelocateImages, BottomUp | Out-Null
} else {
    throw "Set-ProcessMitigation is not available on this system."
}

Write-Host "Done. Reboot required."