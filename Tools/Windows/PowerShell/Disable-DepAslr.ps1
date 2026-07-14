# Disable-DepAslr.ps1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

bcdedit /set nx OptOut | Out-Null

if (Get-Command Set-ProcessMitigation -ErrorAction SilentlyContinue) {
    Set-ProcessMitigation -System -Disable ForceRelocateImages, BottomUp | Out-Null
}

Write-Host "Done. Reboot required."