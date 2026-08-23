<#
.SYNOPSIS
    Removes the ABK FIDO virtual HID devnode, and optionally the driver package
    and the certificate that was trusted for it.

.PARAMETER PackageDir
    Directory holding abkvhidctl.exe. Defaults to this script's directory.

.PARAMETER RemoveDriverPackage
    Also delete the staged package from the driver store (pnputil /delete-driver).

.PARAMETER RemoveCertificate
    Also delete the package's code-signing certificate from LocalMachine Root
    and TrustedPublisher.

.EXAMPLE
    .\Uninstall-AbkFidoVhid.ps1 -RemoveDriverPackage -RemoveCertificate
#>
[CmdletBinding()]
param(
    [string]$PackageDir = $PSScriptRoot,
    [switch]$RemoveDriverPackage,
    [switch]$RemoveCertificate
)

$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'run this from an elevated PowerShell prompt'
}

$PackageDir = (Resolve-Path -LiteralPath $PackageDir).Path
$ctl = Join-Path $PackageDir 'abkvhidctl.exe'
if (-not (Test-Path -LiteralPath $ctl)) { throw "abkvhidctl.exe not found in $PackageDir" }

& $ctl remove
if ($LASTEXITCODE -ne 0) { throw "abkvhidctl remove failed ($LASTEXITCODE)" }

if ($RemoveDriverPackage) {
    # The store renames the package to oemN.inf, so find it by original name.
    # Get-WindowsDriver reports that mapping in locale-independent properties;
    # parsing pnputil's text output would not survive a non-English Windows.
    $published = @()
    try {
        $published = @(Get-WindowsDriver -Online |
            Where-Object { $_.OriginalFileName -like '*abkfidovhid.inf' } |
            ForEach-Object { $_.Driver })
    } catch {
        Write-Warning "could not enumerate the driver store ($($_.Exception.Message)); use ``pnputil /enum-drivers`` and ``pnputil /delete-driver`` by hand"
    }

    if ($published.Count -eq 0) {
        Write-Host 'no abkfidovhid package is staged in the driver store'
    }
    foreach ($name in $published) {
        & pnputil /delete-driver $name /uninstall /force
        if ($LASTEXITCODE -eq 0) {
            Write-Host "deleted $name from the driver store"
        } else {
            Write-Warning "pnputil /delete-driver $name failed ($LASTEXITCODE)"
        }
    }
}

if ($RemoveCertificate) {
    $removed = 0
    foreach ($store in 'Root', 'TrustedPublisher') {
        Get-ChildItem "Cert:\LocalMachine\$store" |
            Where-Object { $_.Subject -like '*ABK FIDO Virtual HID*' } |
            ForEach-Object {
                Remove-Item -LiteralPath $_.PSPath -Force
                Write-Host "removed $($_.Thumbprint) from LocalMachine\$store"
                $removed++
            }
    }
    if ($removed -eq 0) { Write-Host 'no ABK FIDO signing certificate was trusted' }
}

Write-Host 'done'

