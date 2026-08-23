<#
.SYNOPSIS
    Installs the ABK FIDO virtual HID driver from a test-signed package.

.DESCRIPTION
    Trusts the package's self-signed certificate, creates the root-enumerated
    devnode the driver binds to, and reports whether the control device came up.

    Because the package is self-signed, Windows will only load it while test
    signing is on:

        bcdedit /set testsigning on

    which needs Secure Boot disabled in firmware and, on a BitLocker-protected
    system, the recovery key at the next boot (suspend BitLocker first). This
    script checks both and tells you what is missing rather than changing boot
    configuration behind your back.

.PARAMETER PackageDir
    Directory holding abkfidovhid.sys/.inf/.cat/.cer and abkvhidctl.exe.
    Defaults to the directory this script sits in.

.PARAMETER EnableTestSigning
    Also run `bcdedit /set testsigning on`. Takes effect after a reboot.

.EXAMPLE
    .\Install-AbkFidoVhid.ps1 -EnableTestSigning
#>
[CmdletBinding()]
param(
    [string]$PackageDir = $PSScriptRoot,
    [switch]$EnableTestSigning
)

$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'run this from an elevated PowerShell prompt'
}

$PackageDir = (Resolve-Path -LiteralPath $PackageDir).Path
function Get-PackageFile {
    param([Parameter(Mandatory = $true)][string]$Name)

    $path = Join-Path $PackageDir $Name
    if (-not (Test-Path -LiteralPath $path)) { throw "$Name not found in $PackageDir" }
    return $path
}

$inf = Get-PackageFile 'abkfidovhid.inf'
$ctl = Get-PackageFile 'abkvhidctl.exe'
$cer = Get-PackageFile 'abkfidovhid.cer'
Get-PackageFile 'abkfidovhid.sys' | Out-Null
if (-not (Test-Path -LiteralPath (Join-Path $PackageDir 'abkfidovhid.cat'))) {
    Write-Warning 'the package has no catalog; Windows will report an unverified publisher'
}

# Root makes the signature chain valid, TrustedPublisher stops the install
# prompt. Both are machine-wide, which is why this needs elevation.
foreach ($store in 'Root', 'TrustedPublisher') {
    Import-Certificate -FilePath $cer -CertStoreLocation "Cert:\LocalMachine\$store" | Out-Null
    Write-Host "trusted the package certificate in LocalMachine\$store"
}

$secureBoot = $null
try { $secureBoot = Confirm-SecureBootUEFI } catch { }
if ($secureBoot -eq $true) {
    Write-Warning 'Secure Boot is on: test signing stays off until you disable it in firmware, and the driver will not load'
}

$testSigning = (& bcdedit /enum '{current}' | Select-String -Pattern 'testsigning\s+Yes' -Quiet) -eq $true
if ($testSigning) {
    Write-Host 'test signing: on'
} elseif ($EnableTestSigning) {
    & bcdedit /set testsigning on
    if ($LASTEXITCODE -ne 0) { throw "bcdedit failed ($LASTEXITCODE)" }
    Write-Warning 'test signing enabled; reboot, then run this script again to finish the install'
} else {
    Write-Warning 'test signing is off, so the driver will not load. Suspend BitLocker if it is on, run `bcdedit /set testsigning on` (or pass -EnableTestSigning), reboot, then run this script again.'
}

& $ctl install $inf
if ($LASTEXITCODE -ne 0) {
    # With test signing off this is the expected outcome, and saying so is more
    # use than a stack trace: the devnode and the staged package survive, so a
    # reboot with test signing on finishes the job.
    if (-not $testSigning) {
        Write-Warning 'the install failed, most likely because test signing is not in effect yet; turn it on, reboot, and run this script again'
        exit $LASTEXITCODE
    }
    throw "abkvhidctl install failed ($LASTEXITCODE)"
}

& $ctl status
if ($LASTEXITCODE -ne 0) {
    Write-Warning 'the devnode exists but the control device is not reachable; see the status output above'
    exit $LASTEXITCODE
}

Write-Host 'the agent can now open \\.\ABKFidoVhid - run it elevated'

