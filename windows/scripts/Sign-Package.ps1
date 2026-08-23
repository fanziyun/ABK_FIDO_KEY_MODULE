<#
.SYNOPSIS
    Packages and test-signs the ABK FIDO virtual HID driver.

.DESCRIPTION
    Collects abkfidovhid.sys / .inf into a single directory, signs the driver
    with a freshly generated self-signed code-signing certificate, builds the
    catalog over the signed files with inf2cat, signs that too, and exports the
    certificate next to them.

    The certificate is created on the machine that runs this script and its
    private key never leaves it. Whoever installs the result has to trust the
    exported .cer and allow self-signed drivers to load - see
    Install-AbkFidoVhid.ps1.

.PARAMETER SearchRoot
    Directory tree to look for the built driver in, e.g. windows\vhid\x64\Release.

.PARAMETER OutDir
    Directory the signed package is written to. Created if missing.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$SearchRoot,
    [Parameter(Mandatory = $true)][string]$OutDir,
    [string]$Subject = 'CN=ABK FIDO Virtual HID Test Signing'
)

$ErrorActionPreference = 'Stop'

function Find-SdkTool {
    param([Parameter(Mandatory = $true)][string]$Name)

    $roots = @(
        (Join-Path $PSScriptRoot '..\vhid\packages'),
        "${env:ProgramFiles(x86)}\Windows Kits\10\bin",
        "$env:ProgramFiles\Windows Kits\10\bin"
    ) | Where-Object { $_ -and (Test-Path $_) }

    foreach ($root in $roots) {
        $hits = @(Get-ChildItem -LiteralPath $root -Filter $Name -Recurse -File -ErrorAction SilentlyContinue)
        if ($hits.Count -eq 0) { continue }
        $x64 = @($hits | Where-Object { $_.FullName -like '*\x64\*' })
        if ($x64.Count -gt 0) { $hits = $x64 }
        return ($hits | Sort-Object FullName -Descending | Select-Object -First 1).FullName
    }
    return $null
}
$sys = Get-ChildItem -LiteralPath $SearchRoot -Filter 'abkfidovhid.sys' -Recurse -File |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $sys) { throw "abkfidovhid.sys not found under $SearchRoot" }

# Prefer the .inf the build stamped next to the driver in the package folder.
$inf = Get-ChildItem -LiteralPath $SearchRoot -Filter 'abkfidovhid.inf' -Recurse -File |
    Sort-Object @{ Expression = { $_.DirectoryName -eq $sys.DirectoryName } }, LastWriteTime -Descending |
    Select-Object -First 1
if (-not $inf) { throw "abkfidovhid.inf not found under $SearchRoot" }

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$OutDir = (Resolve-Path -LiteralPath $OutDir).Path
Copy-Item -LiteralPath $sys.FullName -Destination $OutDir -Force
Copy-Item -LiteralPath $inf.FullName -Destination $OutDir -Force
Write-Host "packaging $($sys.FullName)"

$signtool = Find-SdkTool -Name 'signtool.exe'
if (-not $signtool) { throw 'signtool.exe not found; install the Windows SDK or restore the WDK NuGet packages' }
Write-Host "signtool: $signtool"

$cert = New-SelfSignedCertificate `
    -Type CodeSigningCert `
    -Subject $Subject `
    -CertStoreLocation 'Cert:\CurrentUser\My' `
    -KeyUsage DigitalSignature `
    -KeyLength 2048 `
    -NotAfter (Get-Date).AddYears(3) `
    -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3')
Write-Host "certificate: $($cert.Subject) $($cert.Thumbprint)"
Export-Certificate -Cert $cert -FilePath (Join-Path $OutDir 'abkfidovhid.cer') -Force | Out-Null

function Invoke-SignTool {
    param([Parameter(Mandatory = $true)][string]$File)

    & $signtool sign /v /fd sha256 /sha1 $cert.Thumbprint $File
    if ($LASTEXITCODE -ne 0) { throw "signtool failed on $File ($LASTEXITCODE)" }
}

# Order matters: the catalog hashes the files as they are on disk, so embedding
# the driver's signature has to happen before inf2cat runs, and the catalog is
# signed last. Any build signature the WDK put on the .sys is replaced here, so
# the whole package chains to the one certificate exported above.
Invoke-SignTool -File (Join-Path $OutDir 'abkfidovhid.sys')

$inf2cat = Find-SdkTool -Name 'inf2cat.exe'
if (-not $inf2cat) {
    throw 'inf2cat.exe not found; it ships with the WDK (the Microsoft.Windows.WDK.x64 NuGet package includes it), and without a catalog Windows rejects the package as unsigned'
}
Write-Host "inf2cat: $inf2cat"
& $inf2cat /driver:$OutDir /os:10_x64 /verbose
if ($LASTEXITCODE -ne 0) { throw "inf2cat failed ($LASTEXITCODE)" }

Invoke-SignTool -File (Join-Path $OutDir 'abkfidovhid.cat')

Write-Host "signed package in $OutDir"


