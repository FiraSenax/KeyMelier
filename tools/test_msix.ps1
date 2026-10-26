# Windows-only installed-package test. Imports only the supplied PUBLIC test
# certificate, refuses an existing test install, and cleans up what it creates.
[CmdletBinding()]
param([string]$PackageDir = 'dist\msix-test')
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repo = Split-Path $PSScriptRoot -Parent
Set-Location $repo
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal $identity
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this test in an elevated Windows PowerShell session.'
}
$folder = (Resolve-Path $PackageDir).Path
$metadata = Get-Content (Join-Path $folder 'TEST-PACKAGE.json') -Raw | ConvertFrom-Json
$name = 'KeyMelier.LocalTest'
if ($metadata.identity -ne $name -or $metadata.purpose -ne 'local-test-only' -or @($metadata.packages).Count -ne 2) {
    throw 'Not a KeyMelier local test package set.'
}
if (Get-AppxPackage -Name $name) { throw 'An existing local test package is installed; left untouched.' }
foreach ($entry in $metadata.files.PSObject.Properties) {
    if ([IO.Path]::GetFileName($entry.Name) -ne $entry.Name) { throw 'Invalid evidence filename.' }
    if ((Get-FileHash (Join-Path $folder $entry.Name) -Algorithm SHA256).Hash -ne $entry.Value) {
        throw "Checksum mismatch: $($entry.Name)"
    }
}
$cert = [Security.Cryptography.X509Certificates.X509Certificate2]::new((Join-Path $folder 'KeyMelier-Test.cer'))
if ($cert.Subject -ne 'CN=KeyMelier Local Test' -or $cert.Thumbprint -ne $metadata.certificate_thumbprint) {
    throw 'Unexpected test certificate.'
}
$trustPath = "Cert:\LocalMachine\TrustedPeople\$($cert.Thumbprint)"
$addedTrust = !(Test-Path $trustPath)
$installed = $false
$failure = $null
$checks = [System.Collections.Generic.List[string]]::new()
$previousRequire = $env:SMOKE_REQUIRE_MSIX
$previousArtifacts = $env:SMOKE_ARTIFACTS
try {
    if ($addedTrust) { Import-Certificate -FilePath (Join-Path $folder 'KeyMelier-Test.cer') -CertStoreLocation 'Cert:\LocalMachine\TrustedPeople' | Out-Null }
    $marker = $null
    $family = $null
    foreach ($entry in $metadata.packages) {
        $file = Join-Path $folder $entry.file
        $sig = Get-AuthenticodeSignature $file
        if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Thumbprint -ne $cert.Thumbprint) { throw 'Invalid MSIX test signature.' }
        Add-AppxPackage -Path $file
        $installed = $true
        $package = Get-AppxPackage -Name $name
        if (!$package -or [string]$package.Version -ne $entry.version) { throw 'Installed package version does not match.' }
        if ($family -and $family -ne $package.PackageFamilyName) { throw 'Upgrade changed package identity.' }
        $family = $package.PackageFamilyName
        if ($marker) {
            if (!(Test-Path $marker) -or (Get-Content $marker -Raw) -ne 'synthetic-upgrade-marker') { throw 'Package LocalState did not survive the upgrade.' }
            $checks.Add('package LocalState marker preserved across upgrade')
        }
        $env:SMOKE_REQUIRE_MSIX = '1'
        $env:SMOKE_ARTIFACTS = Join-Path $repo "build\msix-smoke-$($entry.version)"
        & python tools/smoke_packaged.py (Join-Path $package.InstallLocation 'KeyMelier.exe')
        if ($LASTEXITCODE -ne 0) { throw "Installed MSIX start test failed for $($entry.version)." }
        $checks.Add("installed $($entry.version): GUI, package identity, update policy, native credentials and isolated data")
        if (!$marker) {
            $localState = Join-Path $env:LOCALAPPDATA "Packages\$family\LocalState"
            New-Item -ItemType Directory -Force $localState | Out-Null
            $marker = Join-Path $localState ('keymelier-upgrade-test-' + [guid]::NewGuid().ToString('N'))
            [IO.File]::WriteAllText($marker, 'synthetic-upgrade-marker')
        }
    }
} catch { $failure = $_ } finally {
    $env:SMOKE_REQUIRE_MSIX = $previousRequire
    $env:SMOKE_ARTIFACTS = $previousArtifacts
    try {
        if ($installed) {
            Get-AppxPackage -Name $name | Remove-AppxPackage
            if (Get-AppxPackage -Name $name) { throw 'Test package removal failed.' }
            $checks.Add('test package uninstalled')
        }
    } catch { if (!$failure) { $failure = $_ } }
    try {
        if ($addedTrust -and (Test-Path $trustPath)) {
            Remove-Item $trustPath
            $checks.Add('temporary certificate trust removed')
        }
    } catch { if (!$failure) { $failure = $_ } }
}
[ordered]@{ passed = !$failure; checks = @($checks); hardware_tested = $false; store_submitted = $false } |
    ConvertTo-Json -Depth 5 | Set-Content (Join-Path $folder 'INSTALL-TEST.json') -Encoding UTF8
if ($failure) { throw $failure }
Write-Host 'MSIX install, upgrade, start and cleanup tests passed. No Store submission.'
