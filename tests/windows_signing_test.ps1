# Native integration test on a disposable runner. No Certum account or release secrets.
# Uses a one-day test key, trusted only in this runner, and the public RFC3161 service.
$ErrorActionPreference = 'Stop'
if ($env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:RUNNER_OS -ne 'Windows') {
    throw 'Run this integration test only on a disposable GitHub-hosted Windows runner.'
}
$root = Split-Path $PSScriptRoot -Parent
. "$root\tools\windows-signing.ps1"
$work = Join-Path $env:RUNNER_TEMP ('keymelier-signing-test-' + [guid]::NewGuid())
New-Item $work -ItemType Directory | Out-Null
$created = @()
$checks = [System.Collections.Generic.List[string]]::new()
$install = Join-Path $work 'installed'
# CurrentUser\Root can open an interactive trust dialog. This disposable runner
# is elevated; its machine store permits a noninteractive, finally-cleaned test.
$store = [System.Security.Cryptography.X509Certificates.X509Store]::new('Root', 'LocalMachine')
function Expect-Rejection([string]$Name, [scriptblock]$Action) {
    $rejected = $false
    try { & $Action } catch { $rejected = $true }
    if (-not $rejected) { throw "Accepted unsafe input: $Name" }
    $checks.Add("Rejected: $Name")
}
try {
    if (Test-Path "$root\dist\KeyMelier") { throw 'Test needs a clean checkout without a built application.' }
    New-Item "$root\dist\KeyMelier" -ItemType Directory -Force | Out-Null
    $source = Join-Path $work 'Probe.cs'
    '[assembly:System.Reflection.AssemblyFileVersion("1.8.6.0")] class Probe { static void Main() {} }' |
        Set-Content $source
    $exe = "$root\dist\KeyMelier\KeyMelier.exe"
    & "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /nologo /target:winexe "/out:$exe" $source
    if ($LASTEXITCODE -ne 0) { throw 'Probe compilation failed.' }
    $unsigned = Join-Path $work 'unsigned.exe'
    Copy-Item $exe $unsigned
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=KeyMelier CI TEST ONLY' `
        -CertStoreLocation Cert:\CurrentUser\My -KeyExportPolicy NonExportable -HashAlgorithm SHA256 `
        -NotAfter (Get-Date).AddDays(1)
    $created += $cert
    $env:CERTUM_CERT_SHA1 = $cert.Thumbprint
    Write-Host 'Trust the test certificate on this disposable runner.'
    $store.Open('ReadWrite')
    $store.Add($cert)
    $checks.Add('Created temporary non-exportable test certificate')
    Expect-Rejection 'missing certificate thumbprint' { Get-KeyMelierSigningCertificate '' }
    Expect-Rejection 'unknown certificate' { Get-KeyMelierSigningCertificate ('0' * 40) }
    Expect-Rejection 'unsigned executable' { Assert-KeyMelierSignature $unsigned $cert.Thumbprint }
    $noTimestamp = Join-Path $work 'no-timestamp.exe'
    Copy-Item $unsigned $noTimestamp
    $null = Set-AuthenticodeSignature -FilePath $noTimestamp -Certificate $cert -HashAlgorithm SHA256
    Expect-Rejection 'signature without timestamp' { Assert-KeyMelierSignature $noTimestamp $cert.Thumbprint }

    $wrongEku = New-SelfSignedCertificate -Type SSLServerAuthentication -Subject 'CN=KeyMelier CI wrong EKU' `
        -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddDays(1)
    $created += $wrongEku
    Expect-Rejection 'certificate without code-signing EKU' { Get-KeyMelierSigningCertificate $wrongEku.Thumbprint }
    $expired = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=KeyMelier CI expired' `
        -CertStoreLocation Cert:\CurrentUser\My -NotBefore (Get-Date).AddDays(-2) -NotAfter (Get-Date).AddDays(-1)
    $created += $expired
    Expect-Rejection 'expired signing certificate' { Get-KeyMelierSigningCertificate $expired.Thumbprint }

    Write-Host 'Sign the app probe and verify its timestamp.'
    & "$root\tools\sign-windows.ps1" -Path $exe
    if (-not $?) { throw 'Signing the probe failed.' }
    $checks.Add('Signed app with SHA256 and verified trusted RFC3161 timestamp')
    Expect-Rejection 'wrong signer' { Assert-KeyMelierSignature $exe $wrongEku.Thumbprint }
    $tampered = Join-Path $work 'tampered.exe'
    $bytes = [IO.File]::ReadAllBytes($exe)
    # DOS stub is covered by the Authenticode digest; leave PE parsing intact.
    $bytes[80] = $bytes[80] -bxor 1
    [IO.File]::WriteAllBytes($tampered, $bytes)
    Expect-Rejection 'modified signed executable' { Assert-KeyMelierSignature $tampered $cert.Thumbprint }

    Write-Host 'Build signed setup and uninstaller.'
    New-Item "$root\build" -ItemType Directory -Force | Out-Null
    # The probe has no third-party payload. The real build generates its full
    # notices before calling the same installer builder.
    Copy-Item "$root\LICENSE" "$root\build\THIRD_PARTY_LICENSES.txt"
    & "$root\tools\build-windows-installer.ps1" -AppVersion 1.8.6 -Signed
    $checks.Add('Built and verified signed setup and embedded uninstaller')
    $setup = "$root\dist\KeyMelier-Windows-Setup.exe"
    Write-Host 'Install the test package.'
    $p = Start-Process $setup -ArgumentList @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', "/DIR=`"$install`"") -PassThru
    if (-not $p.WaitForExit(120000)) { $p.Kill(); throw 'Installer timed out.' }
    if ($p.ExitCode -ne 0) { throw "Installer test failed (exit $($p.ExitCode))." }
    Assert-KeyMelierSignature "$install\KeyMelier.exe" $cert.Thumbprint
    Assert-KeyMelierSignature "$install\unins000.exe" $cert.Thumbprint
    $checks.Add('Installed app and uninstaller retain expected signer and timestamp')
    Write-Host 'Uninstall the test package.'
    $p = Start-Process "$install\unins000.exe" -ArgumentList @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART') -PassThru
    if (-not $p.WaitForExit(120000)) { $p.Kill(); throw 'Uninstaller timed out.' }
    if ($p.ExitCode -ne 0) { throw 'Uninstall test failed.' }
    $deadline = (Get-Date).AddSeconds(30)
    while ((Test-Path "$install\KeyMelier.exe") -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 1 }
    if (Test-Path "$install\KeyMelier.exe") { throw 'Uninstaller did not remove the application.' }
    $checks.Add('Signed uninstaller completed successfully')

    # The normal unsigned development installer must also remain buildable.
    Copy-Item $unsigned $exe -Force
    & "$root\tools\build-windows-installer.ps1" -AppVersion 1.8.6
    if ((Get-AuthenticodeSignature -LiteralPath $setup).Status -ne 'NotSigned') { throw 'Unsigned mode produced a signed installer.' }
    $checks.Add('Unsigned development installer builds without a signing session')
} finally {
    foreach ($item in $created) {
        $store.Remove($item)
        Remove-Item "Cert:\CurrentUser\My\$($item.Thumbprint)" -DeleteKey -ErrorAction SilentlyContinue
    }
    $store.Close()
    Remove-Item Env:\CERTUM_CERT_SHA1 -ErrorAction SilentlyContinue
    if (Test-Path $work) { Remove-Item $work -Recurse -Force }
}
$checks | ForEach-Object { Write-Host "PASS: $_" }
if ($env:GITHUB_STEP_SUMMARY) {
    @('## Windows signing test', '', 'Temporary test identity only; no production Certum login tested.', '') +
        @($checks | ForEach-Object { "- $_" }) | Add-Content $env:GITHUB_STEP_SUMMARY
}
