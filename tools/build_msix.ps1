# Build two local-test MSIX versions from the normal PyInstaller Windows bundle.
# No Store identity, Store API, production signing credentials or private-key export.
[CmdletBinding()]
param(
    [string]$BundleDir = "dist\KeyMelier",
    [string]$OutputDir = "dist\msix-test"
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repo = Split-Path $PSScriptRoot -Parent
Set-Location $repo
$bundle = (Resolve-Path $BundleDir).Path
$exe = Join-Path $bundle 'KeyMelier.exe'
if (!(Test-Path $exe)) { throw 'Build dist/KeyMelier with PyInstaller first.' }
if ((Test-Path $OutputDir) -and @(Get-ChildItem $OutputDir -Force).Count) {
    throw 'Output directory is not empty; choose a new directory.'
}
$version = (& python -c 'from keymelier_core.version import __version__; print(__version__)').Trim()
if ($LASTEXITCODE -ne 0 -or $version -notmatch '^\d+\.\d+\.\d+$') { throw 'Cannot read application version.' }
if ((Get-Item $exe).VersionInfo.ProductVersion -ne $version) { throw 'Executable version differs from source version.' }
$sdkRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
$sdk = Get-ChildItem $sdkRoot -Directory | Where-Object {
    $_.Name -match '^10\.0\.\d+\.\d+$' -and (Test-Path (Join-Path $_.FullName 'x64\makeappx.exe')) -and
    (Test-Path (Join-Path $_.FullName 'x64\signtool.exe'))
} | Sort-Object { [version]$_.Name } -Descending | Select-Object -First 1
if (!$sdk) { throw 'Install the Windows SDK (MakeAppx and SignTool).' }
$makeappx = Join-Path $sdk.FullName 'x64\makeappx.exe'
$signtool = Join-Path $sdk.FullName 'x64\signtool.exe'
$out = (New-Item -ItemType Directory -Force $OutputDir).FullName
$stage = Join-Path ([System.IO.Path]::GetTempPath()) ('keymelier-msix-' + [guid]::NewGuid().ToString('N'))
$cert = $null
try {
    New-Item -ItemType Directory $stage | Out-Null
    Copy-Item (Join-Path $bundle '*') $stage -Recurse
    $assets = New-Item -ItemType Directory (Join-Path $stage 'Assets')
    Add-Type -AssemblyName System.Drawing
    $image = [System.Drawing.Image]::FromFile((Join-Path $repo 'static\icon.png'))
    try {
        foreach ($logo in @(@('StoreLogo', 50), @('Square44x44Logo', 44), @('Square150x150Logo', 150))) {
            $bitmap = New-Object System.Drawing.Bitmap ([int]$logo[1]), ([int]$logo[1])
            $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
            try {
                $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
                $graphics.DrawImage($image, 0, 0, $bitmap.Width, $bitmap.Height)
                $bitmap.Save((Join-Path $assets.FullName ($logo[0] + '.png')), [System.Drawing.Imaging.ImageFormat]::Png)
            } finally { $graphics.Dispose(); $bitmap.Dispose() }
        }
    } finally { $image.Dispose() }
    $cert = New-SelfSignedCertificate -Type Custom -Subject 'CN=KeyMelier Local Test' `
        -KeyUsage DigitalSignature -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 `
        -KeyExportPolicy NonExportable -CertStoreLocation 'Cert:\CurrentUser\My' `
        -NotAfter (Get-Date).AddDays(14) -FriendlyName 'KeyMelier temporary MSIX test signer' `
        -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3', '2.5.29.19={text}')
    Export-Certificate -Cert $cert -FilePath (Join-Path $out 'KeyMelier-Test.cer') | Out-Null
    $template = Get-Content (Join-Path $repo 'packaging\windows-msix\AppxManifest.xml') -Raw
    $packages = @()
    foreach ($revision in 0, 1) {
        $packageVersion = "$version.$revision"
        [void][version]::Parse($packageVersion)
        $manifest = $template.Replace('@@VERSION@@', $packageVersion)
        [System.IO.File]::WriteAllText((Join-Path $stage 'AppxManifest.xml'), $manifest, [System.Text.UTF8Encoding]::new($false))
        $package = Join-Path $out "KeyMelier-Test-$packageVersion-x64.msix"
        & $makeappx pack /d $stage /p $package /o
        if ($LASTEXITCODE -ne 0) { throw "MakeAppx validation/packaging failed for $packageVersion." }
        & $signtool sign /fd SHA256 /sha1 $cert.Thumbprint /s My $package
        if ($LASTEXITCODE -ne 0) { throw 'Test signing failed.' }
        $packages += [ordered]@{ file = [System.IO.Path]::GetFileName($package); version = $packageVersion }
    }
    Copy-Item (Join-Path $repo 'packaging\windows-msix\TESTING.md') (Join-Path $out 'TESTING.md')
    $evidence = [ordered]@{
        purpose = 'local-test-only'; identity = 'KeyMelier.LocalTest'; publisher = $cert.Subject
        certificate_thumbprint = $cert.Thumbprint; certificate_expires = $cert.NotAfter.ToUniversalTime().ToString('o')
        version = $version; packages = $packages
        build = (Get-Content (Join-Path $bundle '_internal\data\build.json') -Raw | ConvertFrom-Json)
        files = @{}
    }
    foreach ($file in Get-ChildItem $out -File) {
        $evidence.files[$file.Name] = (Get-FileHash $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $evidence | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $out 'TEST-PACKAGE.json') -Encoding UTF8
    Write-Host "Test packages: $out"
    Write-Host "Public test certificate: $($cert.Thumbprint); expires $($cert.NotAfter.ToUniversalTime().ToString('o'))"
} finally {
    if ($cert) { Remove-Item "Cert:\CurrentUser\My\$($cert.Thumbprint)" -DeleteKey -ErrorAction Stop }
    if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
}
