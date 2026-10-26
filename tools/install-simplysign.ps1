# Only for disposable GitHub-hosted Windows x64 runners; run before loading secrets.
$ErrorActionPreference = 'Stop'
if ($env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:RUNNER_OS -ne 'Windows') {
    throw 'The unattended SimplySign installation requires a disposable GitHub-hosted Windows runner.'
}
$version = '9.4.4.92'
$sha256 = '8ec420fc27798b86078b7bd02fe7152097e1b3005bab51820eaca8e57df84da3'
$url = "https://files.certum.eu/software/SimplySignDesktop/Windows/$version/SimplySignDesktop-$version-64-bit-en.msi"
$msi = Join-Path $env:RUNNER_TEMP 'keymelier-simplysign.msi'
$app = 'C:\Program Files\Certum\SimplySign Desktop\SimplySignDesktop.exe'
if (Test-Path $app) { throw 'Unexpected pre-existing SimplySign installation.' }
try {
    Invoke-WebRequest -Uri $url -OutFile $msi -TimeoutSec 300
    if ((Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash -ne $sha256) {
        throw 'SimplySign installer hash mismatch. Review a new vendor build before updating the pin.'
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $msi
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'Asseco Data Systems') {
        throw 'SimplySign installer does not have a valid Asseco Data Systems signature.'
    }
    $proc = Start-Process msiexec.exe -ArgumentList @('/i', "`"$msi`"", '/qn', '/norestart') -Wait -PassThru
    if ($proc.ExitCode -notin @(0, 3010)) { throw "SimplySign installation failed (exit $($proc.ExitCode))." }
    if (-not (Test-Path $app)) { throw 'SimplySign Desktop was not installed at the expected path.' }
    if ((Get-AuthenticodeSignature -LiteralPath $app).Status -ne 'Valid') {
        throw 'Invalid signature on the installed SimplySign application.'
    }
    Write-Host "Verified SimplySign Desktop $version installed."
} finally {
    if (Test-Path $msi) { Remove-Item $msi -Force }
}
