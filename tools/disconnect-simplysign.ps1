# Disconnect only on a disposable runner; never remove certificates from a user's PC.
$ErrorActionPreference = 'Stop'
if ($env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:RUNNER_OS -ne 'Windows') {
    throw 'SimplySign CI cleanup is only allowed on GitHub-hosted Windows runners.'
}
Get-Process -Name SimplySignDesktop -ErrorAction SilentlyContinue | Stop-Process -Force
if (Get-Process -Name SimplySignDesktop -ErrorAction SilentlyContinue) { throw 'SimplySign is still running.' }
if ($env:CERTUM_CERT_SHA1 -match '^[0-9A-Fa-f]{40}$') {
    $cert = "Cert:\CurrentUser\My\$env:CERTUM_CERT_SHA1"
    if (Test-Path $cert) { Remove-Item $cert -Force }
}
Write-Host 'SimplySign stopped and the selected local certificate reference removed.'
