<# Sign one file using a connected SimplySign certificate (also Inno's callback). #>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Path,
    [string]$Thumbprint = $env:CERTUM_CERT_SHA1,
    [switch]$VerifyOnly
)
$ErrorActionPreference = 'Stop'
try {
    . "$PSScriptRoot\windows-signing.ps1"
    if ($VerifyOnly) { Assert-KeyMelierSignature $Path $Thumbprint }
    else { Add-KeyMelierSignature $Path $Thumbprint }
} catch {
    Write-Error $_ -ErrorAction Continue
    exit 1
}
