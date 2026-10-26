# Shared Authenticode checks. No credentials or private-key export is needed here.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-KeyMelierSignTool {
    $sdk = "${env:ProgramFiles(x86)}\Windows Kits\10\bin"
    $tool = Get-ChildItem "$sdk\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
        Sort-Object { [version]$_.Directory.Parent.Name } -Descending | Select-Object -First 1
    if (-not $tool) { throw 'Install the Windows SDK (x64 SignTool is required).' }
    return $tool.FullName
}

function Assert-SigningThumbprint([string]$Thumbprint) {
    if ($Thumbprint -notmatch '^[0-9A-Fa-f]{40}$') {
        throw 'CERTUM_CERT_SHA1 must be the exact 40-character certificate thumbprint.'
    }
}

function Get-KeyMelierSigningCertificate([string]$Thumbprint) {
    Assert-SigningThumbprint $Thumbprint
    $cert = Get-Item "Cert:\CurrentUser\My\$Thumbprint" -ErrorAction Stop
    if (-not $cert.HasPrivateKey) { throw 'The selected certificate has no accessible private key.' }
    $now = Get-Date
    if ($cert.NotBefore -gt $now -or $cert.NotAfter -le $now) { throw 'The signing certificate is not currently valid.' }
    $eku = @($cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' } |
        ForEach-Object { $_.EnhancedKeyUsages } | ForEach-Object { $_.Value })
    if ('1.3.6.1.5.5.7.3.3' -notin $eku) {
        throw 'The selected certificate is not a code-signing certificate.'
    }
    return $cert
}

function Assert-KeyMelierSignature([string]$Path, [string]$Thumbprint) {
    Assert-SigningThumbprint $Thumbprint
    $file = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    $sig = Get-AuthenticodeSignature -LiteralPath $file
    if ($sig.Status -ne 'Valid') { throw "Invalid Authenticode signature on ${file}: $($sig.Status)" }
    if ($sig.SignerCertificate.Thumbprint -ne $Thumbprint) { throw "Unexpected signer on $file" }
    if (-not $sig.TimeStamperCertificate) { throw "Missing trusted timestamp on $file" }
    $tool = Get-KeyMelierSignTool
    # /all validates every embedded signature; /tw warns for a missing timestamp.
    # Treat warnings (exit 2) as failures too.
    & $tool verify /pa /all /tw $file
    if ($LASTEXITCODE -ne 0) { throw "SignTool verification failed on $file (exit $LASTEXITCODE)." }
}

function Add-KeyMelierSignature([string]$Path, [string]$Thumbprint) {
    $null = Get-KeyMelierSigningCertificate $Thumbprint
    $file = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    $tool = Get-KeyMelierSignTool
    # /sha1 selects a certificate; file and RFC3161 timestamp digests use SHA256.
    & $tool sign /s My /sha1 $Thumbprint /fd SHA256 /tr http://time.certum.pl /td SHA256 /d KeyMelier $file
    if ($LASTEXITCODE -ne 0) { throw "Signing failed on $file (exit $LASTEXITCODE)." }
    Assert-KeyMelierSignature $file $Thumbprint
}
