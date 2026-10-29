$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/../tools/install-vc-runtime.ps1"

# Harmless bytes only: no downloaded installer or machine runtime is changed.
$work = Join-Path ([IO.Path]::GetTempPath()) ('km-runtime-' + [guid]::NewGuid())
New-Item $work -ItemType Directory | Out-Null
$path = Join-Path $work 'vc_redist.x64.exe'
[IO.File]::WriteAllBytes($path, [byte[]](1, 2, 3))
$script:Calls = 0
$script:ExitCode = 0
$script:Status = 'Valid'
$script:Publisher = 'Microsoft Corporation'
$script:Metadata = [pscustomobject]@{
    ProductName = 'Microsoft Visual C++ v14 Redistributable (x64) - 14.50.0.0'
    FileMajorPart = 14; FileMinorPart = 50; FileBuildPart = 0; FilePrivatePart = 0
}
function Get-AuthenticodeSignature { param($LiteralPath)
    $certificate = [pscustomobject]@{}
    $certificate | Add-Member ScriptMethod GetNameInfo { param($Kind, $Issuer) $script:Publisher }
    [pscustomobject]@{Status = $script:Status; SignerCertificate = $certificate}
}
function Get-VCRuntimeMetadata { param($Path) $script:Metadata }
function Start-Process { param($FilePath, $ArgumentList, [switch]$Wait, [switch]$PassThru)
    if (-not $Wait -or -not $PassThru -or ($ArgumentList -join ' ') -ne '/install /norestart') {
        throw 'Microsoft setup must be interactive, waited for, and must not reboot Windows.'
    }
    $script:Calls++
    [pscustomobject]@{ExitCode = $script:ExitCode}
}
function MustReject {
    $before = $script:Calls
    $rejected = $false
    try { Install-VerifiedVCRuntime $path ([version]'14.44.35211.0') | Out-Null }
    catch { $rejected = $true }
    if (-not $rejected -or $script:Calls -ne $before) { throw 'Untrusted/unsupported runtime was executed.' }
}
try {
    foreach ($code in @(0, 1602, 1638, 3010, 1641, 5100)) {
        $script:ExitCode = $code
        if ((Install-VerifiedVCRuntime $path ([version]'14.44.35211.0')) -ne $code) {
            throw 'Child installer result was not returned to KeyMelier Setup.'
        }
    }
    foreach ($status in @('NotSigned', 'HashMismatch', 'NotTrusted', 'UnknownError')) {
        $script:Status = $status
        MustReject
    }
    $script:Status = 'Valid'
    $script:Publisher = 'Another publisher'
    MustReject
    $script:Publisher = 'Microsoft Corporation'
    $script:Metadata.ProductName = 'Microsoft Windows'
    MustReject
    $script:Metadata.ProductName = 'Microsoft Visual C++ Redistributable (x86)'
    MustReject
    $script:Metadata.ProductName = 'Microsoft Visual C++ Redistributable (x64)'
    $script:Metadata.FileMinorPart = 43
    MustReject
    $script:Metadata.FileMinorPart = 50
    [IO.File]::WriteAllBytes($path, [byte[]]@())
    MustReject
    Write-Host 'VC runtime: signature, publisher, architecture, minimum version and installer result checks passed.'
} finally {
    Remove-Item $work -Recurse -Force
}
