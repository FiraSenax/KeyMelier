[CmdletBinding()]
param(
    [string]$RuntimePath,
    [version]$MinimumVersion = '14.44.35211.0'
)
$ErrorActionPreference = 'Stop'

function Get-VCRuntimeMetadata([string]$Path) {
    [Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
}

function Install-VerifiedVCRuntime([string]$Path, [version]$Minimum) {
    $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $item.Length -le 0 -or $item.Length -gt 100MB) {
        throw 'Invalid runtime download.'
    }
    # Keep the file locked against writes/deletion from verification through
    # execution. Never execute solely on the basis of a URL or file name.
    $locked = [IO.File]::Open($item.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $signature = Get-AuthenticodeSignature -LiteralPath $item.FullName
        if ($signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate -or
            $signature.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) -cne 'Microsoft Corporation') {
            throw 'The runtime does not have a valid Microsoft signature.'
        }
        $metadata = Get-VCRuntimeMetadata $item.FullName
        $version = [version]::new($metadata.FileMajorPart, $metadata.FileMinorPart,
                                  $metadata.FileBuildPart, $metadata.FilePrivatePart)
        if ($version -lt $Minimum -or $metadata.ProductName -notmatch '^Microsoft Visual C\+\+.*\(x64\)') {
            throw 'The signed file is not a supported x64 Visual C++ runtime.'
        }
        # Full Microsoft UI lets the user review its terms and cancel. Never
        # restart Windows from the child installer; return its status to Inno.
        $process = Start-Process -FilePath $item.FullName -ArgumentList '/install', '/norestart' -Wait -PassThru
        return $process.ExitCode
    } finally {
        $locked.Dispose()
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    try {
        exit (Install-VerifiedVCRuntime -Path $RuntimePath -Minimum $MinimumVersion)
    } catch {
        Write-Error 'The Microsoft runtime could not be verified or installed.' -ErrorAction Continue
        exit 5100
    }
}
