[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$AppVersion,
    [switch]$Signed
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\windows-signing.ps1"
$root = Split-Path $PSScriptRoot -Parent
Push-Location $root
try {
    $args = @("/DAppVersion=$AppVersion")
    if ($Signed) {
        Assert-KeyMelierSignature 'dist\KeyMelier\KeyMelier.exe' $env:CERTUM_CERT_SHA1
        # Do not reuse an uninstaller signed by an old certificate.
        $cache = Join-Path $root 'build\signed-uninstaller'
        if (Test-Path $cache) { Remove-Item $cache -Recurse -Force }
        New-Item $cache -ItemType Directory -Force | Out-Null
        $ps = (Get-Command pwsh.exe -ErrorAction Stop).Source.Replace('$', '$$')
        $script = (Join-Path $PSScriptRoot 'sign-windows.ps1').Replace('$', '$$')
        $command = '$q' + $ps + '$q -NoProfile -NonInteractive -File $q' + $script + '$q -Path $f'
        $args += '/DSignWindows=1', "/Scertum=$command"
    }
    $args += 'packaging\keymelier.iss'
    & "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe" @args
    if ($LASTEXITCODE -ne 0) { throw 'Installer build failed.' }
    if ($Signed) {
        Assert-KeyMelierSignature 'dist\KeyMelier-Windows-Setup.exe' $env:CERTUM_CERT_SHA1
        $uninstallers = @(Get-ChildItem 'build\signed-uninstaller' -File -Filter '*.e32')
        if ($uninstallers.Count -ne 1) { throw 'Expected one signed Inno uninstaller.' }
        Assert-KeyMelierSignature $uninstallers[0].FullName $env:CERTUM_CERT_SHA1
    }
} finally {
    Pop-Location
}
