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
    Copy-Item 'packaging\WINDOWS-README.txt' 'dist\KeyMelier\WINDOWS-README.txt'
    # Inno's text license reader detects UTF-8 by its BOM. Preserve non-ASCII
    # original copyright names on every Windows display language.
    $notices = [IO.File]::ReadAllText((Join-Path $root 'build\THIRD_PARTY_LICENSES.txt'), [Text.Encoding]::UTF8)
    [IO.File]::WriteAllText((Join-Path $root 'build\INSTALLER-LICENSES.txt'), $notices, [Text.UTF8Encoding]::new($true))
    $compilerArgs = @("/DAppVersion=$AppVersion")
    if ($Signed) {
        Assert-KeyMelierSignature 'dist\KeyMelier\KeyMelier.exe' $env:CERTUM_CERT_SHA1
        # Do not reuse an uninstaller signed by an old certificate.
        $cache = Join-Path $root 'build\signed-uninstaller'
        if (Test-Path $cache) { Remove-Item $cache -Recurse -Force }
        New-Item $cache -ItemType Directory -Force | Out-Null
        $ps = (Get-Command pwsh.exe -ErrorAction Stop).Source.Replace('$', '$$')
        $script = (Join-Path $PSScriptRoot 'sign-windows.ps1').Replace('$', '$$')
        $command = '$q' + $ps + '$q -NoProfile -NonInteractive -File $q' + $script + '$q -Path $f'
        $compilerArgs += '/DSignWindows=1', "/Scertum=$command"
    }
    $compilerArgs += 'packaging\keymelier.iss'
    & "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe" @compilerArgs
    if ($LASTEXITCODE -ne 0) { throw 'Installer build failed.' }
    if ($Signed) {
        Assert-KeyMelierSignature 'dist\KeyMelier-Windows-Setup.exe' $env:CERTUM_CERT_SHA1
        # With SignTool enabled, Inno signs uninst.e32.tmp on the fly and deletes
        # it afterwards. Our callback verifies it before Inno embeds it; the
        # Windows integration test also checks the installed unins000.exe.
    }
} finally {
    Pop-Location
}
