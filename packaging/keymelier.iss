; Windows installer (Inno Setup 6): installs to Program Files, Start menu
; entry, uninstaller; a newer installer replaces an existing installation
; (same AppId) and closes a running KeyMelier first.
#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef VCMinVersion
  #define VCMinVersion "14.44.35211.0"
#endif

[Setup]
AppId={{B51D17BC-8D7E-4DF0-90EF-BFA10DC2A0C0}
AppName=KeyMelier
AppVersion={#AppVersion}
AppVerName=KeyMelier {#AppVersion}
AppPublisher=KeyMelier project
AppPublisherURL=https://firasenax.github.io/KeyMelier/
AppSupportURL=https://github.com/FiraSenax/KeyMelier/issues
AppUpdatesURL=https://github.com/FiraSenax/KeyMelier/releases/latest
DefaultDirName={autopf}\KeyMelier
DefaultGroupName=KeyMelier
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir=..\dist
OutputBaseFilename=KeyMelier-Windows-Setup
SetupIconFile=..\static\icon.ico
UninstallDisplayIcon={app}\KeyMelier.exe
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
RestartApplications=no
LicenseFile=..\build\INSTALLER-LICENSES.txt
VersionInfoProductName=KeyMelier
VersionInfoProductVersion={#AppVersion}
VersionInfoVersion={#AppVersion}
VersionInfoDescription=KeyMelier installer
#ifdef SignWindows
SignTool=certum
SignedUninstaller=yes
SignedUninstallerDir=..\build\signed-uninstaller
#endif

[Languages]
Name: "en"; MessagesFile: "compiler:Default.isl"
Name: "de"; MessagesFile: "compiler:Languages\German.isl"
Name: "fr"; MessagesFile: "compiler:Languages\French.isl"
Name: "es"; MessagesFile: "compiler:Languages\Spanish.isl"
Name: "it"; MessagesFile: "compiler:Languages\Italian.isl"
Name: "nl"; MessagesFile: "compiler:Languages\Dutch.isl"
Name: "pl"; MessagesFile: "compiler:Languages\Polish.isl"
Name: "pt"; MessagesFile: "compiler:Languages\Portuguese.isl"
Name: "ja"; MessagesFile: "compiler:Languages\Japanese.isl"

[CustomMessages]
RuntimeRequired=Microsoft Visual C++ v14 Redistributable (x64, {#VCMinVersion} or later) is required. Install it from Microsoft, then retry.
RuntimeOffer=The required Microsoft Visual C++ runtime is missing or too old.%n%nDownload it directly from Microsoft and open its installer now? After you complete Microsoft's setup, KeyMelier Setup will continue automatically.
RuntimeDownload=Downloading the Microsoft Visual C++ runtime
RuntimeDownloadHint=The Microsoft installer opens after its signature has been checked.
RuntimeFailed=The Microsoft runtime could not be downloaded, verified or installed. KeyMelier has not been installed. Retry or install the runtime directly from Microsoft.
RuntimeCancelled=The runtime installation was cancelled. KeyMelier has not been installed. Retry when you are ready.
RuntimeRestart=Microsoft requires a restart to finish installing the runtime. Restart Windows, then run KeyMelier Setup again.
de.RuntimeRequired=Microsoft Visual C++ v14 Redistributable (x64, ab {#VCMinVersion}) wird benötigt. Installiere es von Microsoft und versuche es erneut.
de.RuntimeOffer=Die benötigte Microsoft-Visual-C++-Runtime fehlt oder ist zu alt.%n%nJetzt direkt von Microsoft herunterladen und deren Installer öffnen? Sobald du das Microsoft-Setup abgeschlossen hast, setzt KeyMelier seine Installation automatisch fort.
de.RuntimeDownload=Microsoft-Visual-C++-Runtime wird heruntergeladen
de.RuntimeDownloadHint=Nach der Signaturprüfung öffnet sich der Microsoft-Installer.
de.RuntimeFailed=Die Microsoft-Runtime konnte nicht heruntergeladen, geprüft oder installiert werden. KeyMelier wurde nicht installiert. Versuche es erneut oder installiere die Runtime direkt von Microsoft.
de.RuntimeCancelled=Die Runtime-Installation wurde abgebrochen. KeyMelier wurde nicht installiert. Du kannst es erneut versuchen.
de.RuntimeRestart=Microsoft benötigt einen Neustart, um die Runtime-Installation abzuschließen. Starte Windows neu und führe danach das KeyMelier-Setup erneut aus.

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[InstallDelete]
; files of the previous version that no longer exist
Type: filesandordirs; Name: "{app}\_internal"

[Files]
Source: "..\dist\KeyMelier\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\tools\install-vc-runtime.ps1"; Flags: dontcopy

[Icons]
Name: "{group}\KeyMelier"; Filename: "{app}\KeyMelier.exe"
Name: "{autodesktop}\KeyMelier"; Filename: "{app}\KeyMelier.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\KeyMelier.exe"; Description: "{cm:LaunchProgram,KeyMelier}"; Flags: nowait postinstall skipifsilent shellexec; Check: CanLaunchKeyMelier

[Code]
const
  RuntimeHelp = 'https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist';
  RuntimeDownload = 'https://aka.ms/vc14/vc_redist.x64.exe';

var
  RuntimePage: TDownloadWizardPage;
  RuntimeRestartRequired: Boolean;

procedure InitializeWizard;
begin
  RuntimePage := CreateDownloadPage(CustomMessage('RuntimeDownload'), CustomMessage('RuntimeDownloadHint'), nil);
  RuntimePage.ShowBaseNameInsteadOfUrl := True;
end;

function CanLaunchKeyMelier(): Boolean;
begin
  Result := not RuntimeRestartRequired;
end;

function NeedRestart(): Boolean;
begin
  Result := RuntimeRestartRequired;
end;

function HasVCRuntime(): Boolean;
var
  Version, Minimum: Int64;
begin
  Log('Checking Microsoft C++ x64 runtime >= {#VCMinVersion}');
  if not StrToVersion('{#VCMinVersion}', Minimum) then RaiseException('Invalid C++ runtime minimum version');
  Result := GetPackedVersion(ExpandConstant('{sys}\vcruntime140.dll'), Version);
  if Result then Result := ComparePackedVersion(Version, Minimum) >= 0;
  if Result then Result := GetPackedVersion(ExpandConstant('{sys}\msvcp140.dll'), Version);
  if Result then Result := ComparePackedVersion(Version, Minimum) >= 0;
  if Result then Result := GetPackedVersion(ExpandConstant('{sys}\vcruntime140_1.dll'), Version);
  if Result then Result := ComparePackedVersion(Version, Minimum) >= 0;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Code: Integer;
  Parameters: String;
begin
  Result := '';
  if HasVCRuntime() then Exit;
  Result := CustomMessage('RuntimeRequired') + #13#10 + RuntimeHelp;
  // Silent deployments retain the existing no-download behavior. Administrators
  // provision the prerequisite separately; interactive downloads need consent.
  if WizardSilent() then Exit;
  if MsgBox(CustomMessage('RuntimeOffer'), mbConfirmation, MB_YESNO or MB_DEFBUTTON2) <> IDYES then Exit;
  Result := CustomMessage('RuntimeFailed') + #13#10 + RuntimeHelp;
  try
    try
      RuntimePage.Clear;
      RuntimePage.Add(RuntimeDownload, 'vc_redist.x64.exe', '');
      RuntimePage.Show;
      try
        RuntimePage.Download;
      finally
        RuntimePage.Hide;
      end;
      ExtractTemporaryFile('install-vc-runtime.ps1');
      Parameters := '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' +
        ExpandConstant('{tmp}\install-vc-runtime.ps1') + '" -RuntimePath "' +
        ExpandConstant('{tmp}\vc_redist.x64.exe') + '" -MinimumVersion "{#VCMinVersion}"';
      // The embedded helper verifies Microsoft's Authenticode publisher before
      // launching the downloaded EXE, and waits for Microsoft's interactive UI.
      if not Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
        Parameters, '', SW_HIDE, ewWaitUntilTerminated, Code) then Exit;
      Log(Format('Microsoft runtime installer exit code: %d', [Code]));
      if Code = 1602 then begin
        Result := CustomMessage('RuntimeCancelled');
        Exit;
      end;
      if (Code <> 0) and (Code <> 1638) and (Code <> 3010) and (Code <> 1641) then Exit;
      RuntimeRestartRequired := (Code = 3010) or (Code = 1641);
      if HasVCRuntime() then
        Result := ''
      else if RuntimeRestartRequired then begin
        NeedsRestart := True;
        Result := CustomMessage('RuntimeRestart');
      end;
    except
      if RuntimePage.AbortedByUser then Result := CustomMessage('RuntimeCancelled');
      Log('Microsoft runtime prerequisite did not complete.');
    end;
  finally
    DeleteFile(ExpandConstant('{tmp}\vc_redist.x64.exe'));
  end;
end;
