; Windows installer (Inno Setup 6): installs to Program Files, Start menu
; entry, uninstaller; a newer installer replaces an existing installation
; (same AppId) and closes a running KeyMelier first.
#ifndef AppVersion
  #define AppVersion "0.0.0"
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
OutputDir=..\dist
OutputBaseFilename=KeyMelier-Windows-Setup
SetupIconFile=..\static\icon.ico
UninstallDisplayIcon={app}\KeyMelier.exe
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
RestartApplications=no
LicenseFile=..\LICENSE
VersionInfoProductName=KeyMelier
VersionInfoProductVersion={#AppVersion}
VersionInfoVersion={#AppVersion}
VersionInfoDescription=KeyMelier installer

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

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[InstallDelete]
; files of the previous version that no longer exist
Type: filesandordirs; Name: "{app}\_internal"

[Files]
Source: "..\dist\KeyMelier\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\KeyMelier"; Filename: "{app}\KeyMelier.exe"
Name: "{autodesktop}\KeyMelier"; Filename: "{app}\KeyMelier.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\KeyMelier.exe"; Description: "{cm:LaunchProgram,KeyMelier}"; Flags: nowait postinstall skipifsilent shellexec
