; =====================================================================
; NetPulse 2D - Script de Instalacao Inno Setup 6
; =====================================================================

#ifndef MyAppVersion
  #define MyAppVersion "1.0.0"
#endif

#ifndef MyAppNumericVersion
  #define MyAppNumericVersion "1.0.0.0"
#endif

#define MyAppName "NetPulse 2D"
#define MyAppPublisher "Cristiano Groberio / Area 27"
#define MyAppURL "https://github.com/djcristianosgp/netpulse-map"
#define MyAppExeName "netpulse.exe"
#define MyAppId "{{8A4E9C21-6F3B-4B7A-9E12-3D5C7F8A1B40}"

[Setup]
AppId={#MyAppId}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
OutputDir=..\..\dist
OutputBaseFilename=NetPulse2D-Setup-x64
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
AppMutex=NetPulse2D_SingleInstance_Mutex
CloseApplications=yes
CloseApplicationsFilter=netpulse.exe
RestartApplications=no
DisableDirPage=auto
DisableProgramGroupPage=auto
SetupIconFile=..\..\assets\netpulse.ico
UninstallDisplayIcon={app}\assets\netpulse.ico
VersionInfoVersion={#MyAppNumericVersion}
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription=NetPulse 2D - Mapa Planetario de Conexoes de Rede em Tempo Real
VersionInfoCopyright=Copyright (C) 2026

[Languages]
Name: "brazilianportuguese"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "startup"; Description: "Iniciar automaticamente com o Windows"; GroupDescription: "Preferencias do Sistema:"; Flags: unchecked

[Files]
Source: "..\..\dist\staging\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\assets\netpulse.ico"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"; IconFilename: "{app}\assets\netpulse.ico"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\assets\netpulse.ico"; Tasks: desktopicon

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "NetPulse2D"; ValueData: """{app}\{#MyAppExeName}"" --no-browser"; Flags: uninsdeletevalue; Tasks: startup

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent
