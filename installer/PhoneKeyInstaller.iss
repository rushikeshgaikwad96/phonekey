; Inno Setup Script for PhoneKey Windows Installer (Phase 2)
#define MyAppName "PhoneKey"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "PhoneKey Open Source Security"
#define MyAppURL "https://github.com/phonekey/phonekey"
#define MyAppExeName "PhoneKeyAgent.exe"

[Setup]
AppId={{D89B5F7A-2E4C-4D19-9B3A-8F7C6E5D4C3B}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={pf}\{#MyAppName}
DefaultGroupName={#MyAppName}
OutputBaseFilename=PhoneKey_Setup_v1.0.0
Compression=lzma2/max
SolidCompression=yes
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "..\PhoneKeyAgent.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\PhoneKeyCredentialProvider.dll"; DestDir: "{app}"; Flags: ignoreversion regserver
Source: "..\docs\user_setup_guide.md"; DestDir: "{app}\docs"; Flags: ignoreversion

[Icons]
Name: "{group}\PhoneKey Agent"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Uninstall PhoneKey"; Filename: "{uninstallexe}"

[Run]
Filename: "sc.exe"; Parameters: "create PhoneKeyAgent binPath= ""{app}\{#MyAppExeName}"" start= auto displayname= ""PhoneKey Desktop Agent Service"""; Flags: runhidden
Filename: "sc.exe"; Parameters: "start PhoneKeyAgent"; Flags: runhidden

[UninstallRun]
Filename: "sc.exe"; Parameters: "stop PhoneKeyAgent"; Flags: runhidden
Filename: "sc.exe"; Parameters: "delete PhoneKeyAgent"; Flags: runhidden
Filename: "regsvr32.exe"; Parameters: "/u /s ""{app}\PhoneKeyCredentialProvider.dll"""; Flags: runhidden
