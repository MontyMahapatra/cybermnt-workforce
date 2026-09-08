; CyberMNT Monitor Agent - Windows installer definition.
; Built by CI on a real windows-latest GitHub Actions runner via Inno Setup
; (iscc). Not hand-tested on a personal Windows machine by anyone yet --
; treat the first real install as the actual test.
;
; Invoked as:
;   iscc /DRepoRoot="%GITHUB_WORKSPACE%" installer\windows\cybermnt_agent.iss

#ifndef RepoRoot
  #define RepoRoot ".."
#endif

#define MyAppName "CyberMNT Monitor Agent"
#define MyAppVersion "0.3.0"
#define MyAppPublisher "CyberMNT"
#define MyAppExeName "CyberMNT-Agent.exe"

[Setup]
AppId={{B36F1E6B-9C1A-4C7E-9C34-CYBERMNT-AGENT}}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\CyberMNT Monitor
DefaultGroupName=CyberMNT Monitor
DisableProgramGroupPage=yes
OutputDir={#RepoRoot}\installer_output
OutputBaseFilename=CyberMNT-Monitor-Setup
Compression=lzma
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64compatible
WizardStyle=modern

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Files]
Source: "{#RepoRoot}\agent\dist\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#RepoRoot}\agent\config.example.yaml"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\CyberMNT Monitor Agent"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Uninstall CyberMNT Monitor Agent"; Filename: "{uninstallexe}"
Name: "{autodesktop}\CyberMNT Monitor Agent"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "notepad.exe"; Parameters: """{app}\config.example.yaml"""; \
  Description: "Open the config file now to fill in server_url / device_token / employee_id"; \
  Flags: postinstall nowait skipifsilent

[UninstallDelete]
Type: files; Name: "{app}\config.yaml"
Type: files; Name: "{app}\.offline_queue.jsonl"
