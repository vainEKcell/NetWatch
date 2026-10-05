; NetWatch 安装包脚本（Inno Setup 6）
; 构建方式见 build-installer.ps1；版本号可由 ISCC /DMyAppVersion=x.y.z 覆盖

#ifndef MyAppVersion
#define MyAppVersion "1.0.0"
#endif

#define MyAppName "NetWatch"
#define MyAppExeName "NetWatch.exe"

[Setup]
AppId={{8F4E1C62-9A3D-4B57-B21E-C6F0A5D83E91}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher=NetWatch
DefaultDirName={autopf}\NetWatch
DisableProgramGroupPage=yes
PrivilegesRequired=admin
OutputDir=dist
OutputBaseFilename=NetWatch-Setup-{#MyAppVersion}
SetupIconFile=src\NetWatch\Assets\app.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "publish\installer-payload\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#MyAppName}}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; 用户数据（基线/证据/设置）保存在 %LOCALAPPDATA%\NetWatch，卸载时保留；如需彻底清除请手动删除该目录
