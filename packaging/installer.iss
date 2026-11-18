; AntivirusMVP 安裝程式（Inno Setup 6）
; 以一般使用者權限安裝到 %LOCALAPPDATA%\Programs，不需要系統管理員權限。

#ifndef AppVersion
  #define AppVersion "0.1.0"
#endif

[Setup]
AppId={{620AB0C3-6854-4528-9C9E-6C461E441C4D}
AppName=AntivirusMVP
AppVersion={#AppVersion}
AppPublisher=Alvin Jhu
AppPublisherURL=https://github.com/AlvinJhu/antivirus-mvp
DefaultDirName={localappdata}\Programs\AntivirusMVP
DefaultGroupName=AntivirusMVP
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\dist
OutputBaseFilename=AntivirusMVP-Setup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\AntivirusMVP.exe
LicenseFile=..\build\THIRD_PARTY_NOTICES.txt

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "建立桌面捷徑 (Create a desktop shortcut)"; GroupDescription: "捷徑 (Shortcuts):"

[Files]
Source: "..\dist\AntivirusMVP\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion
Source: "..\build\clamav\*"; DestDir: "{app}\clamav"; Flags: recursesubdirs ignoreversion
Source: "..\build\THIRD_PARTY_NOTICES.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSE"; DestDir: "{app}"; DestName: "LICENSE.txt"; Flags: ignoreversion

[Icons]
Name: "{group}\AntivirusMVP 防毒"; Filename: "{app}\AntivirusMVP.exe"
Name: "{group}\解除安裝 AntivirusMVP"; Filename: "{uninstallexe}"
Name: "{autodesktop}\AntivirusMVP 防毒"; Filename: "{app}\AntivirusMVP.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\AntivirusMVP.exe"; Description: "立即開啟 AntivirusMVP (Launch now)"; Flags: nowait postinstall skipifsilent
