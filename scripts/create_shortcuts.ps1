# PowerShell script to create Desktop and Start Menu shortcuts for SecureVault
$ErrorActionPreference = "Stop"

$ProjectRoot = (Resolve-Path "$PSScriptRoot\..").Path
$PythonwPath = Join-Path $ProjectRoot "venv\Scripts\pythonw.exe"
$MainPyPath = Join-Path $ProjectRoot "main.py"
$IconPath = Join-Path $ProjectRoot "assets\icon.ico"

if (-not (Test-Path $PythonwPath)) {
    Write-Error "Virtual environment pythonw.exe not found at $PythonwPath"
    exit 1
}

if (-not (Test-Path $IconPath)) {
    Write-Error "Icon file not found at $IconPath. Run scripts\generate_icon.py first."
    exit 1
}

$WshShell = New-Object -ComObject WScript.Shell

# 1. Desktop Shortcut
$DesktopFolder = [Environment]::GetFolderPath("Desktop")
$DesktopShortcutPath = Join-Path $DesktopFolder "SecureVault.lnk"
$DesktopShortcut = $WshShell.CreateShortcut($DesktopShortcutPath)
$DesktopShortcut.TargetPath = $PythonwPath
$DesktopShortcut.Arguments = "`"$MainPyPath`""
$DesktopShortcut.WorkingDirectory = $ProjectRoot
$DesktopShortcut.IconLocation = "$IconPath,0"
$DesktopShortcut.Description = "SecureVault Password Manager"
$DesktopShortcut.Save()
Write-Host "Created Desktop Shortcut: $DesktopShortcutPath"

# 2. Start Menu Programs Shortcut
$ProgramsFolder = [Environment]::GetFolderPath("Programs")
$ProgramsShortcutPath = Join-Path $ProgramsFolder "SecureVault.lnk"
$ProgramsShortcut = $WshShell.CreateShortcut($ProgramsShortcutPath)
$ProgramsShortcut.TargetPath = $PythonwPath
$ProgramsShortcut.Arguments = "`"$MainPyPath`""
$ProgramsShortcut.WorkingDirectory = $ProjectRoot
$ProgramsShortcut.IconLocation = "$IconPath,0"
$ProgramsShortcut.Description = "SecureVault Password Manager"
$ProgramsShortcut.Save()
Write-Host "Created Start Menu Shortcut: $ProgramsShortcutPath"
