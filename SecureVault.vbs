Set WshShell = CreateObject("WScript.Shell")
ProjectDir = CreateObject("Scripting.FileSystemObject").GetParentFolderName(WScript.ScriptFullName)
PythonwPath = ProjectDir & "\venv\Scripts\pythonw.exe"
MainPyPath = ProjectDir & "\main.py"

WshShell.CurrentDirectory = ProjectDir
WshShell.Run """" & PythonwPath & """ """ & MainPyPath & """", 0, False
Set WshShell = Nothing
