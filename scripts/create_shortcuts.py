import os
import sys

def create_windows_shortcuts():
    if sys.platform != "win32":
        print("Shortcut creation is only supported on Windows.")
        return

    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    pythonw_path = os.path.join(project_root, "venv", "Scripts", "pythonw.exe")
    main_py_path = os.path.join(project_root, "main.py")
    icon_path = os.path.join(project_root, "assets", "icon.ico")

    if not os.path.exists(pythonw_path):
        raise FileNotFoundError(f"pythonw.exe not found at {pythonw_path}")
    if not os.path.exists(icon_path):
        raise FileNotFoundError(f"icon.ico not found at {icon_path}")

    # Use PowerShell COM object WScript.Shell to avoid extra win32com dependencies
    import subprocess
    ps_script = os.path.join(project_root, "scripts", "create_shortcuts.ps1")
    res = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", ps_script], capture_output=True, text=True)
    print(res.stdout)
    if res.returncode != 0:
        print(f"Error creating shortcuts: {res.stderr}", file=sys.stderr)
        sys.exit(res.returncode)

if __name__ == "__main__":
    create_windows_shortcuts()
