Set WshShell = CreateObject("WScript.Shell")
strPath = CreateObject("Scripting.FileSystemObject").GetParentFolderName(WScript.ScriptFullName)
strCmd = """" & strPath & "\backend\venv\Scripts\pythonw.exe"" """ & strPath & "\launcher.py"""
WshShell.CurrentDirectory = strPath
WshShell.Run strCmd, 1, False
