@echo off
NET SESSION >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    PowerShell -Command "Start-Process '%~f0' -Verb RunAs"
    EXIT
)
cd /d C:\Users\SAVITHRI\PatchAgent
call venv\Scripts\activate.bat
python main.py
pause