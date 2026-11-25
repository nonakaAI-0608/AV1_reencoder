@echo off
cd /d "%~dp0"
rem Launch the GUI without a console window; this window closes immediately.
where pyw >nul 2>nul
if not errorlevel 1 (
    start "" pyw -3 AV1_reencoder.py
) else (
    start "" pythonw AV1_reencoder.py
)
exit /b 0
