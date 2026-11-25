@echo off
cd /d "%~dp0"
rem Launch the GUI without a console window; this window closes immediately.
where pyw >nul 2>nul
if not errorlevel 1 (
    start "" pyw -3 video_reencoder_gui_v18.py
) else (
    start "" pythonw video_reencoder_gui_v18.py
)
exit /b 0
