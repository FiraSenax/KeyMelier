@echo off
REM KeyMelier — Windows launcher
REM Double-click this file to start the app.
REM NOTE: On Windows 10 v1903+, direct CTAP2 HID access requires running as Administrator.
REM Right-click this file and choose "Run as administrator" if tokens are not detected.

cd /d "%~dp0"

if exist "venv\Scripts\activate.bat" (
    call venv\Scripts\activate.bat
)

pip install -q -r requirements.txt

python app.py
pause
