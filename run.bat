@echo off
setlocal
cd /d "%~dp0"
if not exist "venv\Scripts\python.exe" python -m venv venv
if errorlevel 1 exit /b 1
venv\Scripts\python -m pip install --require-hashes -r requirements.txt
if errorlevel 1 exit /b 1
venv\Scripts\python app.py %*
