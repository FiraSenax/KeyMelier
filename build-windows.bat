@echo off
REM KeyMelier — Windows build script
REM Produces: dist\KeyMelier\KeyMelier.exe
REM Requires: Python 3.10+ on PATH

cd /d "%~dp0"

echo === KeyMelier - Windows build ===

if not exist "build-venv\Scripts\python.exe" (
    echo Creating build venv...
    python -m venv build-venv
)

echo Installing dependencies...
build-venv\Scripts\pip install -q --upgrade pip
build-venv\Scripts\pip install -q -r requirements.txt
build-venv\Scripts\pip install -q pyinstaller

echo Running PyInstaller...
build-venv\Scripts\pyinstaller --clean --noconfirm fido2tool.spec

echo.
echo Build complete: dist\KeyMelier\KeyMelier.exe
pause
