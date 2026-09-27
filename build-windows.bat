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
if not exist build mkdir build
rem The reports record which files pip installed (SBOM hashes, tools/sbom.py)
build-venv\Scripts\pip install --require-hashes -q -r requirements.txt --report build\pip-report-runtime.json
if errorlevel 1 exit /b 1
build-venv\Scripts\pip install --require-hashes -q -r requirements-build.txt --report build\pip-report-build.json
if errorlevel 1 exit /b 1

echo Running PyInstaller...
build-venv\Scripts\pyinstaller --clean --noconfirm fido2tool.spec
if errorlevel 1 exit /b 1

echo.
echo Build complete: dist\KeyMelier\KeyMelier.exe
pause
