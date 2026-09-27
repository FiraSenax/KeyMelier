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
rem The report records which files pip installed (SBOM hashes, tools/sbom.py);
rem --force-reinstall so a rebuild records every package, not only new ones
if exist build\pip-report*.json del /q build\pip-report*.json
build-venv\Scripts\python -m pip install --require-hashes --force-reinstall -q -r requirements.txt -r requirements-build.txt --report build\pip-report.json
if errorlevel 1 exit /b 1

rem Source commit for About/diagnostics (CI writes it in its own step)
if not defined CI build-venv\Scripts\python tools\write_build_info.py

echo Running PyInstaller...
build-venv\Scripts\pyinstaller --clean --noconfirm fido2tool.spec
if errorlevel 1 exit /b 1

echo.
echo Build complete: dist\KeyMelier\KeyMelier.exe
pause
