@echo off
echo Starting RedKit Proxy...

:: Check for virtual environment and set paths
set "VENV_PYTHON=%~dp0.venv\Scripts\python.exe"
set "VENV_MITMDUMP=%~dp0.venv\Scripts\mitmdump.exe"

:: Use virtual environment if it exists, otherwise use system commands
if exist "%VENV_PYTHON%" (
    set "PY_CMD=%VENV_PYTHON%"
) else (
    set "PY_CMD=python"
)

if exist "%VENV_MITMDUMP%" (
    set "MITM_CMD=%VENV_MITMDUMP%"
) else (
    set "MITM_CMD=mitmdump"
)

:: Start the Python backend in a new window
start "RedKit Backend" cmd /k ""%PY_CMD%" backend.py"

:: Start mitmdump with the backend script in a new window
start "RedKit MitmDump" cmd /k ""%MITM_CMD%" -s backend.py -p 8080"

echo Proxy components are starting in separate windows...
pause