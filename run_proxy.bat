@echo off
echo Starting RedKit Proxy...

:: Start the Python backend in a new window
start "RedKit Backend" cmd /k "python backend.py"

:: Start mitmdump with the backend script in a new window
start "RedKit MitmDump" cmd /k "mitmdump -s backend.py -p 8080"

echo Proxy components are starting in separate windows...
pause