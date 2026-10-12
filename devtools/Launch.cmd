@echo off
setlocal
cd /d "%~dp0"
if exist "C:\Users\1\AppData\Local\Programs\Python\Python311\python.exe" (
  "C:\Users\1\AppData\Local\Programs\Python\Python311\python.exe" -B app.py --open
) else (
  py -3 -B app.py --open
)
if errorlevel 1 pause
