@echo off
setlocal
python "%~dp0scripts\build_complete.py" %*
exit /b %ERRORLEVEL%
