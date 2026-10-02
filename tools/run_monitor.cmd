@echo off
REM ---------------------------------------------------------------------------
REM  Test_1101 - launch the live monitor in its own cmd window.
REM
REM  Double-click this file, or run it from any terminal.
REM  Optional first argument: the serial port (default: auto-detect).
REM ---------------------------------------------------------------------------
setlocal
cd /d "%~dp0.."

if "%~1"=="" (
  set PORT_ARG=
) else (
  set PORT_ARG=--port %~1
)

title Test_1101 monitor
mode con: cols=130 lines=45

echo Starting the Test_1101 monitor...
echo   connect a device to the open Wi-Fi network "Test_1101"
echo   press Ctrl+C in the monitor window to stop
echo.

python "%~dp0wifi_monitor.py" %PORT_ARG% --log "%~dp0..\capture.csv"

echo.
echo Monitor stopped.
pause
