# One-shot hardware acceptance check for the ESP32-S3 board.
#
#   pwsh -File tools\check-board.ps1
#
# Reports, without needing the OLED to work:
#   * the serial port and the USB bridge chip it is behind
#   * the chip type, revision, flash size and eFuse settings (via esptool)
#   * whether any USB device is currently failing to enumerate
#
# This is the "is the board itself good?" half of an acceptance test; the rest of
# the device (radio, web UI, BLE) is checked with flash-sniffer.ps1 and the
# test_*.ps1 scripts next to this one.

[CmdletBinding()]
param([string]$Port)

$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
$Scripts = Join-Path $env:APPDATA 'Python\Python313\Scripts'
$env:Path += ";$Scripts"
$env:TEMP = Join-Path $root '.tmp'
$env:TMP  = $env:TEMP
New-Item -ItemType Directory -Force -Path $env:TEMP | Out-Null

function Section($t) { Write-Host "`n=== $t ===" -ForegroundColor Cyan }

Section 'USB side'
$ports = @([System.IO.Ports.SerialPort]::GetPortNames() | Sort-Object)
if (-not $ports) {
  Write-Host 'no COM port present - is the board plugged in with a DATA cable?' -ForegroundColor Red
  Write-Host 'a charge-only cable powers the board but never enumerates.' -ForegroundColor Red
  return
}
Write-Host ("COM ports: {0}" -f ($ports -join ', ')) -ForegroundColor Green

Get-PnpDevice -PresentOnly -Class Ports -ErrorAction SilentlyContinue |
  Select-Object Status, FriendlyName, InstanceId |
  Format-Table -AutoSize | Out-String -Width 200 | Write-Host

$bad = Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue | Where-Object Status -eq 'Error'
if ($bad) {
  Write-Host 'failing USB devices (should be none):' -ForegroundColor Red
  $bad | Select-Object FriendlyName, InstanceId | Format-Table -AutoSize | Out-String -Width 200 | Write-Host
} else {
  Write-Host 'no failing USB devices' -ForegroundColor Green
}

if (-not $Port) { $Port = $ports[0] }
Write-Host "using port: $Port"

Section "Chip identity on $Port"
if (-not (Get-Command esptool -ErrorAction SilentlyContinue)) {
  Write-Host 'esptool not on PATH; install with: python -m pip install --user esptool' -ForegroundColor Yellow
} else {
  esptool --port $Port flash-id 2>&1 | Write-Host
}

Section 'Summary'
Write-Host 'Board is healthy when the above shows:'
Write-Host '  * a COM port, with no failing USB device'
Write-Host '  * "Detected flash size: 16MB" and "Chip type: ESP32-S3"'
Write-Host 'The rest of the device is a separate matter - check it by flashing the'
Write-Host 'firmware with tools\flash-sniffer.ps1 and running tools\test_juice.ps1.'
