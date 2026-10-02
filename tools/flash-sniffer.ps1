# Build / upload the Test_1101 sniffer firmware.
#
#   pwsh -File tools\flash-sniffer.ps1              # compile, then upload
#   pwsh -File tools\flash-sniffer.ps1 -BuildOnly   # compile only
#   pwsh -File tools\flash-sniffer.ps1 -Port COM6   # skip auto-detection
#   pwsh -File tools\flash-sniffer.ps1 -Oled ssd1306
#
# Differs from a plain `arduino-cli compile` in exactly two ways:
#
#   * the partition scheme.  With BLE linked in, this sketch is ~1.23 MB and the
#     stock "Default 4MB with spiffs" app slot is 1.25 MB - it fits with 80 KB to
#     spare, and -Oled ssd1306 or any further feature will not.  "Huge APP" gives
#     the app 3 MB and still leaves a 1 MB filesystem, which is ample for
#     events.log (capped at 512 KB in the firmware).
#
#   * the optional OLED defines, which the sketch reads to pick a panel driver.
#
# Everything (toolchain, downloads, build cache) stays on D:.

[CmdletBinding()]
param(
  [switch]$BuildOnly,
  [string]$Port,
  [ValidateSet('none', 'sh1106', 'ssd1306')]
  [string]$Oled = 'sh1106',
  [string]$BuildDir
)

$ErrorActionPreference = 'Stop'

$Root    = Split-Path -Parent $PSScriptRoot
$Acli    = Join-Path $Root 'tools\arduino-cli\arduino-cli.exe'
$Sketch  = Join-Path $Root 'wifi_sniffer'
if (-not $BuildDir) { $BuildDir = Join-Path $Root "build-sniff-$Oled" }

# Compiling pulls in the whole toolchain; without this the C: volume fills up.
$env:TEMP = Join-Path $Root '.tmp'
$env:TMP  = $env:TEMP
New-Item -ItemType Directory -Force -Path $env:TEMP, $BuildDir | Out-Null

$fqbn = 'esp32:esp32:esp32s3:PartitionScheme=huge_app'
$extra = @()
if ($Oled -ne 'none') {
  # OLED_ENABLE only; the driver profile (OLED_SH1106) is already the sketch
  # default, so ssd1306 is the one that needs the flag.
  $extra += '--build-property'
  $extra += 'compiler.cpp.extra_flags=-DOLED_ENABLE=1' + $(if ($Oled -eq 'ssd1306') { ' -DOLED_SH1106=0' } else { '' })
}

Write-Host "=== compiling $Sketch (oled=$Oled) ===" -ForegroundColor Cyan
& $Acli compile --fqbn $fqbn --build-path $BuildDir --warnings none @extra $Sketch
if ($LASTEXITCODE -ne 0) { throw "compile failed (exit $LASTEXITCODE)" }
Write-Host 'compile OK' -ForegroundColor Green

if ($BuildOnly) { return }

if (-not $Port) {
  $cand = @([System.IO.Ports.SerialPort]::GetPortNames() | Sort-Object)
  if ($cand.Count -eq 1) {
    $Port = $cand[0]
    Write-Host "auto-selected $Port"
  } elseif ($cand.Count -gt 1) {
    Write-Host "several ports present: $($cand -join ', ') - pass -Port COMx" -ForegroundColor Yellow
    return
  } else {
    throw 'no COM port available - is the board plugged in with a DATA cable?'
  }
}

Write-Host "=== uploading to $Port ===" -ForegroundColor Cyan
& $Acli upload -p $Port --fqbn $fqbn --input-dir $BuildDir
if ($LASTEXITCODE -ne 0) { throw "upload failed (exit $LASTEXITCODE)" }

Write-Host ''
Write-Host 'uploaded.  Next steps:' -ForegroundColor Green
Write-Host '  join the open network Test_1101, open http://192.168.4.1/admin (admin / 1324123)'
Write-Host '  or run:  pwsh -File tools\test_juice.ps1'
