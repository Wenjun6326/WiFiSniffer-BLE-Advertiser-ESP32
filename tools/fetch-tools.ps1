# Fetch the esp32:esp32 toolchain into arduino-cli's package cache, through a
# GitHub proxy.
#
# Why this exists: on this network `github.com` and `objects.githubusercontent.com`
# resolve to 127.0.0.1 (DNS poisoning), so every release asset 404s or times out.
# `espressif.github.io` is reachable but throttles to ~75 KB/s.  Routing the same
# files through a GitHub proxy and fetching byte ranges in parallel gets the whole
# toolchain down in minutes instead of hours.
#
# Files land in <data>/downloads/packages with exactly the names arduino-cli
# expects, so the later `core install` finds them and skips the network.
#
#   pwsh -File tools\fetch-tools.ps1            # fetch everything missing
#   pwsh -File tools\fetch-tools.ps1 -Skip xtensa-esp-elf   # e.g. while it downloads

[CmdletBinding()]
param(
  [string]$Proxy = 'https://ghfast.top/',
  [string[]]$Skip = @(),
  [int]$Parts = 16
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$dl   = Join-Path $root '.arduino-dl\packages'
New-Item -ItemType Directory -Force -Path $dl | Out-Null

$env:TEMP = Join-Path $root '.tmp'
$env:TMP  = $env:TEMP
New-Item -ItemType Directory -Force -Path $env:TEMP | Out-Null

$Pget = Join-Path $PSScriptRoot 'pget.ps1'

# name (for -Skip matching) -> URL
$items = @(
  @{ n = 'platform';          u = 'https://github.com/espressif/arduino-esp32/releases/download/3.3.12/esp32-core-3.3.12.zip' }
  @{ n = 'esp32s3-libs';      u = 'https://github.com/espressif/arduino-esp32/releases/download/3.3.12/esp32s3-libs-3.3.12.zip' }
  @{ n = 'esp32-libs';        u = 'https://github.com/espressif/arduino-esp32/releases/download/3.3.12/esp32-libs-3.3.12.zip' }
  @{ n = 'riscv32-esp-elf';   u = 'https://github.com/espressif/crosstool-NG/releases/download/esp-14.2.0_20260121/riscv32-esp-elf-14.2.0_20260121-x86_64-w64-mingw32.zip' }
  @{ n = 'esptool';           u = 'https://github.com/espressif/esptool/releases/download/v5.3.1/esptool-v5.3.1-windows-amd64.zip' }
  @{ n = 'mklittlefs';        u = 'https://github.com/earlephilhower/mklittlefs/releases/download/4.0.2/x86_64-w64-mingw32-mklittlefs-db0513a.zip' }
  @{ n = 'mkspiffs';          u = 'https://github.com/igrr/mkspiffs/releases/download/0.2.3/mkspiffs-0.2.3-arduino-esp32-win32.zip' }
  @{ n = 'esp32c3-libs';      u = 'https://github.com/espressif/arduino-esp32/releases/download/3.3.12/esp32c3-libs-3.3.12.zip' }
  @{ n = 'esp32c6-libs';      u = 'https://github.com/espressif/arduino-esp32/releases/download/3.3.12/esp32c6-libs-3.3.12.zip' }
  @{ n = 'esp32h2-libs';      u = 'https://github.com/espressif/arduino-esp32/releases/download/3.3.12/esp32h2-libs-3.3.12.zip' }
  @{ n = 'esp32p4-libs';      u = 'https://github.com/espressif/arduino-esp32/releases/download/3.3.12/esp32p4-libs-3.3.12.zip' }
  @{ n = 'esp32p4_es-libs';   u = 'https://github.com/espressif/arduino-esp32/releases/download/3.3.12/esp32p4_es-libs-3.3.12.zip' }
  @{ n = 'esp32c5-libs';      u = 'https://github.com/espressif/arduino-esp32/releases/download/3.3.12/esp32c5-libs-3.3.12.zip' }
  @{ n = 'esp32s2-libs';      u = 'https://github.com/espressif/arduino-esp32/releases/download/3.3.12/esp32s2-libs-3.3.12.zip' }
  @{ n = 'esp32c2-libs';      u = 'https://github.com/espressif/arduino-esp32/releases/download/3.3.12/esp32c2-libs-3.3.12.zip' }
)

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$done = @()
$fail = @()

foreach ($it in $items) {
  $file = Split-Path -Leaf $it.u
  $dest = Join-Path $dl $file

  if ($Skip -contains $it.n) { Write-Host "skip (requested): $($it.n)" -ForegroundColor DarkGray; continue }

  # Is this zip already being written by arduino-cli?  Detect by sampling growth.
  if (Test-Path $dest) {
    $a = (Get-Item $dest).Length
    Start-Sleep -Milliseconds 1500
    $b = (Get-Item $dest).Length
    if ($b -ne $a) {
      Write-Host "skip (arduino-cli is downloading it): $file  [{0:N1} MB]" -f ($b / 1MB) -ForegroundColor DarkGray
      continue
    }
    if ($b -gt 1000) {
      Write-Host "already present: $file  [{0:N1} MB]" -f ($b / 1MB) -ForegroundColor DarkGray
      continue
    }
  }

  Write-Host "`n--- $($it.n)" -ForegroundColor Cyan
  Write-Host "    $file"
  try {
    $url = $Proxy + $it.u
    & pwsh -NoProfile -File $Pget -Url $url -Out $dest -Parts $Parts
    if ($LASTEXITCODE -ne 0) { throw "pget exited $LASTEXITCODE" }
    $done += $it.n
  } catch {
    Write-Host "    FAILED: $($_.Exception.Message)" -ForegroundColor Red
    $fail += $it.n
  }
}

$sw.Stop()
Write-Host "`n================ summary ================" -ForegroundColor Cyan
Write-Host ("elapsed : {0:N0} min" -f $sw.Elapsed.TotalMinutes)
Write-Host ("fetched : {0}" -f ($(if ($done) { $done -join ', ' } else { '(nothing)' })))
if ($fail) { Write-Host ("failed  : {0}" -f ($fail -join ', ')) -ForegroundColor Red }
Write-Host ''

Get-ChildItem $dl -File | Sort-Object Length -Descending |
  Select-Object @{n = 'MB'; e = { [math]::Round($_.Length / 1MB, 1) } }, Name |
  Format-Table -AutoSize | Out-String | Write-Host
