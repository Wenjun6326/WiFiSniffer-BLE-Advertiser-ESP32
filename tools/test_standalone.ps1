# Verify the standalone web console by joining the ESP32's own AP.
#
#   pwsh -File tools\test_standalone.ps1
#
# The laptop briefly leaves its normal Wi-Fi, joins Test_1101, exercises the
# three endpoints, then reconnects to whatever it was on before.  This is the
# only way to prove the device really works with no PC in the loop.

[CmdletBinding()]
param(
  [string]$Ssid = 'Test_1101',
  [string]$Base = 'http://192.168.4.1'
)

$ErrorActionPreference = 'Continue'

function Section($t) { Write-Host "`n=== $t ===" -ForegroundColor Cyan }

Section 'Before'
$before = (netsh wlan show interfaces | Select-String '^\s+SSID\s+:' |
           Select-Object -First 1).ToString()
if ($before) { Write-Host "currently on: $($before.Trim())" }

# netsh needs a profile to connect; make one for the open network.
Section "Creating a profile for $Ssid"
$profile = @"
<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <name>$Ssid</name>
  <SSIDConfig><SSID><name>$Ssid</name></SSID></SSIDConfig>
  <connectionType>ESS</connectionType>
  <connectionMode>manual</connectionMode>
  <MSM><security>
    <authEncryption><authentication>open</authentication>
      <encryption>none</encryption><useOneX>false</useOneX></authEncryption>
  </security></MSM>
</WLANProfile>
"@
$pf = Join-Path $env:TEMP "$Ssid.xml"
Set-Content -Path $pf -Value $profile -Encoding UTF8
netsh wlan add profile filename="$pf" | Out-Null

Section "Joining $Ssid"
netsh wlan connect name="$Ssid" ssid="$Ssid" | Out-Null
$ok = $false
for ($i = 1; $i -le 15; $i++) {
  Start-Sleep -Seconds 2
  $cur = (netsh wlan show interfaces | Select-String '^\s+SSID\s+:' |
          Select-Object -First 1).ToString()
  if ($cur -and $cur -match [regex]::Escape($Ssid)) { $ok = $true; break }
  Write-Host "  waiting... ($i)"
}
if (-not $ok) {
  Write-Host "could not join $Ssid - is the board powered and the AP up?" -ForegroundColor Red
} else {
  Write-Host "joined $Ssid" -ForegroundColor Green

  # DHCP from the ESP32 needs a moment to hand out a lease.
  Start-Sleep -Seconds 4

  Section 'GET /  (dashboard page)'
  try {
    $r = Invoke-WebRequest -Uri "$Base/" -TimeoutSec 15 -UseBasicParsing
    Write-Host ("status {0}, {1} bytes" -f $r.StatusCode, $r.RawContentLength) -ForegroundColor Green
    if ($r.Content -match 'Test_1101') { Write-Host 'page contains the expected title' -ForegroundColor Green }
  } catch { Write-Host "FAILED: $($_.Exception.Message)" -ForegroundColor Red }

  Section 'GET /api  (JSON)'
  try {
    $r = Invoke-WebRequest -Uri "$Base/api" -TimeoutSec 15 -UseBasicParsing
    $j = $r.Content | ConvertFrom-Json
    Write-Host ("clients={0} frames={1} logged={2} hosts={3} devices={4}" -f `
      $j.clients, $j.frames, $j.logged, $j.hosts.Count, $j.devices.Count) -ForegroundColor Green
    if ($j.hosts.Count -gt 0) {
      Write-Host 'servers seen:'
      $j.hosts | Select-Object -First 8 | ForEach-Object {
        Write-Host ("   {0,-14} {1}" -f $_.service, $_.host)
      }
    }
  } catch { Write-Host "FAILED: $($_.Exception.Message)" -ForegroundColor Red }

  Section 'GET /events.log  (flash log download)'
  try {
    $r = Invoke-WebRequest -Uri "$Base/events.log" -TimeoutSec 15 -UseBasicParsing
    Write-Host ("status {0}, {1} bytes" -f $r.StatusCode, $r.RawContentLength) -ForegroundColor Green
    ($r.Content -split "`n" | Select-Object -First 6) | ForEach-Object { Write-Host "   $_" }
  } catch { Write-Host "FAILED: $($_.Exception.Message)" -ForegroundColor Red }
}

Section 'Restoring the previous network'
if ($before -and $before -match ':\s*(.+)$') {
  $target = $Matches[1].Trim()
  netsh wlan connect name="$target" | Out-Null
  Start-Sleep -Seconds 5
  Write-Host "reconnected to $target"
}
netsh wlan delete profile name="$Ssid" | Out-Null
