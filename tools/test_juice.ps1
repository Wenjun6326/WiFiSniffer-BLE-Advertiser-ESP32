# Exercise the BLE advertiser added to the sniffer firmware, over serial.
#
#   pwsh -File tools\test_juice.ps1                 # auto-detect the port
#   pwsh -File tools\test_juice.ps1 -Port COM6
#   pwsh -File tools\test_juice.ps1 -WithHttp       # also check /admin/* over the AP
#
# Why serial and not the web page: this is the control path with the fewest
# moving parts.  If the radio cannot come up, or the payload cannot be set, the
# failure is visible here as an @JUICE line, which is exactly what the admin
# panel's status field would be reporting anyway.
#
# The board is reset through the CH343's DTR/RTS lines first, so the run starts
# from a known boot.  Nothing is written to flash; the advertiser is off at boot
# by construction and the auto-off test drives it for real.

[CmdletBinding()]
param(
  [string]$Port,
  [int]$RotateSeconds = 4,
  [switch]$WithHttp,
  [string]$Base = 'http://192.168.4.1',
  [string]$User = 'admin',
  [string]$Password = '1324123'
)

$ErrorActionPreference = 'Continue'

function Section($t) { Write-Host "`n=== $t ===" -ForegroundColor Cyan }
function Pass($m) { Write-Host "   PASS  $m" -ForegroundColor Green; $script:ok++ }
function Fail($m) { Write-Host "   FAIL  $m" -ForegroundColor Red; $script:bad++ }
function Info($m) { Write-Host "         $m" -ForegroundColor DarkGray }

$ok = 0; $bad = 0

# ------------------------------------------------------------------ port
if (-not $Port) {
  $cand = @([System.IO.Ports.SerialPort]::GetPortNames() | Sort-Object)
  if ($cand.Count -eq 1) { $Port = $cand[0] }
  elseif ($cand.Count -gt 1) { throw "several ports: $($cand -join ', ') - pass -Port COMx" }
  else { throw 'no COM port - is the board plugged in with a DATA cable?' }
}
Write-Host "using $Port" -ForegroundColor DarkGray

$sp = New-Object System.IO.Ports.SerialPort $Port, 115200, 'None', 8, 'One'
$sp.ReadTimeout = 250
$sp.NewLine = "`n"
$sp.DtrEnable = $false          # keep GPIO0 high: boot the sketch, not the loader

try { $sp.Open() } catch { throw "cannot open $Port : $($_.Exception.Message)" }

# Collect everything for a while; returns the accumulated text.
function Read-For([double]$seconds) {
  $sb = New-Object System.Text.StringBuilder
  $until = (Get-Date).AddSeconds($seconds)
  while ((Get-Date) -lt $until) {
    try {
      $chunk = $sp.ReadExisting()
      if ($chunk) { [void]$sb.Append($chunk) }
    } catch { }
    Start-Sleep -Milliseconds 60
  }
  return $sb.ToString()
}

function Send-Cmd([string]$text) {
  Info "-> $text"
  $sp.Write("$text`r`n")
}

$all = New-Object System.Text.StringBuilder

try {
  # ---------------------------------------------------------------- reset
  Section 'reset and boot'
  # RTS -> EN, DTR -> GPIO0 (kept low so the chip boots the sketch).
  $sp.RtsEnable = $true
  Start-Sleep -Milliseconds 150
  $sp.RtsEnable = $false
  Start-Sleep -Milliseconds 50

  $boot = Read-For 6
  [void]$all.Append($boot)
  $boot -split "`r?`n" | Where-Object { $_ -match '^@' } | Select-Object -First 14 | ForEach-Object { Info $_ }

  if ($boot -match '@READY') { Pass 'firmware booted (@READY)' } else { Fail 'no @READY after reset - is the right firmware flashed?' }
  if ($boot -match '@JUICE ') { Fail 'advertiser reported activity before being asked' } else { Pass 'advertiser silent at boot' }

  # ---------------------------------------------------------------- on
  Section 'juice=on'
  Send-Cmd '@CMD juice=on'
  $on = Read-For 4
  [void]$all.Append($on)
  $on -split "`r?`n" | Where-Object { $_ -match 'JUICE|ACK|ERR' } | ForEach-Object { Info $_ }

  if ($on -match '@JUICE ON templates=(\d+) every=(\d+)ms auto-off=(\d+)s') {
    Pass "advertising started ($($Matches[1]) templates, every $($Matches[2]) ms, auto-off $($Matches[3]) s)"
  } else {
    Fail 'no @JUICE ON line'
  }
  if ($on -match 'adv-set-failed') { Fail 'payload was rejected by the stack' }
  if ($on -match '@JUICE ERR') { Fail "firmware reported: $($Matches[0])" }

  # ---------------------------------------------------------------- rotate
  Section "rotation for $RotateSeconds s"
  Send-Cmd '@CMD juice=on'          # re-assert: exercises the already-on path
  $rot = Read-For $RotateSeconds
  [void]$all.Append($rot)
  if ($rot -match '@STAT ') {
    $stat = ($rot -split "`r?`n" | Where-Object { $_ -match '@STAT' } | Select-Object -Last 1)
    Info $stat
    if ($rot -notmatch '@JUICE OFF') { Pass 'still running while rotating' }
  } else {
    Info '(no @STAT inside the window)'
  }
  if ($rot -match '@JUICE ERR') { Fail "error during rotation: $(($rot -split "`r?`n" | Where-Object { $_ -match 'ERR' }) -join '; ')" }
  else { Pass 'no errors while rotating' }

  # ---------------------------------------------------------------- off
  Section 'juice=off'
  Send-Cmd '@CMD juice=off'
  $off = Read-For 2
  [void]$all.Append($off)
  $off -split "`r?`n" | Where-Object { $_ -match 'JUICE|ACK' } | ForEach-Object { Info $_ }
  if ($off -match '@JUICE OFF cycles=(\d+) errors=(\d+)') {
    Pass "stopped cleanly after $($Matches[1]) packets, $($Matches[2]) error(s)"
  } else {
    Fail 'no @JUICE OFF line'
  }

  # ---------------------------------------------------------------- auto-off
  Section 'auto-off watchdog'
  Info 'this one is worth doing by hand: turn it on from the admin page with a'
  Info 'phone clock in view, and confirm it stops by itself and logs "auto-off".'
  Info 'Doing it here would cost 60 s of capture for no extra information.'
} finally {
  $sp.Close()
}

# ------------------------------------------------------------------ http
if ($WithHttp) {
  Section "HTTP checks against $Base"

  # The checks need this PC on the device's own network, so join it and put the
  # original network back at the end.  Same approach as test_admin.ps1.
  function Current-Ssid {
    $line = netsh wlan show interfaces | Select-String '^\s+SSID\s+:' | Select-Object -First 1
    if (-not $line) { return $null }
    return ($line.ToString() -replace '^\s*SSID\s*:\s*', '').Trim()
  }
  function Join-Network([string]$name) {
    $xml = @"
<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <name>$name</name>
  <SSIDConfig><SSID><name>$name</name></SSID></SSIDConfig>
  <connectionType>ESS</connectionType><connectionMode>manual</connectionMode>
  <MSM><security><authEncryption><authentication>open</authentication>
  <encryption>none</encryption><useOneX>false</useOneX></authEncryption></security></MSM>
</WLANProfile>
"@
    $pf = Join-Path $env:TEMP "wlan_$name.xml"
    Set-Content -Path $pf -Value $xml -Encoding UTF8
    netsh wlan add profile filename="$pf" | Out-Null
    netsh wlan connect name="$name" ssid="$name" | Out-Null
    for ($i = 1; $i -le 15; $i++) {
      Start-Sleep -Seconds 2
      if ((Current-Ssid) -eq $name) { return $true }
    }
    return $false
  }

  $original = Current-Ssid
  Info "currently on: $original"
  if ($original -ne 'Test_1101') {
    Info 'joining Test_1101 (the device access point)...'
    if (Join-Network 'Test_1101') { Pass 'joined the device AP' }
    else { Fail 'could not join Test_1101 - is the board powered and in range?' }
    Start-Sleep -Seconds 3      # let the device hand out a lease
  }

  $good = New-Object System.Management.Automation.PSCredential($User, (ConvertTo-SecureString $Password -AsPlainText -Force))
  $anon = New-Object System.Management.Automation.PSCredential($User, (ConvertTo-SecureString 'wrong-on-purpose' -AsPlainText -Force))

  function Try-Get([string]$url, $cred) {
    $p = @{ Uri = $url; TimeoutSec = 15; UseBasicParsing = $true }
    if ($cred) { $p.Credential = $cred; $p.AllowUnencryptedAuthentication = $true }
    try { return @{ ok = $true; status = 200; body = (Invoke-WebRequest @p).Content } }
    catch {
      $c = 0; try { $c = [int]$_.Exception.Response.StatusCode } catch { }
      return @{ ok = $false; status = $c; err = $_.Exception.Message }
    }
  }

  $r = Try-Get "$Base/admin/state" $null
  if ($r.status -eq 401) { Pass '/admin/state without credentials is 401' } else { Fail "no-credential request returned $($r.status)" }

  $r = Try-Get "$Base/admin/state" $anon
  if ($r.status -eq 401) { Pass '/admin/state with a wrong password is 401' } else { Fail "wrong-password request returned $($r.status)" }

  $r = Try-Get "$Base/admin/state" $good
  if ($r.ok) {
    $st = $r.body | ConvertFrom-Json
    $fields = 'juice', 'juice_left', 'juice_cycles', 'juice_errors', 'juice_tpl', 'juice_window'
    $missing = $fields | Where-Object { -not ($st.PSObject.Properties.Name -contains $_) }
    if (-not $missing) { Pass "state exposes the advertiser fields (juice=$($st.juice), window=$($st.juice_window)s)" }
    else { Fail "state is missing: $($missing -join ', ')" }
    if ($st.juice -eq $false) { Pass 'reports OFF outside a window' } else { Info 'reports ON - someone left it running' }
  } else {
    Fail "/admin/state failed: $($r.err)"
  }

  $r = Try-Get "$Base/api" $null
  if ($r.ok -and ($r.body | ConvertFrom-Json).juice) { Pass '/api carries the public juice status the dashboard banner reads' }
  else { Fail '/api has no juice object' }
  if ($r.ok) {
    $j = ($r.body | ConvertFrom-Json)
    Info ("frames={0} servers={1} clients={2}" -f $j.frames, $j.hosts.Count, $j.clients)
  }

  # leave the PC where it was found
  if ($original -and $original -ne 'Test_1101') {
    Info "restoring $original"
    netsh wlan connect name="$original" | Out-Null
    Start-Sleep -Seconds 6
    Info "now on: $(Current-Ssid)"
  }
  netsh wlan delete profile name="Test_1101" | Out-Null
}

# ------------------------------------------------------------------ summary
Section 'captured JUICE lines'
# No literal at-sign in this pattern: inside a quoted string PowerShell still
# tries to read it as a splat, and the whole file then fails to parse.
$pattern = 'JUICE|ACK juice'
$all.ToString() -split "`r?`n" |
  Where-Object { $_ -match $pattern } |
  Select-Object -Unique |
  ForEach-Object { Write-Host "   $_" }

Write-Host ''
Write-Host "===== $ok passed, $bad failed =====" -ForegroundColor $(if ($bad -eq 0) { 'Green' } else { 'Yellow' })
if ($bad -gt 0) { exit 1 }
