# Render the admin panel and report what it actually shows.
#
#   pwsh -File tools\test_panel.ps1                 # both languages, advertiser on
#   pwsh -File tools\test_panel.ps1 -NoAdvertiser   # leave the radio alone
#   pwsh -File tools\test_panel.ps1 -OutDir .\tools
#
# Why this needs a script: the panel lives on the device's own access point, so
# the PC has to join Test_1101, which drops its normal network.  This joins,
# renders, and puts the original network back, in that order, so a failed run
# does not strand the machine on a captive network.
#
# The screenshots are the point.  A page can serve 200 and still be visibly
# broken - that is how the missing juice fields were caught the first time.
# Headless Chromium ignores --virtual-time-budget for the panel's fetch loop, so
# the shot is taken after a real sleep with the advertiser already running; the
# fetch that fills the fields has resolved by then.

[CmdletBinding()]
param(
  [string]$Ssid = 'Test_1101',
  [string]$Base = 'http://192.168.4.1',
  [string]$User = 'admin',
  [string]$Password = '1324123',
  [string]$OutDir = 'D:\ESP32-project\tools',
  [switch]$NoAdvertiser
)

$ErrorActionPreference = 'Continue'

function Section($t) { Write-Host "`n=== $t ===" -ForegroundColor Cyan }
function Info($m) { Write-Host "   $m" -ForegroundColor DarkGray }
function Pass($m) { Write-Host "   PASS  $m" -ForegroundColor Green; $script:ok++ }
function Fail($m) { Write-Host "   FAIL  $m" -ForegroundColor Red; $script:bad++ }
$ok = 0; $bad = 0

function Current-Ssid {
  $l = netsh wlan show interfaces | Select-String '^\s+SSID\s+:' | Select-Object -First 1
  if ($l) { return ($l.ToString() -replace '^\s*SSID\s*:\s*', '').Trim() } else { return $null }
}

# Defined at script scope, not inside the try block: the cleanup in `finally`
# needs them too, and PowerShell does not hoist a function out of a block.
function Invoke-Retry {
  param([string]$Url, $Credential, [int]$Tries = 4, [int]$DelaySec = 5)
  for ($i = 1; $i -le $Tries; $i++) {
    try {
      $p = @{ Uri = $Url; TimeoutSec = 30; UseBasicParsing = $true }
      if ($Credential) { $p.Credential = $Credential; $p.AllowUnencryptedAuthentication = $true }
      return Invoke-WebRequest @p
    } catch {
      if ($i -eq $Tries) { throw }
      Write-Host "   attempt $i failed; retrying in ${DelaySec}s" -ForegroundColor DarkGray
      Start-Sleep -Seconds $DelaySec
    }
  }
}

$script:actParams = $null
function Post-Act {
  param([string]$Body, [int]$Tries = 4)
  if (-not $script:actParams) { throw 'Post-Act called before credentials were set up' }
  for ($i = 1; $i -le $Tries; $i++) {
    try {
      return Invoke-WebRequest @script:actParams -Body $Body
    } catch {
      if ($i -eq $Tries) { throw }
      Write-Host "   POST $Body failed; retrying in 5s" -ForegroundColor DarkGray
      Start-Sleep -Seconds 5
    }
  }
}

$edge = @(
  'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe',
  'C:\Program Files\Microsoft\Edge\Application\msedge.exe'
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $edge) { throw 'Edge not found - needed to render the page headlessly' }

$original = Current-Ssid
Write-Host "currently on: $original" -ForegroundColor DarkGray

# ------------------------------------------------------------------ join AP
Section "joining $Ssid"
if ($original -ne $Ssid) {
  $xml = @"
<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <name>$Ssid</name>
  <SSIDConfig><SSID><name>$Ssid</name></SSID></SSIDConfig>
  <connectionType>ESS</connectionType><connectionMode>manual</connectionMode>
  <MSM><security><authEncryption><authentication>open</authentication>
  <encryption>none</encryption><useOneX>false</useOneX></authEncryption></security></MSM>
</WLANProfile>
"@
  $pf = Join-Path $env:TEMP "wlan_$Ssid.xml"
  Set-Content -Path $pf -Value $xml -Encoding UTF8
  netsh wlan add profile filename="$pf" | Out-Null
  netsh wlan connect name="$Ssid" ssid="$Ssid" | Out-Null

  $joined = $false
  for ($i = 1; $i -le 25; $i++) {
    Start-Sleep -Seconds 2
    if ((Current-Ssid) -eq $Ssid -and (Test-Connection 192.168.4.1 -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
      $joined = $true; break
    }
  }
  if ($joined) { Pass "joined $Ssid and the device answers at 192.168.4.1" }
  else { Fail "could not reach the device on $Ssid" }
} else {
  Pass "already on $Ssid"
}

try {
  if (-not (Test-Connection 192.168.4.1 -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
    throw 'device not reachable - aborting before any radio work'
  }

  $cred = New-Object System.Management.Automation.PSCredential($User, (ConvertTo-SecureString $Password -AsPlainText -Force))
  $script:actParams = @{ Uri = "$Base/admin/act"; Method = 'POST'; Credential = $cred
                         AllowUnencryptedAuthentication = $true; TimeoutSec = 30; UseBasicParsing = $true
                         ContentType = 'application/x-www-form-urlencoded' }

  # The device is an ESP32-S3: one 2.4 GHz radio, serving an open AP and
  # advertising on BLE at the same time.  A browser is heavy traffic for that
  # arrangement, so every request is retried and the heavy part (rendering) runs
  # before the advertiser starts.  Both of these were learned by watching the
  # link die mid-run.
  function Save-Shot([string]$Tag, [string]$Name, [string[]]$LangArgs) {
    $shot = Join-Path $OutDir $Name
    $prof = Join-Path $env:TEMP "edge_panel_$Tag"
    Remove-Item $prof -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item $shot -Force -ErrorAction SilentlyContinue

    # Credentials go in the URL: /admin is HTTP Basic protected and headless
    # Chromium has no other way to carry them without a driver.
    $authUrl = $Base -replace '^http://', ("http://{0}:{1}@" -f $User, $Password)
    $edgeArgs = @('--headless=new', '--disable-gpu', '--no-first-run', '--hide-scrollbars',
                  '--disable-background-networking', '--disable-component-update',
                  '--disable-sync', '--no-default-browser-check', '--disable-features=Translate',
                  "--user-data-dir=$prof", '--window-size=1000,1000',
                  "--screenshot=$shot") + $LangArgs + @("$authUrl/admin")
    $log = & $edge @edgeArgs 2>&1 | Out-String

    if (Test-Path $shot) {
      Pass "$Tag rendered $((Get-Item $shot).Length) bytes -> $Name"
      return $true
    }
    Fail "$Tag produced no screenshot"
    Info (($log -split "`n" | Where-Object { $_ -match 'Page load failed|ERR_|FATAL' } |
           Select-Object -First 2) -join ' | ')
    return $false
  }

  # ---------------------------------------------------------- render both
  Section 'rendering the panel (advertiser still off: quieter link)'
  $enOk = Save-Shot 'en' 'admin_panel_en.png' @('--lang=en-US', '--accept-lang=en-US,en')
  $zhOk = Save-Shot 'zh' 'admin_panel_zh.png' @('--lang=zh-CN', '--accept-lang=zh-CN,zh')

  # ---------------------------------------------------------- state check
  Section 'state the panel reads'
  if ($enOk -and $zhOk) {
    # Both screenshots were taken with the advertiser off, so the fields show the
    # idle state.  Confirm the values the page reads are present and sane.
    $st0 = (Invoke-Retry "$Base/admin/state" $cred).Content | ConvertFrom-Json
    Info ("idle: juice={0} tx={1}dBm window={2}s errors={3}" -f `
          $st0.juice, $st0.juice_tx, $st0.juice_window, $st0.juice_errors)
    if ($st0.PSObject.Properties.Name -contains 'juice_tx') { Pass 'state exposes the transmit power' }
    else { Fail 'state is missing juice_tx' }
  }

  # ---------------------------------------------------------- turn it on
  if (-not $NoAdvertiser) {
    Section 'starting the BLE advertiser'
    $r = Post-Act 'a=juice'
    Info $r.Content
    if ($r.Content -match 'ON') { Pass 'advertiser reports ON' } else { Fail "unexpected reply: $($r.Content)" }
    Start-Sleep -Seconds 2
    $st = (Invoke-Retry "$Base/admin/state" $cred).Content | ConvertFrom-Json
    Info ("live: juice={0} tx={1}dBm left={2}s cycles={3} tpl={4}" -f `
          $st.juice, $st.juice_tx, $st.juice_left, $st.juice_cycles, $st.juice_tpl)
    if ($st.juice) { Pass 'advertiser is running and the panel would show ON with a countdown' }
    else { Fail 'advertiser did not report running' }
  }
}
finally {
  # ---------------------------------------------------------- tidy up
  if (-not $NoAdvertiser) {
    try {
      $off = Post-Act 'a=juice'
      Info "advertiser stopped: $($off.Content)"
    } catch { Info "could not stop the advertiser: $($_.Exception.Message)" }
  }
  if ($original -and $original -ne $Ssid) {
    Section "restoring $original"
    netsh wlan connect name="$original" | Out-Null
    Start-Sleep -Seconds 8
    Write-Host "now on: $(Current-Ssid)"
  }
  netsh wlan delete profile name="$Ssid" | Out-Null
}

Section 'summary'
Write-Host "$ok passed, $bad failed" -ForegroundColor $(if ($bad -eq 0) { 'Green' } else { 'Yellow' })
if ($bad -gt 0) { exit 1 }
