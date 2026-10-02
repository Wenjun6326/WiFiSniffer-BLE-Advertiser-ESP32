# Verify the admin panel end to end.
#
#   pwsh -File tools\test_admin.ps1
#
# Joins the device's own AP, then checks that the panel refuses bad credentials
# and accepts the configured password.  The PC is put back on its previous
# network at the end.
#
# Note: `-AllowUnencryptedAuthentication` is mandatory here.  Without it
# Invoke-WebRequest refuses to send Basic credentials over plain HTTP and the
# request fails for a reason that has nothing to do with the device.

[CmdletBinding()]
param(
  [string]$Ssid     = 'Test_1101',
  [string]$Base     = 'http://192.168.4.1',
  [string]$User     = 'admin',
  [string]$Password = '1324123'
)

$ErrorActionPreference = 'Continue'

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
  for ($i = 1; $i -le 20; $i++) {
    Start-Sleep -Seconds 2
    if ((Current-Ssid) -eq $name) { return $true }
  }
  return $false
}

$original = Current-Ssid
Write-Host "currently on: $original" -ForegroundColor DarkGray

Write-Host "`n--- joining $Ssid" -ForegroundColor Cyan
if (-not (Join-Network $Ssid)) {
  Write-Host "FAILED to join $Ssid - is the board powered?" -ForegroundColor Red
  if ($original) { netsh wlan connect name="$original" | Out-Null }
  exit 1
}
Write-Host "joined $Ssid" -ForegroundColor Green
Start-Sleep -Seconds 4        # let the ESP32 hand out a DHCP lease

$bad  = New-Object System.Management.Automation.PSCredential($User, (ConvertTo-SecureString 'definitely-wrong' -AsPlainText -Force))
$good = New-Object System.Management.Automation.PSCredential($User, (ConvertTo-SecureString $Password -AsPlainText -Force))

function Try-Get([string]$url, $cred, [switch]$Raw) {
  $p = @{ Uri = $url; TimeoutSec = 15; UseBasicParsing = $true }
  if ($cred) { $p.Credential = $cred; $p.AllowUnencryptedAuthentication = $true }
  try {
    $r = Invoke-WebRequest @p
    return @{ ok = $true; status = $r.StatusCode; body = $r.Content; len = $r.RawContentLength }
  } catch {
    $code = $_.Exception.Response.StatusCode.value__
    if (-not $code) {
      # PowerShell 5.1 style: dig it out of the response
      try { $code = [int]$_.Exception.Response.StatusCode } catch { $code = 0 }
    }
    return @{ ok = $false; status = $code; err = $_.Exception.Message }
  }
}

$results = @()

Write-Host "`n--- 1. no credentials (expect 401)" -ForegroundColor Cyan
$r = Try-Get "$Base/admin/state" $null
if ($r.status -eq 401) { Write-Host "   PASS  401 as expected" -ForegroundColor Green; $results += $true }
else { Write-Host "   FAIL  got status=$($r.status) $($r.err)" -ForegroundColor Red; $results += $false }

Write-Host "`n--- 2. wrong password (expect 401)" -ForegroundColor Cyan
$r = Try-Get "$Base/admin/state" $bad
if ($r.status -eq 401) { Write-Host "   PASS  401 as expected" -ForegroundColor Green; $results += $true }
else { Write-Host "   FAIL  got status=$($r.status) $($r.err)" -ForegroundColor Red; $results += $false }

Write-Host "`n--- 3. correct password (expect 200 + state)" -ForegroundColor Cyan
$r = Try-Get "$Base/admin/state" $good
if ($r.ok) {
  Write-Host "   PASS  $($r.status)" -ForegroundColor Green
  try {
    $st = $r.body | ConvertFrom-Json
    Write-Host ("         ssid={0} ch={1} log={2}KB heap={3}KB clients={4} allframes={5}" -f `
      $st.ssid, $st.channel, $st.log_kb, $st.heap_kb, $st.clients, $st.foreign)
  } catch { Write-Host "         (state was not JSON: $($r.body))" -ForegroundColor Yellow }
  $results += $true
} else { Write-Host "   FAIL  status=$($r.status) $($r.err)" -ForegroundColor Red; $results += $false }

Write-Host "`n--- 4. admin page (expect 200)" -ForegroundColor Cyan
$r = Try-Get "$Base/admin" $good
if ($r.ok -and $r.body -match 'Test_1101') { Write-Host "   PASS  $($r.len) bytes" -ForegroundColor Green; $results += $true }
else { Write-Host "   FAIL  status=$($r.status)" -ForegroundColor Red; $results += $false }

Write-Host "`n--- 5. dashboard still public (expect 200)" -ForegroundColor Cyan
$r = Try-Get "$Base/" $null
if ($r.ok) { Write-Host "   PASS  $($r.len) bytes" -ForegroundColor Green; $results += $true }
else { Write-Host "   FAIL  status=$($r.status)" -ForegroundColor Red; $results += $false }

Write-Host "`n--- 6. toggle all-frames and read it back" -ForegroundColor Cyan
try {
  $p = @{ Uri = "$Base/admin/act"; Method = 'POST'; Credential = $good
          AllowUnencryptedAuthentication = $true; TimeoutSec = 15; UseBasicParsing = $true
          Body = 'a=foreign'; ContentType = 'application/x-www-form-urlencoded' }
  $a1 = (Invoke-WebRequest @p).Content
  $s1 = ((Try-Get "$Base/admin/state" $good).body | ConvertFrom-Json).foreign
  $a2 = (Invoke-WebRequest @p).Content      # toggle back
  $s2 = ((Try-Get "$Base/admin/state" $good).body | ConvertFrom-Json).foreign
  Write-Host "   '$a1' -> allframes=$s1" -ForegroundColor Green
  Write-Host "   '$a2' -> allframes=$s2" -ForegroundColor Green
  $results += ($s1 -ne $s2)
} catch { Write-Host "   FAIL  $($_.Exception.Message)" -ForegroundColor Red; $results += $false }

Write-Host "`n--- restoring $original" -ForegroundColor Cyan
if ($original) { netsh wlan connect name="$original" | Out-Null; Start-Sleep -Seconds 6 }
netsh wlan delete profile name="$Ssid" | Out-Null
Write-Host "now on: $(Current-Ssid)"

$pass = ($results | Where-Object { $_ }).Count
Write-Host "`n===== $pass / $($results.Count) checks passed =====" -ForegroundColor $(if ($pass -eq $results.Count) { 'Green' } else { 'Yellow' })
