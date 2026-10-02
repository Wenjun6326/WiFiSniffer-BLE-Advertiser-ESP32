# Poll for a usable serial port (run after swapping the USB cable).
#
#   pwsh -File tools\watch-com.ps1                 # watch for 10 minutes
#   pwsh -File tools\watch-com.ps1 -Minutes 30
#
# Exits as soon as a COM port shows up, or when the timeout elapses.  Reports the
# failing USB instance id each time it changes, which tells us whether the device
# is being re-enumerated at all.

[CmdletBinding()]
param([int]$Minutes = 10, [int]$IntervalSeconds = 3)

$deadline = (Get-Date).AddMinutes($Minutes)
$lastId   = $null
$lastSig  = $null
$found    = $null

Write-Host "Watching for a serial port for $Minutes minute(s).  Plug the board in now." -ForegroundColor Cyan

while ((Get-Date) -lt $deadline) {
  $ports = @([System.IO.Ports.SerialPort]::GetPortNames() | Sort-Object)

  if ($ports.Count -gt 0) {
    $found = $ports
    break
  }

  # Report any change in the set of problem USB devices, so a re-enumeration is
  # visible even when it still fails.
  $bad = @(Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue |
           Where-Object { $_.Status -eq 'Error' -and $_.InstanceId -match 'USB\\VID_' })
  $sig = ($bad | ForEach-Object { $_.InstanceId } | Sort-Object) -join '|'
  if ($sig -ne $lastSig) {
    $lastSig = $sig
    $stamp = Get-Date -Format 'HH:mm:ss'
    if ($bad.Count -eq 0) {
      Write-Host "[$stamp] no failing USB devices" -ForegroundColor DarkGray
    } else {
      foreach ($b in $bad) {
        $loc = (Get-PnpDeviceProperty -InstanceId $b.InstanceId -KeyName 'DEVPKEY_Device_LocationInfo' -ErrorAction SilentlyContinue).Data
        Write-Host "[$stamp] FAILING: $($b.InstanceId)  at $loc" -ForegroundColor Red
      }
    }
  }
  $lastId = $sig
  Start-Sleep -Seconds $IntervalSeconds
}

Write-Host ''
if ($found) {
  Write-Host "FOUND serial port(s): $($found -join ', ')" -ForegroundColor Green
  $dev = Get-PnpDevice -PresentOnly -Class Ports -ErrorAction SilentlyContinue |
         Select-Object Status, FriendlyName, InstanceId
  if ($dev) { $dev | Format-Table -AutoSize | Out-String -Width 240 | Write-Host }
} else {
  Write-Host "Timed out with no serial port.  Last failing set: $lastSig" -ForegroundColor Yellow
  Write-Host 'If the instance id never changed, Windows saw no re-enumeration at all,' -ForegroundColor Yellow
  Write-Host 'which points at the cable, the board connector, or the CH343 chip itself.' -ForegroundColor Yellow
}
