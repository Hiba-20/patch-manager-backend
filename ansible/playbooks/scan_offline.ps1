$ErrorActionPreference = "Stop"
$timestamp = Get-Date -Format "yyyyMMddHHmmss"
$resultFile = "C:\Windows\Temp\scan_result_$timestamp.json"
$cacheFile = "C:\Windows\Temp\wsus_updates_cache.json"
$cacheMaxAgeHours = 1

try {
  if (Test-Path $cacheFile) {
    $cacheAge = (Get-Date) - (Get-Item $cacheFile).LastWriteTime
    if ($cacheAge.TotalHours -lt $cacheMaxAgeHours) {
      $content = Get-Content $cacheFile -Raw
      $content | Out-File $resultFile -Force
      Write-Output "SCAN_OK_CACHED:$timestamp"
      exit 0
    }
  }
  $cab = "C:\Windows\Temp\wsusscn2.cab"
  $svcName = "ExiaOfflineScan"
  $SvcMgr = New-Object -ComObject Microsoft.Update.ServiceManager
  $SvcMgr.ClientApplicationID = "ExiaPatchManager"
  $Svc = $SvcMgr.Services | Where-Object { $_.Name -eq $svcName } | Select-Object -First 1
  if (-not $Svc) {
    $Svc = $SvcMgr.AddScanPackageService($svcName, $cab, 0)
  }

  $Session = New-Object -ComObject Microsoft.Update.Session
  $Searcher = $Session.CreateUpdateSearcher()
  $Searcher.ServiceID = $Svc.ServiceID
  $Searcher.ServerSelection = 3
  $Result = $Searcher.Search("IsInstalled=0")

  $updates = @()
  foreach ($update in $Result.Updates) {
    $kbId = ""
    if ($update.KBArticleIDs.Count -gt 0) {
      $kbId = "KB" + $update.KBArticleIDs.Item(0)
    } else {
      if ($update.Title -match '\b(KB\d{6,7})\b') {
        $kbId = $matches[1]
      }
    }
    if (-not $kbId) { continue }

    $cats = @($update.Categories | ForEach-Object { $_.Name })
    $severity = "Important"
    if ($update.MsrcSeverity -in @("Critical", "Important")) {
      $severity = $update.MsrcSeverity
    } elseif ($cats -contains "SecurityUpdates") {
      $severity = "Critical"
    } elseif ($cats -contains "CriticalUpdates") {
      $severity = "Critical"
    }

    $updates += @{
      kb_id = $kbId
      title = $update.Title
      severity = $severity
      categories = $cats
      installed = $false
      support_url = if ($update.SupportUrl) { $update.SupportUrl } else { "" }
    }
  }

  $resultObj = @{
    hostname = $env:COMPUTERNAME
    available_updates = $updates
  }
  $json = $resultObj | ConvertTo-Json -Compress -Depth 10
  $json | Out-File $resultFile -Force
  $json | Out-File $cacheFile -Force
  Write-Output "SCAN_OK:$timestamp"
} catch {
  $err = @{ error = $_.Exception.Message }
  $err | ConvertTo-Json -Compress | Out-File $resultFile -Force
  Write-Output "SCAN_FAILED: $($_.Exception.Message)"
}
