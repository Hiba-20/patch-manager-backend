param([string]$kbId)

$ErrorActionPreference = "Stop"
$timestamp = Get-Date -Format "yyyyMMddHHmmss"
$resultFile = "C:\Windows\Temp\deploy_result_$timestamp.json"
try {
  $cab = "C:\Windows\Temp\wsusscn2.cab"
  $kbNum = $kbId -replace "^KB", ""

  $svcName = "ExiaOfflineDeploy"
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

  $criteria = "IsInstalled=0 and KBArticleIDs contains '" + $kbNum + "'"
  $SearchResult = $Searcher.Search($criteria)

  if ($SearchResult.Updates.Count -eq 0) {
    $AllResult = $Searcher.Search("IsInstalled=0")
    $targetUpdates = @($AllResult.Updates | Where-Object {
      $_.KBArticleIDs -contains $kbNum -or $_.Title -match "\b$kbId\b"
    })
    if ($targetUpdates.Count -eq 0) {
      throw "$kbId not found in offline catalog"
    }
    $targetUpdate = $targetUpdates[0]
  } else {
    $targetUpdate = $SearchResult.Updates.Item(0)
  }

  $UpdatesToInstall = New-Object -ComObject Microsoft.Update.UpdateCollection
  $UpdatesToInstall.Add($targetUpdate) | Out-Null

  $Downloader = $Session.CreateUpdateDownloader()
  $Downloader.Updates = $UpdatesToInstall
  $DownloadResult = $Downloader.Download()

  $Installer = $Session.CreateUpdateInstaller()
  $Installer.Updates = $UpdatesToInstall
  $InstallResult = $Installer.Install()
  $installSuccess = ($InstallResult.ResultCode -eq 2)
  $rebootRequired = $InstallResult.RebootRequired

  $resultObj = @{
    hostname = $env:COMPUTERNAME
    kb_id = $kbId
    installed = $installSuccess
    reboot_required = $rebootRequired
    found_count = 1
    installed_count = if ($installSuccess) { 1 } else { 0 }
    failed_count = if ($installSuccess) { 0 } else { 1 }
    details = "download_code=$($DownloadResult.ResultCode) install_code=$($InstallResult.ResultCode) title=$($targetUpdate.Title)"
  }
  $resultObj | ConvertTo-Json -Compress -Depth 10 | Out-File $resultFile -Force
  Write-Output "DEPLOY_OK:$timestamp"
} catch {
  $err = @{
    hostname = $env:COMPUTERNAME
    kb_id = $kbId
    installed = $false
    reboot_required = $false
    found_count = 0
    installed_count = 0
    failed_count = 1
    details = "ERROR: $($_.Exception.Message)"
  }
  $err | ConvertTo-Json -Compress | Out-File $resultFile -Force
  Write-Output "DEPLOY_FAILED: $($_.Exception.Message)"
}
