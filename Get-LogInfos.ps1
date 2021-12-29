<#
.SYNOPSIS
  Script searches log files generated with "Run-Log4jScan.ps1" for matches.
.DESCRIPTION
  Script searches log files generated with "Run-Log4jScan.psq" for matches and generates summary report file.
  Parameters need to be adjusted to match central path and summary path
.PARAMETER logDirPath
  Path containing log files to be checked.
  Default is C:\logs\
.PARAMETER summaryFilePath
  Path incl. Name for CSV-File containing summary of log files to be checked
  Default is $logDirPath\summary.csv
.EXAMPLE
  .\Get-LogInfos.ps1
  Searches C:\logs\ and generates summary.csv in C:\logs\
.EXAMPLE
  .\Get-LogInfos.ps1 -logDirPath "\\SERVER\share\"
  Searches \\SERVER\share\ and generates summary.csv in that share
.EXAMPLE
  .\Get-LogInfos.ps1 -logDirPath "\\SERVER\share\" -summaryFilePath "\\SERVER\share\$(get-date -Format yyyy-dd-MM)_summary.csv"
  Searches \\SERVER\share\ and generates summary.csv in that share with the current date
.NOTES
	Version: 0.2.2
	History:
		v.0.1.0 First running version
        v.0.2.0 Search adjusted to match "*Found CVE-202*-* vulnerability in*"
        v.0.2.1 Added Detection if search is not finished
        v.0.2.2 added dynamic Parameters for logDirPath and summaryFilePath
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [string]$logDirPath = "C:\logs\",
    [Parameter(Mandatory=$false)]
    [string]$summaryFilePath = $logDirPath+"\summary.csv"
)

Write-Host "$(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')`tStarting Script execution..." -ForegroundColor Green
Write-Output "Hostname`tSource`tMessage" | Out-File $summaryFilePath
$logs = Get-ChildItem -Path $logDirPath | Where-Object {$_.Name -like "*.log"}
Write-Host "$(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')`t$($logs.Count) Log files found. Start processing..." -ForegroundColor Green
foreach ($log in $logs) {
    Write-Host "$(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')`t$($log.Name)" -ForegroundColor Green
    $content = Get-Content -Path $($log.FullName)
    $hostname = $($($log.Name).TrimEnd(".log"))
    if ($($content[-3] -notlike "*End script*")) {
        Write-Output "$hostname`tScript`tSearch not finished" | Out-File $summaryFilePath -Append
        Write-Host "$(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')`t$($log.Name) Search not finished" -ForegroundColor Yellow
    }
    else {
        foreach ($line in $content) {
            # Scrip reported error to log file
            if ($line -like "*`tERROR`t*") {
                Write-Output "$hostname`tScript`t$line" | Out-File $summaryFilePath -Append
            }
            # Scanner reported vulnerability
            if ($line -like "*Found CVE-202*-* vulnerability in*") {
                Write-Output "$hostname`tProgram`t$line" | Out-File $summaryFilePath -Append
            }
        }
    }
}
Write-Host "$(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')`tEnd Script..." -ForegroundColor Green