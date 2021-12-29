<#
.SYNOPSIS
  script to run log4j-scan.exe and search for vulnerable log4j.jar files.
  The default output path is C:\logs\<ScriptName>.log
.DESCRIPTION
  The script starts log4j2-scan.exe ((https://github.com/logpresso/CVE-2021-44228-Scanner)) in the same directory as the script and saves a log file to c:\logs\.
  defaults drive is C:\
  If needed additional parameter can be set in the scripts Variable "$log4jScanArguments" (https://github.com/logpresso/CVE-2021-44228-Scanner).
.PARAMETER folders
    specifies drives/folders to be searched. folders with white spaces need escaped quotation marks (example: "`"C:\Program Files (x86)\`""). Note the trailing '\' this is mandatory to search subdirectories as well.
.PARAMETER installVcRedist
    specifies if VC++ Redistributable v14 should be installed (VC Redist is need for log4J2-Scan.exe to be executed.)
.EXAMPLE
    .\Run-Log4jScan.ps1 -installVcRedist $true
.NOTES
	29.12.2021
    Version: 0.2.2
	History:
		v.0.1.0 first running Version, CVE-2021-44228 gets detected
        v.0.2.0 added help, log files will be overwritten
        v.0.2.1 added drives/folders as parameter
        v.0.2.2 added checks for log path, vc redist file, log4j2-scan.exe
#>

#===================================================================
#Parameter
#===================================================================
#region Parameter
#Parameter
[CmdletBinding()]
param(
[Parameter(Mandatory=$false)]
[string[]]$folders="C:\",
[Parameter(Mandatory=$false)]
[bool]$installVcRedist=$false
)
#endregion

#===================================================================
#Script variables
#===================================================================
#region scriptvariables
#Parameter
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
$log4jScan = $scriptPath+"\log4j2-scan.exe"
$log4jScanArguments = "--scan-log4j1"
$log4jScanFolders = $folders

$vcRedistSrcPath = "C:\temp\VC_redist.x64.exe"
$logDirPath = "C:\logs"

$script:logFile = Join-Path -Path $logDirPath -ChildPath "$($env:COMPUTERNAME).log"
$script:stdErrLog = Join-Path -Path $logDirPath -ChildPath "log4jScan_Err.log"
$script:stdOutLog  = Join-Path -Path $logDirPath -ChildPath "log4jScan_Std.log"
$script:scriptName = $MyInvocation.MyCommand.Name
$script:scriptVersion = "v.0.2.2"
#endregion

#==================================================================
#Function: Install-VcRedist | Install Visual C++ v14 Redistributable
#==================================================================
function Install-VcRedist ($install, $log) {
    try {
        Write-Verbose "$(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')`tStarting Installation C++ Redistributable 14.x ..."
        Write-Output "$(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')`tINFO`tStarting Installation C++ Redistributable 14.x ..." | Out-File $log -Append
        Start-Process -FilePath $install -ArgumentList "/install /quiet" -NoNewWindow -RedirectStandardOutput $script:stdOutLog -RedirectStandardError $script:stdErrLog -Wait -ErrorAction Continue
        Get-Content $script:stdErrLog, $script:stdOutLog | Out-File $log -Append
        Write-Verbose "$(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')`tInstallation finished successfully."
        Write-Output "$(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')`tINFO`tInstallation finished successfully." | Out-File $log -Append
        Remove-Item $script:stdErrLog -Force | Out-Null
        Remove-Item $script:stdOutLog -Force | Out-Null
    }
    catch {
        Write-Verbose "$(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')`tERROR`t Installation failed. Error was: $_"
        Write-Output "$(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')`tERROR`tInstallation failed. Error was: $_" | Out-File $log -Append
    }
}
#endregion

#==================================================================
#Function: Get-VcRedist | Check if Visual C++ v14 installation
#==================================================================
function Get-VcRedist ($log) {
    try {
        $items = Get-ChildItem -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\VisualStudio\14.0\VC\Runtimes -ErrorAction Stop
        Write-Verbose "$(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')`tINFO`tC++ Redistributable 14.x installed. Continue..."
        Write-Output "$(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')`tINFO`tC++ Redistributable 14.x installed. Continue..." | Out-File $log -Append
        $installed = $true
    }
    catch {
        Write-Verbose "$(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')`tERROR`tC++ Redistributable 14.x not installed."
        Write-Output "$(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')`tERROR`tC++ Redistributable 14.x ist not installed." | Out-File $log -Append
        $installed = $false
    }
    return $installed
}
#endregion

#==================================================================
#Function: Start-Log4jScan | Start scan for vulnerable log4j versions
#==================================================================
function Start-Log4jScan ($log4jScan, $folder, $arguments, $log) {
    try {
        $argumentlist = $arguments + " $folder"
        Write-Debug "$(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')`tStarte Suche unter $folder nach veralteten log4j-Versionen"
        Write-Output "$(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')`tINFO`tStarte Suche unter $folder nach veralteten log4j-Versionen" | Out-File $log -Append
        Start-Process -FilePath $log4jScan -ArgumentList $argumentList -NoNewWindow -RedirectStandardOutput $script:stdOutLog -RedirectStandardError $script:stdErrLog -Wait -ErrorAction Stop
        Get-Content $script:stdErrLog, $script:stdOutLog | Out-File $log -Append
        Write-Debug "$(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')`tScan erfolgreich abgeschlossen."
        Write-Output "$(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')`tINFO`tScan erfolgreich abgeschlossen. Logdatei unter $log ." | Out-File $log -Append
        Remove-Item $script:stdErrLog -Force | Out-Null
        Remove-Item $script:stdOutLog -Force | Out-Null
    }
    catch {
        Write-Debug "$(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')`tKonnte Scan nicht starten. Fehler: $_"
        Write-Output "$(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')`tERROR`tKonnte Scan nicht starten. Fehler: $_" | Out-File $log -Append
        $installed = $false
    }
    return $installed
}
#endregion

#region Main
Write-Debug "$(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')`tStart script $scriptName $scriptVersion`. Logd file: $logfile`."
Write-Output "$(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')`tINFO`tStart Script $scriptName $scriptVersion`. Log file $logfile`." | Out-File $logFile
$vcInstalled = Get-VcRedist $logFile
if ($vcInstalled -eq $false) {
    if ($installVcRedist -eq $true) {
        Install-VcRedist $vcRedistSrcPath $logFile
        $vcInstalled = Get-VcRedist $logFile
    }
}

if ($vcInstalled ) {
    foreach ($folder in $log4jScanFolders) {
        Start-Log4jScan $log4jScan $folder $log4jScanArguments $logFile
    }
}

Write-Debug "$(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')`tEnd script execution..."
Write-Output "$(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')`tINFO`tEnd script execution..." | Out-File $logFile -Append
Write-Output "" | Out-File $logFile -Append
Write-Output "" | Out-File $logFile -Append
#endregion main