# logpressowrapper
Wrapper scripts for logpresso/CVE-2021-44228-Scanner
https://github.com/logpresso/CVE-2021-44228-Scanner

## Run-Log4jScan.ps1
Wrapper to run log4j-scan.exe as scheduled task.
Installs neccessary Microsoft Visual C++ 2015-2019 Redistributable (x64) if specified.
Latest Redistributable can be found here https://aka.ms/vs/17/release/vc_redist.x64.exe
the downloaded install file has to be in the same directory as the script.

## Get-LogInfos.ps1
automatic analysis of the log files created with Run-Log4jScan.ps1
