$RootPath = "\\usc.internal\usc\appdev\General"
Start-Transcript -Path $RootPath\Logs\DriverPackageDownloadAutomator.log
Set-Location $PSScriptRoot
Import-Module $RootPath\SCCMTools\Scripts\Modules\Dev\USC-SCCMDrivers
Save-NewDriverPacks -OutPath "$RootPath\Packaging\DriverPackages" -Verbose
Stop-Transcript