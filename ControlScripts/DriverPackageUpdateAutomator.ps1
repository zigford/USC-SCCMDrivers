[CmdletBinding()]
Param()

$isDotSourced = $MyInvocation.InvocationName -eq '.' -or $MyInvocation.Line -eq ''

function Test-CurrentAdminRights {
    #Return $True if process has admin rights, otherwise $False
    $user = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $Role = [System.Security.Principal.WindowsBuiltinRole]::Administrator
    $UserPrincipal = New-Object Security.Principal.WindowsPrincipal $User
    $IsElevated = $UserPrincipal.IsInRole($Role)
    return $IsElevated
 }

function Install-USCModule {
[CmdLetBinding()]
Param($Name)
    $RootModulePath = "$env:SystemRoot\System32\WindowsPowershell\v1.0\Modules"
    If (-Not (Test-Path -Path "$RootModulePath\$Name")) {
        Write-Verbose "Installing $Name to system context"
        Set-Location $env:SystemRoot\System32\WindowsPowershell\v1.0\Modules
        git clone https://github.com/zigford/$Name
    }
}

function Send-EmailMessage {
[CmdLetBinding()]
    Param($Message,$EmailAddress,$Subject)

    $messageParameters = @{
        Subject = $Subject
        Body = "$Message"
        To = $EmailAddress
        From = "do-not-reply@usc.edu.au"
        SmtpServer = "mail.usc.edu.au"
    }
    Send-MailMessage @messageParameters
}

function Get-ModelFromFileName {
    Param([Parameter(Mandatory=$True)]$FileName)
    $SplitName = $FileName.BaseName.Split('-')
    $Model = ""
    for ( $i=1; $i -lt $SplitName.Count - 1; $i++ ) {
        $Model += $SplitName[$i] + "-"
    }
    return $Model.TrimEnd('-')
}

function Get-ArchFromFileName {
    Param([Parameter(Mandatory=$True)]$FileName)
    $SplitName = $FileName.BaseName.Split('-')
    return $SplitName[0]
}

If (!$isDotSourced) {
    # Init Variables
    $General = '\\usc.internal\usc\appdev\General'
    $LogPath = "$General\Logs"
    $ModulePath = "$General\SCCMTools\Scripts\Modules\Dev"
    Import-Module "$ModulePath\USC-SCCMDrivers"
    $CompletedRoot = "\\usc.internal\usc\appdev\General\Packaging\CompletedPackages"
    $LogFile="$LogPath\PackageDriverAutomator.log"

    If ((Test-Path $LogFile) -and (Get-Item $LogFile).Length -gt 2097152) {
        Start-Transcript -Path $LogPath\PackageDriverAutomator.log
    } else {
        Start-Transcript -Path $LogPath\PackageDriverAutomator.log -Append
    }

    $DriverPackageDir = "$General\Packaging\DriverPackages"
    $DriverPackages = Get-ChildItem -Path $DriverPackageDir |
    Where-Object { $_.Extension -in '.cab','.zip' }
    $ErrorActionPreference = 'Stop'

    ForEach ($DriverPackage in $DriverPackages) {
        Write-Verbose "Working on $DriverPackage"
        $Architecture = Get-ArchFromFileName $DriverPackage
        $Model = Get-ModelFromFileName $DriverPackage
        $UpdateParams = @{
            Model = $Model
            DriverCab = $DriverPackage.FullName
            Architecture = $Architecture
        }
        Update-CfgDriverPackage @UpdateParams -Verbose
        $email = @{
            Message = "$DriverPackage has been updated! Check the logs at $(
                )General\Logs\PackageDriverAutomator.log"
                #EmailAddress = 'jpharris@usc.edu.au'
            EmailAddress = '330c4da0.usceduau.onmicrosoft.com@apac.teams.ms'
            #EmailAddress = '3b7f44bd.usceduau.onmicrosoft.com@apac.teams.ms'
            Subject = $DriverPackage
        }
        Send-EmailMessage @email
        Write-Verbose "Moving source files to complete folder."
        If ((pwd).path -notmatch 'c:\\') {Set-Location $env:WinDir; Write-Verbose "Had to update location to C:"}
        Move-Item $DriverPackage.FullName $CompletedRoot -Force
    }
    Stop-Transcript
}
