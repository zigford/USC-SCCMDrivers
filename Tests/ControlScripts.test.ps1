Import-Module Pester
$TestRoot = Split-Path -Path $PSScriptRoot -Parent
$ControlScripts = Join-Path -Path $TestRoot -ChildPath 'ControlScripts'
$DriverPackageUpdateAutomator = Join-Path -Path $ControlScripts -ChildPath `
    'DriverPackageUpdateAutomator.ps1'

# Dot Source the script we are testing
 
If (-Not (Test-Path -Path $DriverPackageUpdateAutomator)) {
    Write-Error "Could not locate script we are testing"
}

. "$DriverPackageUpdateAutomator"

# Tests

Describe "Get-ModelFromFileName" {
    $FileNameTests = [PSCustomObject]@{
        FileName = "Win10x64-Latitude 3380-A11.cab"
        Expected = "Latitude 3380"
    },[PSCustomObject]@{
        FileName = "Win10x64-Latitude 5300 2-in-1-A00.cab"
        Expected = "Latitude 5300 2-in-1"
    },[PSCustomObject]@{
        FileName = "Win10x64-Latitude 5300 2-IN-1-A01.cab"
        Expected = "Latitude 5300 2-IN-1"
    },[PSCustomObject]@{
        FileName = "Win10x64-Latitude 7280-A11.cab"
        Expected = "Latitude 7280"
    },[PSCustomObject]@{
        FileName = "Win10x64-Latitude 7390 2-in-1-A08.cab"
        Expected = "Latitude 7390 2-in-1"
    },[PSCustomObject]@{
        FileName = "Win10x64-Latitude 7400-A00.cab"
        Expected = "Latitude 7400"
    },[PSCustomObject]@{
        FileName = "Win10x64-Latitude E7470-A12.cab"
        Expected = "Latitude E7470"
    },[PSCustomObject]@{
        FileName = "Win10x64-OptiPlex 7460 AIO-A05.cab"
        Expected = "OptiPlex 7460 AIO"
    },[PSCustomObject]@{
        FileName = "Win10x64-XPS 13 9365-A12.cab"
        Expected = "XPS 13 9365"
    },[PSCustomObject]@{
        FileName = "Win10x64-XPS 13 9380-A03.cab"
        Expected = "XPS 13 9380"
    }
    It "returns the device model from the file object of a dell cab pack" {
        ForEach ($Test in $FileNameTests) {
            Get-ModelFromFileName -FileName ([System.IO.FileInfo]$Test.FileName) |
            Should Be $Test.Expected
        }
    }
}

Describe "Get-ArchFromFileName" {
    It "returns the arch (OsVerBitness) from a file object" {
        Get-ArchFromFileName -FileName `
            ([System.IO.FileInfo]"Win10x64-Latitude 7280-A11.cab") |
            Should Be "Win10x64"
    }
}
