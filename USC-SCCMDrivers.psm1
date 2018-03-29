function Get-DellDriverCatalogue {
    <#
    .SYNOPSIS
        Retrieve the lates dell driver catalog from Dell's site
    .DESCRIPTION
        Download the latest dell driver catalog and cast it into an XML object and return it.
    .EXAMPLE
        PS> $XML = Get-DellDriverCatalogue
    .NOTES
        Author: Jesse Harris
    .LINK
        https://github.com/zigford/USC-SCCMDrivers
    #>
    [CmdLetBinding()]
    Param()

    $CatalogURI = 'http://downloads.dell.com/catalog/DriverPackCatalog.cab'
    $CatalogTempPath = New-Item -Path $env:temp -Name (Get-Random) -ItemType Directory
    $CatalogFilePath = "$CatalogTempPath\$($CatalogURI.Split('/')[-1])"
    Invoke-WebRequest -UseBasicParsing -Uri $CatalogURI -OutFile $CatalogFilePath
    $CatalogExtractPath = New-Item -Path $env:temp -Name DellCatalog -ItemType Directory -Force
    expand.exe $CatalogFilePath -F:*.* $CatalogExtractPath | Out-Null
    Get-ChildItem -Path $CatalogExtractPath -Filter *.cab | ForEach-Object {
            $XML = [xml](Get-Content ($_ | Rename-Item -NewName "$($_.BaseName).xml" -PassThru))

    }
    $XML
    Remove-Item -Path $CatalogTempPath -Recurse -Force
    Remove-Item -Path $CatalogExtractPath -Recurse -Force
}

function Get-DellUpdatedDriverPacks {
    <#
    .SYNOPSIS
        Get new driver packs from dell by comparing to a local cache of previously downloaded driver packs
    .DESCRIPTION
        Use other dell commands to get a list of driver packs. If a driver pack is detected as changed, download it and update the cache.
    .PARAMETER CacheFile
         Specify the file where previous driverpack information was stored
    .EXAMPLE
        Example
    .NOTES
        notes
    .LINK
        online help
#>
    [CmdLetBinding()]
    Param([Parameter(Mandatory=$True)]$CacheFile)

}

function Get-DellDriverURL {
    [CmdLetBinding()]
    Param(
        [Parameter(ValueFromPipeline=$True)]$Model,$OSVersion='Windows10',
        [Parameter(Mandatory=$True)]$XML)
    <#
        .SYNOPSIS
        Retreieve a URL for downloading Dell CAB driver packs for a model.

        .DESCRIPTION
        Takes a Dell Model name an XML of Dell's Driver catalog and output's the latest URL's for that model

        .PARAMETER Model
        A Dell model. Ie, "Precicison 5520"

        .EXAMPLE
        PS> Get-DellDriverPackUrl -Model "Precision 5520" -OSVersion "Windows10" -XML $XML
        https://dell.download.com/blahbla.cab

        .LINK
        https://github.com/zigford/USC-SCCMDrivers

        .NOTES
        Author: Jesse Harris
        Release Date: 29/03/2018
        Version: 0.1
#>
    Begin{
        # Check for valid XML
        If ($XML.GetType().Name -eq 'XmlDocument') {
            Write-Verbose "Data type is XML"
            If ($XML.DriverPackManifest.DriverPackage) {
                Write-Verbose "XML is valid from Dell"
            } else {
                Write-Error "Does not contain expected XML data"
            }
        } elseif ($XML.GetType().Name -eq 'String'){
            # Maybe it is a path to an XML
            If (Test-Path -Path $XML) {
                Try {
                    $XML = [XML](Get-Content -Path $XML -Raw)
                } catch {
                    Write-Error "File is not valid XML"
                }
                If ($XML.DriverPackManifest.DriverPackage){
                    Write-Verbose "XML is valid from Dell"
                } else {
                    Write-Error "Does not contain expected XML data"
                }
            } else {
                Write-Error "XML param is not an XML type or a path to an XML file"
            }
        }
    }
    Process {
        $DriverPackages = $XML.DriverPackManifest.DriverPackage
        $ValidOSPackages = $DriverPackages | Where-Object {
            $psItem.SupportedOperatingSystems.OperatingSystem.osCode -eq $OSVersion
        }
        Write-Verbose "$($ValidOSPackages.Count) OS matching packages found"
        $MatchingModels = $ValidOSPackages | Where-Object {
            $psItem.SupportedSystems.Brand.Model.name -eq $Model
        }
        $MatchingModels | ForEach-Object {
            [PSCustomObject]@{
                'Model' = $Model
                'Version' = $psItem.dellVersion
                'URL' = "https://download.dell.com/$($psItem.path)"
                'ReleaseDate' = (Get-Date $psItem.dateTime -Format "yyyy-MM-dd")
                'MD5' = $psItem.hashMD5
            }
        }
    }
}
