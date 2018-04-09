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

function Save-DellDriverPack {
    <#
    .SYNOPSIS
        Download and verify a driver package for a model of device
    .DESCRIPTION
        Take a dell model, obtain the CAB URL from Dells Catalog, download and save it and MD5 Checksum it.
    .PARAMETER Model
        A valid dell model
    .PARAMETER OutFile
        Path and full filename to save location
    .EXAMPLE
        PS> Save-DellDriverPack -Model "Precision 5520" 

        Path                                                         Downloaded VerifySucceeded
        ----                                                         ---------- ---------------
        C:\Jesse\dev\zigford\USC-SCCMDrivers\Precision 5520-A03.cab        True            True

    .NOTES
        Author: Jesse Harris
    .LINK
        online help
    #>
    [CmdLetBinding()]
    Param(
        [Parameter(ValueFromPipelineByPropertyName=$True,ValueFromPipeline=$True)]$Model,
        [string]$OutFile,
        [string]$OutPath,
        [ValidateSet(
            "Windows10",
            "Windows7",
            "Windows8",
            "Windows8.1"
        )]$OSVersion = "Windows10",
        [int]$DownloadAttempts = 2,
        [switch]$WhatIf
    )
    Begin{
        $XML = Get-DellDriverCatalogue
    }
    Process{
	# Check if model info has been supplied by an object (ie, Get-DellDriverCabPackinfo)
        if ($Model.Model) {
            Write-Verbose "Detected Model Object"
            $ModelInfo = $Model
            $Model = $ModelInfo.Model
        } else {
            If (-Not $Model){
                Write-Error "You must specify a model"
            }
        }
        If (-Not $ModelInfo){
	    # model must have been supplied as a string. Get the DellDriverCabPackInfo using the function here
            $ModelInfo = Get-DellDriverCabPackInfo -Model $Model -XML $XML -OSVersion $OSVersion
        }
        If (-Not $OutFile) {
            # if the outfil hasn't been manually specified, let's construct it.
            If (-Not ($OutPath)){
                # if the outpath hasn't been specified, use current directory
                $OutPath = (Get-Location).Path
            }
            # Construected out file
            $OutFile = Join-Path -Path $OutPath -ChildPath "$Model-$($ModelInfo.Version).cab"
        } 
        If (-Not (Test-Path -Path (Split-Path -Path $OutFile -Parent) -ErrorAction SilentlyContinue)) {
            # make sure the outpath directory has been created
            New-Item -Path (Split-Path -Path $OutFile -Parent) -ItemType Directory -Force
        }
        Write-Verbose "Downloading Cab pack $($ModelInfo.Model)"
        $Tries = 0
        If (Test-Path -Path $OutFile) {
            Write-Verbose "File already exists."
            $FileHashMatch = Test-DellPackHash -FilePath $OutFile -Model $ModelInfo.Model -XML $XML -OSVersion $OSVersion
        }
        If (-Not $WhatIf) {
            While ($Tries -lt $DownloadAttempts -and $FileHashMatch -ne $True ){
                $Tries++
                Try {
                    Write-Verbose "Downloading $($ModelInfo.URL)"
                    Invoke-WebRequest -UseBasic -Uri $ModelInfo.URL -OutFile $OutFile
                    $FileHashMatch = Test-DellPackHash -FilePath $OutFile -Model $ModelInfo.Model -XML $XML -OSVersion $OSVersion
                    #Start-BitsTransfer -Source $ModelInfo.URL -Destination $OutFile
                } catch {
                    Write-Warning "Download attempt $Tries failed"
                }
            }
            [PSCustomObject]@{
		'Model' = $Model
                'Path' = $OutFile
                'Downloaded' = (Test-Path -Path $OutFile)
                'VerifySucceeded' = $FileHashMatch
            }    
        } else {
            Write-OutPut "WhatIf: Performing the operation ""Save File"" on target $($ModelInfo.URL) as destination file $OutFile"
        }
        # Cleanup for pipeline processing
        Remove-Variable OutFile -EA SilentlyContinue
        Remove-Variable ModelInfo -EA SilentlyContinue
        Remove-Variable FileHashMatch -EA SilentlyContinue
    }
    End{

    }
}

function Test-DellPackHash {
    <#
    .SYNOPSIS
        Verify a dell cab pack against it's MD5 hash.
    .DESCRIPTION
        Get the Dell Catalogue XML and get the cab packs hash. Use built-in Get-FileHash to confirm the hashes match
    .PARAMETER FilePath
        Path to the downloaded CAB pack to be verified
    .PARAMETER Model
        Model of cab pack and OS version to get hash for from Dell.
    .PARAMETER OSVersion
        OS Version to get hash from
    .PARAMETER CacheFile
        Path to Dell Catalogue cache file to avoid obtaining a new one.
    .EXAMPLE
        PS> Test-DellPackHash -Model 'Precision 5510' -OSVersion 'Windows10' -CacheFile .\DellCache.csv
        $True
    .NOTES
        Author: Jesse Harris
    .LINK
        online help
    #>
    [CmdLetBinding()]
    Param(
        [Parameter(Mandatory=$True)][ValidateScript({Test-Path -Path $_})]$FilePath,
        [Parameter(Mandatory=$True)]$Model,
        [ValidateSet(
            "Windows10",
            "Windows7",
            "Windows8.1",
            "Windows8"
        )][string]$OSVersion,
        [ValidateScript({Test-Path -Path $_})][string]$CacheFile,
        $XML
    )
    
    If ($CacheFile){
        $ModelInfo = Import-CSV -Path $CacheFile | Where-Object {$PSItem -eq $Model}
    } else {
        if (-Not $XML){
            $XML = Get-DellDriverCatalogue
        }
        $ModelInfo = Get-DellDriverCabPackInfo -XML $XML -Model $Model 
    }
    Write-Verbose "Testing file hash of $FilePath"
    $FileHash = Get-FileHash -Path $FilePath -Algorithm MD5
    If ($FileHash.Hash -eq $ModelInfo.MD5) {
        $True
    } else {
        $False
    }
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
    Param(
        [Parameter(ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]$Model,
        [Parameter(Mandatory=$True)]$CacheFile
    )

    Begin {
        If (-Not (Test-Path -Path $CacheFile)) {
            # Write a new cache file
            $UpdatedModels = Get-DellDriverCabPackInfo -XML (Get-DellDriverCatalogue)
            $UpdatedModels | Export-CSV -NoTypeInformation -Path $CacheFile
            $NewData = $UpdatedModels
        } else {
            Write-Verbose "Importing cachedata from $CacheFile"
            $CacheData = Import-CSV $CacheFile
            $NewData = $CacheData.Model | Get-DellDriverCabPackInfo -XML (Get-DellDriverCatalogue)
        }
    }

    Process {
        If ($Model){
            If ($Model.Model) {
                $Model = $Model.Model
            }
            Write-Debug "Only scanning for changes on $Model"
            $NewModelData = $NewData | Where-Object {$PSItem.Model -eq $Model}
        } else {
            $NewModelData = $NewData
        }
        If ($CacheData -and $NewModelData) {
            $NewModelData | Where-Object {
                $NewModel = $_.Model
                $CacheModel = $CacheData | Where-Object {$psItem.Model -eq $NewModel}
                Write-Debug "Comparing new data for model $NewModel with cache $($CacheModel.Model)"
                Compare-Object -Ref $psItem -Diff $CacheModel -Property Version
            }
        } elseif ($NewModelData) {
            $NewModelData
        }

    }
    End{

    }
}

function Get-DellDriverCabPackInfo {
    [CmdLetBinding()]
    Param(
        [Parameter(ValueFromPipeline=$True)]$Model,
        [ValidateSet(
            "Windows10",
            "Windows7",
            "Windows8",
            "Windows8.1"
        )]$OSVersion='Windows10',
        $XML=(Get-DellDriverCatalogue)
    )
    <#
        .SYNOPSIS
        Retrieve URL and other data about Driver packs for a model of Dell hardware

        .DESCRIPTION
        Takes a Dell Model name an XML of Dell's Driver catalog and output's an object containing the latest URL, MD5 sum of the CAB file, and Dell version of the driver pack.

        .PARAMETER Model
        A Dell model. Ie, "Precicison 5520"

        .EXAMPLE
        PS> Get-DellDriverPackUrl -Model "Precision 5520" -OSVersion "Windows10" -XML $XML

        Model       : Precision 5520
        Version     : A05
        URL         : https://download.dell.com/FOLDER04664035M/1/5520-win10-A05-NCVG1.CAB
        ReleaseDate : 2018-01-10
        MD5         : 0F84099B396A0381567296B72966DFC4

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
        $ValidPackages = $DriverPackages | Where-Object {
            $psItem.SupportedOperatingSystems.OperatingSystem.osCode -eq $OSVersion
        }
        If ($Model) {
            Write-Verbose "Getting driver pack info for $Model"
            $ValidPackages = $ValidPackages | Where-Object {
                $psItem.SupportedSystems.Brand.Model.name -eq $Model
            }
        }
        $ValidPackages | ForEach-Object {
	    $Package = $psItem
            $psItem.SupportedSystems.Brand.Model.name | ForEach-Object {
                [PSCustomObject]@{
                    'Model' = $_
                    'Version' = $Package.dellVersion
                    'URL' = "https://downloads.dell.com/$($Package.path)"
                    'ReleaseDate' = (Get-Date $Package.dateTime -Format "yyyy-MM-dd")
                    'MD5' = $Package.hashMD5
                }
            }
        }
    }
}

function Save-NewDriverPacks {
    [CmdLetBinding()]
    Param($ModelFile='.\models.txt',$CacheFile=".\DriverPackageCache.csv",
    $OutPath=".\",[switch]$Whatif)
    Get-Content -Path $ModelFile | Get-DellUpdatedDriverPacks -CacheFile $CacheFile | Save-DellDriverPack -OutPath $OutPath -WhatIf:$Whatif
    # Update Cache
    Get-DellDriverCabPackInfo -XML (Get-DellDriverCatalogue) | Export-CSV -Path $CacheFile -NoTypeInformation
}