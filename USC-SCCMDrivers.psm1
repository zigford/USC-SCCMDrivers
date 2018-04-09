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
            $SupportedModels = $psItem.SupportedSystems.Brand.Model.name | Select-Object -Unique
            $SupportedModels | ForEach-Object {
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

If (-Not (Get-Command Expand-Archive -ErrorAction SilentlyContinue)) {
    #Not WMF5, implement our own expand archive
    function Expand-Archive {
    [CmdletBinding()]
    Param($Path,$DestinationPath)
        Add-Type -assembly “system.io.compression.filesystem”
        [io.compression.zipfile]::ExtractToDirectory($Path, $DestinationPath)
    }
}


function Find-ConfigManagerModulePath {
[CmdletBinding()]
Param()
    $PossibleLocations = 'C:\Program Files (x86)\Microsoft Configuration Manager\AdminConsole\bin\',
        'D:\Program Files\Microsoft Configuration Manager\AdminConsole\bin\',
        'D:\Program Files (x86)\Microsoft Configuration Manager\AdminConsole\bin\',
        'C:\Program Files\Microsoft Configuration Manager\AdminConsole\bin\'
    $i=0
    Do {
        $Result = Test-Path -Path $PossibleLocations[$i]
        $i++
        } Until ($Result -eq $True)
    return $PossibleLocations[$i-1]
}

function Extract-CfgDriverPackage {
[CmdletBinding()]
Param($DriverCAB)
$ErrorActionPreference='Stop'

    #Does the CAB exist?
    If (-Not (Test-Path -Path $DriverCAB)) {
        Write-Error "Could not access CAB/ZIP file"
    }

    $TempFolderPath = "$($env:Temp)\ExtractDriverPackage"
    If (Test-Path -Path $TempFolderPath) {
        Remove-Item -Path $TempFolderPath -Recurse -Force
    }
    $TempFolder = New-Item -Path $TempFolderPath -ItemType Directory
    Write-Verbose "Attempting to extract archive $DriverCAB to temp folder: $($TempFolder.FullName)"
    Switch ((Get-Item -Path $DriverCAB).Extension) {
      .zip { 
        Try {
            Write-Verbose "Zip file detected. Windows 10 or WMF 5 required"
            Expand-Archive -Path $DriverCAB -DestinationPath $TempFolder.FullName 
        } Catch {
            $TempFolder | Remove-Item -Force
            Write-Error "Unable to fully extract archive $DriverCAB"
        }
      }
      .cab { 
        Try {
            Write-Verbose "CAB file $DriverCAB detected. Using expand.exe"
            expand.exe $DriverCAB -F:*.* $TempFolder.FullName | Out-Null
        } Catch {
            $TempFolder | Remove-Item -Force
            Write-Error "Unable to fully expand archive $DriverCAB"
        }
      }
      default {$TempFolder | Remove-Item -Force; Write-Error "Unable to extract compressed archive"}
    }

    return $TempFolder

}

function Archive-CfgDriverStore {
[CmdletBinding()]
Param($Model,$DriverStoreRoot='\\usc.internal\usc\appdev\General\DriverStore',$Architecture='Win10x64')
    $ErrorActionPreference='Stop'

    If (-Not (Test-Path -Path "$DriverStoreRoot\$Architecture\$Model")) {
        Write-Verbose "Could not locate driverstore model $DriverStoreRoot\$Architecture\$Model"
        New-Item -Path "$DriverStoreRoot\$Architecture" -Name $Modle -ItemType Directory -Force
        $ArchiveFolder = New-Item -Path "$DriverStoreRoot\$Architecture\$Model\_Archive" -Name $FolderDate -ItemType Directory -Force
    } Else {
        $FolderDate = Get-Date -Format ddMMyyyy
        If (-Not (Test-Path -Path "$DriverStoreRoot\$Architecture\$Model\_Archive\$FolderDate")) {
            $ArchiveFolder = New-Item -Path "$DriverStoreRoot\$Architecture\$Model\_Archive" -Name $FolderDate -ItemType Directory -Force    
        } Else {
            Write-Verbose "An archive has already occured today. Lets assume it previously errored and we are trying again"
            $ArchiveFolder = Get-Item "$DriverStoreRoot\$Architecture\$Model\_Archive\$FolderDate"
            return $ArchiveFolder
        }        
        Try {
            Get-ChildItem -Path "$DriverStoreRoot\$Architecture\$Model" -Filter *.* -Exclude _Archive | Move-Item -Destination $ArchiveFolder
        } Catch {
            Write-Error "Wasn't able to archive folders in $DriverStoreRoot\$Architecture\$Model"
        }
    }

    return $ArchiveFolder

}

function Remove-CfgAllDriversFromPackage {
[CmdletBinding()]
Param($Model,$Architecture='Win10x64',$ArchiveFolder,$SiteCode='SC1',$DriverStoreRoot='\\usc.internal\usc\appdev\General\DriverStore')
    $ErrorActionPreference='Stop'
    
    Import-Module "$(Find-ConfigManagerModulePath)\ConfigurationManager.psd1" -Verbose:$False
    Push-Location
    #"$Architecture-$Model"
    Set-Location "$($SiteCode):\" -Verbose:$False
    $DriverPackage = Get-CMDriverPackage -Name "$Architecture-$Model" -Verbose:$False
    $Category = Get-CMCategory -Name "$Architecture-$Model" -Verbose:$False

    If (-Not $DriverPackage) {
        Write-Verbose "Could not find Driver Package $Architecture-$Model"
        #exit 1
    } Else {

        $OldDriverListID = @()
        #$DriverPackage.Name 
        Get-CMDriver -DriverPackageName $DriverPackage.Name -Verbose:$False| ForEach-Object {
            $DriverID = $_.CI_ID
            $DriverName = $_.LocalizedDisplayName
            $OldDriverListID += $DriverID
            Write-Verbose "Removing driver $($_.LocalizedDisplayName) from package"
            Try {
                Remove-CMDriverFromDriverPackage -DriverId $DriverID -DriverPackage $DriverPackage -Force -Verbose:$False
                #Set-CMDriver -InputObject $_ -RemoveAdministrativeCategory $Category -Verbose:$False
            } Catch {
                Write-Verbose "Failed to remove driver $DriverName content from $($DriverPackage.Name)"
            }
        }
        $SafeToDeleteDriverSources = @()
        Write-Verbose "There are $($OldDriverListID.Count) drivers which were modified. Starting to check if they are applicable to other models"
        ForEach ($DriverID in $OldDriverListID) {
            Pop-Location
            If ($ArchiveFolder.FullName) {
                $ArchiveFolderName = $ArchiveFolder.FullName
                Write-Verbose "Archive folder is an object and full name is $($ArchiveFolder.FullName)"
                If (-Not (Test-Path -Path "$($ArchiveFolder.FullName)\SafeToDelete")) {
                    $SafeToDelete = New-Item -Path $ArchiveFolder.FullName -Name SafeToDelete -ItemType Directory -Force
                } Else {
                    $SafeToDelete = Get-Item -Path "$($ArchiveFolder.FullName)\SafeToDelete"
                }
            } Else {
                $ArchiveFolderName = $ArchiveFolder
                Write-Verbose "Either ArchiveFolder is not an object or is literal path $ArchiveFolder"
                If (-Not (Test-Path -Path "$ArchiveFolder\SafeToDelete")) {
                    $SafeToDelete = New-Item -Path $ArchiveFolder -Name SafeToDelete -ItemType Directory -Force
                } Else {
                    $SafeToDelete = Get-Item -Path $ArchiveFolder\SafeToDelete
                }
            }
            $ArchiveFolderBaseName = (Get-Item $ArchiveFolder).BaseName
            Push-Location
            Set-Location "$($SiteCode):\" -Verbose:$False
            $Driver = Get-CMDriver -Id $DriverID -Verbose:$False
            $DriverName = $Driver.LocalizedDisplayName
            $CurrentDriverSource = $Driver.ContentSourcePath
            Write-Verbose "Replacing $DriverStoreRoot\$Architecture\$Model with $ArchiveFolderName out of $CurrentDriverSource"
            $NewDriverSource = $CurrentDriverSource -ireplace "$Architecture\\$Model","$Architecture\$Model\_Archive\$ArchiveFolderBaseName"
            Write-Verbose "NewDrvierSource is $NewDriverSource"
            If (($Driver.LocalizedCategoryInstanceNames).Count -gt 1) {
                Write-Verbose "Removing Category as this driver is still valid in another category"
                Try {
                    Set-CMDriver -Id $DriverID -RemoveAdministrativeCategory $Category -Verbose:$False
                } Catch {
                    Write-Error "Unable to remove administrative category from driver id $DriverID"
                }
                
                If ($CurrentDriverSource -notmatch '_Archive') {
                    #Now we must update the source location as it is now archived.
                    Write-Verbose "Updating driver source location with new archived path"
                    Try {
                        Set-CMDriver -Id $DriverID -DriverSource $NewDriverSource -Verbose:$False
                    } Catch {
                        Write-Error "Unable to update driver source to new location $NewDriverSource"
                    }
                }
            } Else {
                Write-Verbose "Removing driver $DriverName with ID $DriverID as this driver is no longer used by any other categories"
                Write-Verbose "Categories are $((Get-CMDriver -Id $DriverID -Verbose:$False).LocalizedCategoryInstanceNames)"
                Remove-CMDriver -Id $DriverID -Confirm:$False -Verbose:$False -Force
                If ($NewDriverSource -notin $SafeToDeleteDriverSources) {
                    $SafeToDeleteDriverSources += $NewDriverSource
                    Pop-Location
                    Write-Verbose "Moving $NewDriverSource content into SafeToDelete Zone"
                    If ($Drive.Drive.ToString -ne 'C') {Set-Location $env:WinDir; Write-Verbose "Had to update location to C:"}
                    #Should test if anything else has already moved it here.
                    Try {
                        Copy-Item -Path $NewDriverSource -Destination $SafeToDelete -Recurse
                        Remove-Item -Path $NewDriverSource -Confirm:$False -Recurse
                    } Catch {
                        Write-Verbose "Could not move driver to safe zone"
                    }
                }
            }
        }
    }
    Pop-Location
}

function Add-CfgNewDriversToDriverStore {
[CmdletBinding()]
Param($DriverRoot,$Architecture,$Model,$DriverStoreRoot='\\usc.internal\usc\appdev\General\DriverStore')
    Write-Verbose "DriverRoot is $DriverRoot"
    If ($DriverRoot -eq $Null -or (Test-Path -Path $DriverRoot) -eq $False) {
        Write-Error "Could not locate driver root $DriverRoot or DriverRoot variable null"
    }

    Try {
        $DriverRoot | Get-ChildItem | Move-Item -Destination "$DriverStoreRoot\$Architecture\$Model" -Force
        $DriverRoot | Remove-Item
        return "$DriverStoreRoot\$Architecture\$Model"
    } Catch {
        Write-Error "Unable to move drivers $DriverRoot to driverstore"
    }
}

function Import-CfgDriversToSCCM {
[CmdletBinding()]
Param($DriverSource,$Model,$Architecture,$SiteCode,$DriverPackageRoot)
    Push-Location

    Import-Module "$(Find-ConfigManagerModulePath)\ConfigurationManager.psd1" -Verbose:$False
    Set-Location "$($SiteCode):\" -Verbose:$False
    $CategoryName = "$Architecture-$Model"
    $Category = Get-CMCategory -Name $CategoryName -Verbose:$False
    If (-Not ($Category)) {
        Write-Verbose "Driver category $CategoryName does not exist. Creating..."
        $Category = New-CMCategory -Name $CategoryName -CategoryType DriverCategories -Verbose:$False
    }
    $DriverPackageName = $CategoryName
    $DriverPackage = Get-CMDriverPackage -Name $DriverPackageName -Verbose:$False
    If (-Not ($DriverPackage)) {
        Write-Verbose "Driver package $DriverPackageName does not exist. Creating..."
        $DriverPackage = New-CMDriverPackage -Name $DriverPackageName -Path "$DriverPackageRoot\$DriverPackageName" -Verbose:$False
    }
    Pop-Location
    $DriverFolders = Get-ChildItem -Path $DriverSource -Exclude _Archive
    Write-Verbose "Importing Drivers from $DriverSource"
    $DriverFolders | ForEach-Object {
        $i=1
        $InfFiles = Get-ChildItem -Path $_.FullName -Recurse *.inf
        $InfFiles | ForEach-Object {
        Write-Progress -Activity "Importing Drivers" -Status "Importing $($_.Name) - $i of $($InfFiles.Count)" -PercentComplete ((100 / $InfFiles.Count)*$i)
        $i++
            Try {
                Push-Location
                Set-Location "$($SiteCode):\" -Verbose:$False
                Write-Verbose "Importing $($_.FullName)"
                $Driver = Import-CMDriver -UncFileLocation $_.FullName -ImportDuplicateDriverOption AppendCategory -EnableAndAllowInstall $True -AdministrativeCategory $Category -Verbose:$False
                If ($Driver.ContentSourcePath -match '_Archive') {
                    Write-Verbose "Duplicate driver detected. Updating driver to new source path"
                    $SourcePath = Split-Path -Path $_ -Parent
                    Set-CMDriver -InputObject $Driver -DriverSource $SourcePath -Description 'Updated source location from Archive'
                }
            } Catch {
                Write-Verbose "Had trouble importing $_.Fullname"
            }
            Pop-Location
        }
        #Import-CMDriver -UncFileLocation $_.FullName -ImportFolder -ImportDuplicateDriverOption AppendCategory -EnableAndAllowInstall $True -AdministrativeCategory $Category -DriverPackage $DriverPackage
        Write-Progress -Activity "Importing Drivers" -Completed
    }
    #Now add all the drivers to the package
    Pop-Location
    Set-Location "$($SiteCode):\" -Verbose:$False
    $i = 1
    $DriversToAdd = Get-CMDriver -Verbose:$False | Where-Object {$CategoryName -in $_.LocalizedCategoryInstanceNames} 
    $DriversToAdd | ForEach-Object {
        $ObjResult = [PSCustomObject]@{
            'DriverPackage' = $DriverPackageName
            'Driver' = $_.LocalizedDisplayName
        }
        Write-Progress -Activity "Adding Drivers to package $DriverPackageName" -Status "Adding $($_.LocalizedDisplayName) - $i of $($DriversToAdd.Count)" -PercentComplete ((100 / $DriversToAdd.Count)*$i)
        Write-Verbose "Adding $($_.LocalizedDisplayName) to $DriverPackageName"
        Try {
            Add-CMDriverToDriverPackage -Driver $_ -DriverPackageName $DriverPackageName -Verbose:$False
            $ObjResult | Add-Member -MemberType NoteProperty -Name 'Imported' -Value $True -PassThru
        } catch {
            $ObjResult | Add-Member -MemberType NoteProperty -Name 'Imported' -Value $False -PassThru
        }
        $i++
    }
    Write-Progress -Activity "Adding Drivers to package $DriverPackageName" -Completed
    Pop-Location
}

function Cleanup-CfgTempFiles {
[CmdLetBinding()]
Param($DriverTemp)

    If (Test-Path -Path $DriverTemp) {
        Remove-Item -Path $DriverTemp -Recurse -Force
    }

}

function Update-CfgDriverPackage {
[CmdletBinding()]
Param($Model,$DriverCAB,$Architecture='Win10x64',$DriverStoreRoot='\\usc.internal\usc\appdev\General\DriverStore',$SiteCode='SC1',$DriverPackageRoot='\\usc.internal\usc\appdev\SCCMPackages\DriverPackages')
    $ErrorActionPreference = 'Stop'
    #Import-Module "$(Split-Path -Path $PSCommandPath -Parent)\DriverUpdateCommands.ps1"
    
    $NewDrivers = Extract-DriverPackage -DriverCAB $DriverCAB
    $ArchiveFolder = Archive-DriverStore -Model $Model -DriverStoreRoot $DriverStoreRoot -Architecture $Architecture
    #$NewDrivers = Get-Item 'C:\Users\jpharris\AppData\Local\Temp\1516192286'
    #$ArchiveFolder = Get-Item '\\usc.internal\usc\appdev\General\DriverStore\Win10x64\Surface Book\_Archive\15022016'
    Remove-AllDriversFromPackage -Architecture $Architecture -Model $Model -ArchiveFolder $ArchiveFolder -SiteCode $SiteCode -DriverStoreRoot $DriverStoreRoot
    $NewSource = Add-NewDriversToDriverStore -DriverRoot $NewDrivers -Architecture $Architecture -Model $Model -DriverStoreRoot $DriverStoreRoot
    Import-DriversToSCCM -DriverSource $NewSource -Model $Model -Architecture $Architecture -SiteCode $SiteCode -DriverPackageRoot $DriverPackageRoot
    Cleanup-TempFiles -DriverTemp $NewDrivers
}
