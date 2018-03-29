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