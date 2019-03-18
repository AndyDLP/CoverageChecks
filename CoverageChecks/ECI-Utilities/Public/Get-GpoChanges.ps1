function Get-GPOChanges {
<#
    .SYNOPSIS
        Gets a summary of changes to Group Policy
    
    .DESCRIPTION
        Gets a summary of changes to Group Policy
    
    .PARAMETER LastRunFolder
        The folder path to where the last runs XML files will be stored and checked
    
    .PARAMETER ThisRunFolder
        The folder to save the current export of GPOs as XML
    
    .EXAMPLE
        PS C:\> Get-GPOChanges -LastRunFolder $PSScriptRoot -ThisRunFolder $PSScriptRoot
    
    .OUTPUTS
        System.Array
    
    .NOTES
        Updated 2017-11-24
#>
    
    [CmdletBinding(PositionalBinding = $true)]
    [OutputType([array])]
    param
    (
        [Parameter(Mandatory = $true,
                    Position = 1,
                    HelpMessage = 'The folder path to where the last runs XML files will be stored and checked')]
        [ValidateScript({
                (Test-Path -Path $_)
            })]
        [string]
        $LastRunFolder,
        [Parameter(Mandatory = $true,
                    Position = 2,
                    HelpMessage = 'The folder to save the current export of GPOs as XML')]
        [ValidateScript({
                (Test-Path -Path $_)
            })]
        [string]
        $ThisRunFolder
    )
    
    $AllGPOs = Get-GPO -All
    Write-Verbose "Exporting current GPOs to: $ExportLocation"
    Write-Verbose ""
    $AllGPOChanges = @()
    foreach ($GPO in $AllGPOs) {
        # Export XML to export location
        $DisplayNameNoDots = ($GPo.DisplayName).Replace(".", "")
        $DisplayNameNoDots = $DisplayNameNoDots.Replace(":", "")
        $FileWithPath = Join-Path -Path $ThisRunFolder -ChildPath "$DisplayNameNoDots.xml"
        
        Write-Verbose "Original name: $($GPO.DisplayName)"
        Write-Verbose "Fixed name: $DisplayNameNoDots.xml"
        Write-Verbose "GUID: $($GPO.Id)"
        Write-Verbose "Exported path: $FileWithPath"
        
        # Create the file
        $GPO.GenerateReportToFile("xml", $FileWithPath)
        
        $CurrentGPOContent = Get-Content -Path $FileWithPath | Where-Object {
            $_ -notlike "*<ReadTime>*"
        }
        try {
            $LastGPOContent = Get-Content (Join-Path -Path $LastRunFolder -ChildPath "$DisplayNameNoDots.xml") -ErrorAction Stop | Where-Object {
                $_ -notlike "*<ReadTime>*"
            }
            $Differences = Compare-Object -ReferenceObject $LastGPOContent -DifferenceObject $CurrentGPOContent
            If (($Differences.count) -gt 0) {
                # GPO Changed
                Write-Verbose "GPO CHANGED: $($GPO.DisplayName)"
                $GPOProperties = @{
                    GPOName	    = ($GPo.DisplayName)
                    ChangeType  = "Modified"
                }
                $GPOObj = New-Object PSObject -Property $GPOProperties
                $GPOObj = $GPOObj | Select-Object GPOName, ChangeType
                $AllGPOChanges = $AllGPOChanges + $GPOObj
            } else {
                # GPO same
                Write-Verbose "No Change on $($GPO.DisplayName)"
            }
        } catch {
            # Failed find - could be new?
            Write-Verbose "Failed to find $($GPO.DisplayName)"
        }
        Write-Verbose ""
    }
    
    $LastGPOs = Get-ChildItem -Path $LastRunFolder -Name
    $NewGpos = Get-ChildItem -Path $ThisRunFolder -Name
    $Differences = Compare-Object -ReferenceObject $NewGpos -DifferenceObject $LastGPOs
    
    $NewGPOList = $Differences | Where-Object {
        $_.sideIndicator -eq "<="
    } | Select-Object InputObject -ExpandProperty InputObject
    foreach ($NewGPO in $NewGPOList) {
        $GPOProperties = @{
            GPOName	    = $NewGPO
            ChangeType  = "New"
        }
        $GPOObj = New-Object PSObject -Property $GPOProperties
        $GPOObj = $GPOObj | Select-Object GPOName, ChangeType
        $AllGPOChanges = $AllGPOChanges + $GPOObj
    }
    
    $DeletedGposList = $Differences | Where-Object {
        $_.sideIndicator -eq "=>"
    } | Select-Object InputObject -ExpandProperty InputObject
    foreach ($DeletedGPO in $DeletedGposList) {
        $GPOProperties = @{
            GPOName	    = $DeletedGPO
            ChangeType  = "Deleted"
        }
        $GPOObj = New-Object PSObject -Property $GPOProperties
        $GPOObj = $GPOObj | Select-Object GPOName, ChangeType
        $AllGPOChanges = $AllGPOChanges + $GPOObj
    }
    
    # Delete old and move current run
    Get-ChildItem -Path $LastRunFolder | Remove-Item -Include "*.xml" -Force
    Get-ChildItem -Path $ThisRunFolder | Move-Item -Destination $LastRunFolder -Force
    
    $AllGPOChanges
}