function Get-RecentUpdateInfo {
<#
    .SYNOPSIS
        Gets information about recent windows updates
    
    .DESCRIPTION
        Finds the last time windows updates were searched for and when the last install was.
    
    .PARAMETER ComputerName
        The name of the machine to check
    
    .PARAMETER UpToDateTime
        The amount of days that will be used when determining the UpToDate state.
    
    .EXAMPLE
        PS C:\> Get-RecentUpdateInfo -ComputerName $Server.Name
    
    .OUTPUTS
        System.Object
    
    .NOTES
        Updated 2017-11-18
#>
    
    [CmdletBinding()]
    [OutputType([object])]
    param
    (
        [Parameter(Position = 1,
                    ValueFromPipeline = $true,
                    ValueFromPipelineByPropertyName = $true,
                    Mandatory = $false,
                    HelpMessage = 'The name of the machine to check')]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName = $env:COMPUTERNAME,

        [Parameter(Position = 2,
                    HelpMessage = 'The amount of days that will be used when determining the UpToDate state.')]
        [ValidateNotNullOrEmpty()]
        [int]$UpToDateTime = 35
    )
    
    begin {}

    process {
        Write-Verbose "Computer name is: $ComputerName"
        if ($ComputerName -eq $env:COMPUTERNAME) {
            Write-Verbose "Getting update info from local machine"
            $UpdateObj = New-Object -ComObject Microsoft.Update.AutoUpdate
            
            $LastSearch = $UpdateObj.Results.LastSearchSuccessDate
            Write-Verbose "Last search: $LastSearch"
            
            #$LastInstall = $UpdateObj.Results.LastInstallationSuccessDate
            $LastInstall = Get-HotFix -ComputerName $ComputerName | Sort-Object InstalledOn -Descending | Select-Object -First 1 -ExpandProperty InstalledOn
            Write-Verbose "Last install: $LastInstall"
            
            $UpToDate = if ($LastSearch -lt (Get-Date).AddDays(-$UpToDateTime)) {
                $false
            } else {
                $true
            }
            Write-Verbose "Up to date?: $UpToDate"
            
            $UpdateProperties = @{
                ComputerName    = $ComputerName
                LastSearch	    = $LastSearch
                LastInstall	    = $LastInstall
                UpToDate	    = $UpToDate
            }
            $windowsUpdateObject = New-Object PSObject -Property $UpdateProperties
            $windowsUpdateObject = $windowsUpdateObject | Select-Object ComputerName, LastSearch, LastInstall, UpToDate
        } else {
            Write-Verbose "Getting update info from remote machine: $ComputerName"
            $windowsUpdateObject = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                $UpdateObj = New-Object -ComObject Microsoft.Update.AutoUpdate
                $LastSearch = $UpdateObj.Results.LastSearchSuccessDate
                $LastInstall = Get-HotFix -ComputerName $env:COMPUTERNAME | Sort-Object InstalledOn -Descending | Select-Object -First 1 -ExpandProperty InstalledOn
                $UpToDate = if ($LastInstall -lt (Get-Date).AddDays(-$UpToDateTime)) {
                    $false
                } else {
                    $true
                }
                $UpdateProperties = @{
                    ComputerName	 = $env:COMPUTERNAME
                    LastSearch	     = $LastSearch
                    LastInstall	     = $LastInstall
                    UpToDate		 = $UpToDate
                }
                $windowsUpdateObject = New-Object PSObject -Property $UpdateProperties
                $windowsUpdateObject
            } -HideComputerName
            $windowsUpdateObject = $windowsUpdateObject | Select-Object ComputerName, LastSearch, LastInstall, UpToDate
        }
        $windowsUpdateObject
    }

    end {}
}