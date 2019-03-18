function Get-StoppedServices {
<#
    .SYNOPSIS
        Gets a list of stopped auto-starting services
    
    .DESCRIPTION
        Gets a list of stopped auto-starting services
    
    .PARAMETER ComputerName
        The name of the computer to check
    
    .EXAMPLE
        PS C:\> Get-StoppedServices -ComputerName $Server.Name
    
    .OUTPUTS
        System.Array
    
    .NOTES
        Updated 2017-11-18
#>
    
    [CmdletBinding()]
    [OutputType([array])]
    param
    (
        [Parameter(Position = 1,
                    HelpMessage = 'The name of the computer to check')]
        [ValidateNotNullOrEmpty()]
        [string]
        $ComputerName = $env:COMPUTERNAME
    )
    
    $ServiceList = @()
    $AllServices = Get-WmiObject "Win32_Service" -ComputerName $ComputerName | Where-Object { (($_.State -ne "Running") -and ($_.StartMode -eq "Auto")) }
    Write-Verbose "$ComputerName has $($AllServices.count) stopped auto-starting services"
    foreach ($Service in $AllServices) {
        $ServiceProperties = @{
            ComputerName = $ComputerName
            ServiceName = $Service.Name
            ServiceStatus = $Service.State
            RunAs = $Service.StartName
        }
        $ServiceObj = New-Object PSObject -Property $ServiceProperties | Select-Object ComputerName, ServiceName, ServiceStatus, RunAs
        $ServiceList = $ServiceList + $ServiceObj
    }
    $ServiceList
}