function Test-IsCluster {
<#
    .SYNOPSIS
        Returns true if the computer object is a virtual cluster object
    
    .DESCRIPTION
        Returns true if the computer object is a virtual cluster object
    
    .PARAMETER ADObject
        The object returned from a Get-ADComputer query
    
    .EXAMPLE
        PS C:\> $IsCluster = Get-IsCluster -ADObject $Server
    
    .OUTPUTS
        System.Boolean
#>
    [CmdletBinding()]
    [OutputType([boolean])]
    param
    (
        [Parameter(Mandatory = $true,
                    Position = 1,
                    ValueFromPipeline = $true,
                    HelpMessage = 'The object returned from a Get-ADComputer query')]
        [ValidateScript({
                ($_.objectClass -eq "computer") -and ($null -ne $_.servicePrincipalNames)
            })]
        [Microsoft.ActiveDirectory.Management.ADComputer[]]$ADObject
    )
    begin {}

    process {
        foreach ($object in $ADObject) {
            Write-Verbose "ADObject name is: $($object.Name)"
            $return = $false
            foreach ($SPN in $object.servicePrincipalNames) {
                if ($SPN.StartsWith('MSServerCluster/')) {
                    Write-Verbose "$($object.Name) is a virtual cluster object"
                    $return = $true
                    break
                }
            }
            $return
        }
    }

    end {}
}
    