function Test-IsClusterMember {
    <#
        .SYNOPSIS
            Returns true if the machine is a member of a Failover Cluster
        
        .DESCRIPTION
            Returns true if the machine is a member of a Failover Cluster
        
        .PARAMETER ComputerName
            The name of the computer to check, defaults to local machine
        
        .EXAMPLE
            PS C:\> $IsClusterMember = Get-IsClusterMember
        
        .NOTES
            Simple wrapper for Get-WMIObject directly relating to cluster membership
    #>
        
        [CmdletBinding()]
        [OutputType([boolean])]
        param
        (
            [Parameter(Mandatory = $false,
                   Position = 1,
                   ValueFromPipeline = $true,
                   ValueFromPipelineByPropertyName = $true,
                   HelpMessage = 'The name of the computer to check')]
            [ValidateNotNullOrEmpty()]
            [string[]]$ComputerName = $env:COMPUTERNAME
        )

        begin {}

        process {
            foreach ($computer in $ComputerName) {
                Write-Verbose "Computer name is: $computer"
                $ClusterWMI = Get-WMIObject -Class 'MSCluster_ResourceGroup' -ComputerName $computer -Namespace 'root\mscluster' -ErrorAction 'SilentlyContinue'
                if ($null -ne $ClusterWMI) {
                    Write-Verbose "$computer is a failover cluster member"
                    $true
                } else {
                    Write-Verbose "$computer is not a failover cluster member"
                    $false
                }
            }
        }

        end {}
    }