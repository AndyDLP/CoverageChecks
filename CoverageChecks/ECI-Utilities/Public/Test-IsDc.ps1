function Test-IsDC {
<#
    .SYNOPSIS
        Returns true if the computer object is a Domain Controller
    
    .DESCRIPTION
        Returns true if the computer object is a Domain Controller
    
    .PARAMETER ComputerName
        The computer name to check
    
    .EXAMPLE
        PS C:\> $IsDC = Test-IsDC -ComputerName $Server
    
    .OUTPUTS
        System.Boolean
#>
    [CmdletBinding()]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory = $false,
                   Position = 1,
                   ValueFromPipeline = $true,
                   ValueFromPipelineByPropertyName = $true,
                   HelpMessage = 'The computername to check')]
        [ValidateNotNullOrEmpty()]
        [string[]]$ComputerName = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false,
                   Position = 2,
                   HelpMessage = 'The credentials to use')]
        [PSCredential]$Credential
    )
    begin {
        $Splat = if ($Credential) { @{Credential = $Credential} } else { @{} }
    }

    process {
        foreach ($Computer in $ComputerName) {
            if ($Computer -ne $env:COMPUTERNAME) {
                if (Test-Connection -ComputerName $Computer -Quiet) {
                    try {
                        Test-WSMan -ComputerName $Computer -ErrorAction Stop | Out-Null
                        $DomainRole = Invoke-Command -ComputerName $Computer -ScriptBlock {
                            Get-WmiObject -Class 'win32_computersystem' | Select-Object -ExpandProperty DomainRole
                        } -HideComputerName -ErrorAction Stop @Splat
                    } 
                    catch {
                        $DomainRole = Get-WmiObject -Class 'win32_computersystem' -ComputerName $Computer -ErrorAction Stop @Splat | Select-Object -ExpandProperty DomainRole
                    }
                } else {
                    throw "Failed to connect to $Computer"
                }
            } else {
                $DomainRole = Get-WmiObject -Class 'win32_computersystem' @Splat | Select-Object -ExpandProperty DomainRole
            }
            if (($DomainRole -eq 4) -or ($DomainRole -eq 5)) { $true } else { $false }
        } # foreach
    } # process

    end {}
}