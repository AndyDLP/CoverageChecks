<#
	.SYNOPSIS
		ECI Coverage check automation
	
	.DESCRIPTION
		Automatically finds and checks for the most common problems in a variety of areas
	
	.PARAMETER IgnoredServers
        An array of server names or IP addresses to ignore / not attempt to gather information
        
    .PARAMETER SendEmail
        If this flag is added, the script will try to send an email after the checks complete

    .PARAMETER TargetEmail
        Which address(s) to send the report to. Only active if SendEmail is also used

    .PARAMETER MailServer
        Which SMTP server to use. Only active if SendEmail is also used

    .PARAMETER MailPort
        Which port to use. Only active if SendEmail is also used

    .PARAMETER FromEmail
        Which address to show as FROM. Only active if SendEmail is also used

	.EXAMPLE
		PS C:\> .\RunMe.ps1 
	
    .NOTES
        Andrew de la Pole
        2019
	
    .LINK
        www.eci.com
#>
[CmdletBinding()]
Param (
    [Parameter(HelpMessage = "An array of server names (strings) to exclude from checks).")]
    [ValidateNotNullOrEmpty()]
    [string[]]$IgnoredServers = @(""),

    [Parameter(HelpMessage = "Send an email report once checks are complete")]
    [ValidateNotNullOrEmpty()]
    [switch]$SendEmail,

    [Parameter(HelpMessage = "The email address to send the report to")]
    [ValidateNotNullOrEmpty()]
    [string]$TargetEmail = "recipient@example.com",
	
    [Parameter(HelpMessage = "The SMTP relay to send the mail to / from")]
    [ValidateNotNullOrEmpty()]
	[string]$MailServer = "mail.example.com",
	
    [Parameter(HelpMessage = "The port used. Default = 25")]
    [ValidateNotNullOrEmpty()]
	[int]$MailPort = 25,
	
    [Parameter(HelpMessage = "The from email address")]
    [ValidateNotNullOrEmpty()]
	[string]$FromEmail = "ServerChecks@example.com"
)

# Convert SwitchParameter type to boolean
$OnlyShowWarnings = $OnlyShowWarnings -as [boolean]

# Check if verbose flag is set to later dump more info
$IsVerbose = $PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent

# Get PSScriptRoot on PS 2.0
if (-not $PSScriptRoot) {
    $PSScriptRoot = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
}

# Todays date in filename compatible format
$Today = (Get-Date -Format "dd-MM-yy")

# Stop any current transcript / logging & restart logging to same folder as it's run
$ErrorActionPreference = "SilentlyContinue"
Stop-Transcript | Out-Null
$ErrorActionPreference = "Continue"
Start-Transcript -Path (Join-Path -Path $PSScriptRoot -ChildPath "$Today.log") -Append

# Required modules
Import-Module ActiveDirectory -ErrorAction Stop

# Optional modules
#Import-Module FailoverClusters,VMWare.PowerCLI -ErrorAction SilentlyContinue

# Make sure that the user running script is a domain admin
# Ensures full access to all servers for full info grab
# Can replace with another administrator level group if required i.e. ServerAdmins 
$RunningUser = Get-ADUser ($env:USERNAME) -ErrorAction Stop
Write-Verbose "Script running as: $($env:USERNAME)@$($env:USERDNSDOMAIN)"
$RunningUserGroups = Get-ADGroup -LDAPFilter ("(member:1.2.840.113556.1.4.1941:={0})" -f ($RunningUser.DistinguishedName)) | Select-Object -ExpandProperty Name
If ($RunningUserGroups -Contains "Domain Admins") {
    Write-Verbose "$($env:USERNAME)@$($env:USERDNSDOMAIN) is a domain admin"
} else {
    # If user is not a domain admin then stop script
    Write-Warning "$($env:USERNAME)@$($env:USERDNSDOMAIN) is not a domain admin!"
    Write-Warning "Exiting script..."
    exit
}

########################################################
# BEGIN DEFINE FUNCTIONS

function Get-DfsrBacklog {
<#
    .SYNOPSIS
        Gets DFSR backlogs
    
    .DESCRIPTION
        Gets DFSR backlogs
    
    .PARAMETER ComputerName
        The computer to get DFSR backlogs from
    
    .EXAMPLE
        PS C:\> Get-DfsrBacklog -ComputerName DC01

        Get the backlog information from one DC
    
    .EXAMPLE
        PS C:\> $DCList = Get-ADDomainController -Filter * | Select-Object -ExpandProperty Name
        PS C:\> Get-DfsrBacklog -ComputerName $DCList | Format-Table -AutoSize

        Get backlog info from all DCs in the current domain
    
    .NOTES
        Original from the internet (unsure of exact source)
        Updated 2019-03-20 by Andy DLP
        adelapole@eci.com

    .LINK
        www.eci.com
#>
    
    [CmdletBinding(PositionalBinding = $true)]
    param
    (
        [Parameter(Mandatory = $true,
                    ValueFromPipeline = $true,
                    ValueFromPipelineByPropertyName = $true,
                    Position = 0,
                    HelpMessage = 'The computername from which to check backlog')]
        [ValidateNotNullOrEmpty()]
        [string[]]$ComputerName
    )

    begin {}

    process {
        foreach ($computer in $ComputerName) {
            Write-Verbose "Connecting to $computer"
            $RGroups = Get-WmiObject -Namespace "root\MicrosoftDFS" -Query "SELECT * FROM DfsrReplicationGroupConfig" -ComputerName $computer
            foreach ($Group in $RGroups) {
                Write-Verbose "Replication group $($Group.ReplicationGroupName)"
                $RGFoldersWMIQ = "SELECT * FROM DfsrReplicatedFolderConfig WHERE ReplicationGroupGUID='" + $Group.ReplicationGroupGUID + "'"
                $RGFolders = Get-WmiObject -Namespace "root\MicrosoftDFS" -Query  $RGFoldersWMIQ -ComputerName $computer
                $RGConnectionsWMIQ = "SELECT * FROM DfsrConnectionConfig WHERE ReplicationGroupGUID='"+ $Group.ReplicationGroupGUID + "'"
                $RGConnections = Get-WmiObject -Namespace "root\MicrosoftDFS" -Query $RGConnectionsWMIQ -ComputerName $computer
                foreach ($Connection in $RGConnections) {
                    $ConnectionName = $Connection.PartnerName#.Trim()
                    if ($Connection.Enabled -eq $True) {
                        foreach ($Folder in $RGFolders) {
                            $RGName = $Group.ReplicationGroupName
                            $RFName = $Folder.ReplicatedFolderName
                            if ($Connection.Inbound -eq $True) {
                                $SendingMember = $ConnectionName
                                $ReceivingMember = $computer
                            } else {
                                $SendingMember = $computer
                                $ReceivingMember = $ConnectionName
                            }

                            $outputObjectParams = @{
                                ComputerName = $computer
                                ReplicationGroupname = $RGName
                                SendingMember = $SendingMember
                                ReceivingMember = $ReceivingMember
                            }

                            if ((Get-Item 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion' | Get-ItemProperty).installationtype -ne 'Server Core') {
                                # Neither DFSRdiag nor DFSR diag tool are available on server core? :(
                                $BLCommand = "dfsrdiag Backlog /RGName:'" + $RGName + "' /RFName:'" + $RFName + "' /SendingMember:" + $SendingMember + " /ReceivingMember:" + $ReceivingMember
                                if ($computer -eq $env:ComputerName) {
                                    $Backlog = Invoke-Expression -Command $BLCommand
                                } else {
                                    $Backlog = Invoke-Command -ComputerName $computer -HideComputerName -ScriptBlock {
                                        $Backlog = Invoke-Expression -Command $args[0]
                                        $Backlog
                                    } -ArgumentList $BLCommand
                                }
                                $BackLogFilecount = 0
                                foreach ($item in $Backlog) {
                                    if ($item -ilike "*Backlog File count*") {
                                        $BacklogFileCount = [int]$Item.Split(":")[1].Trim()
                                    }
                                }
                                Write-Verbose "$BacklogFileCount files in backlog $SendingMember->$ReceivingMember for $RGName"
                                $outputObjectParams.Add('BacklogFileCount',$BackLogFilecount)
                            } else {
                                Write-Verbose "DFSRDIAG tool / DFSR PS cmdlets are not available on Server Core! Skipping..."
                                $outputObjectParams.Add('BacklogFileCount',-1)
                            }
                            $outputObject = [PSCustomObject]$outputObjectParams
                            $outputObject
                        } # Closing iterate through all folders
                    } # Closing  If Connection enabled
                } # Closing iteration through all connections
            } # Closing iteration through all groups
        } # foreach computer
    } # process

    end {}
}


# END DEFINE FUNCTIONS
########################################################

########################################################
# GET AD INFORMATION

# !Assumption is the environment is one forest with one root domain only!

$ThisForest = Get-ADForest

$AllDomainInfo = @()
$AllDomainObjectInfo =@()
foreach ($Domain in $ThisForest.Domains) {
    $ThisDomain = Get-ADDomain -Identity $Domain
    $AllDomainControllersPS = ( $ThisDomain.ReplicaDirectoryServers + $ThisDomain.ReadOnlyReplicaDirectoryServers ) | Get-ADDomainController
    $AllDomainControllersAD = Get-ADObject -Server $ThisDomain.PDCEmulator -Filter {ObjectClass -eq 'computer'} -SearchBase "OU=Domain Controllers,$($ThisDomain.DistinguishedName)"
    $DCRefObj = $AllDomainControllersPS | Select-Object -ExpandProperty ComputerObjectDN
    $DCDiffObj = $AllDomainControllersAD | Select-Object -ExpandProperty DistinguishedName
    $Differences = Compare-Object -ReferenceObject $DCRefObj -DifferenceObject $DCDiffObj
    $SYSVOLReplicationMode = switch ((Get-ADObject "CN=DFSR-GlobalSettings,CN=System,$($ThisDomain.DistinguishedName)" -Properties 'msDFSR-Flags').'msDFSR-Flags') {
        0 {'FRS'}
        16 {'FRS'}
        32 {'DFSR'}
        48 {'DFSR'}
        Default {'FRS'}
     }
    $ADInfoParams = @{
        ForestName = $ThisForest.Name
        DomainDNSRoot = $ThisDomain.DNSRoot
        DomainName = $ThisDomain.NetBIOSName
        ForestMode = $ThisForest.ForestMode
        DomainMode = $ThisDomain.DomainMode
        SchemaMaster = $ThisForest.SchemaMaster
        DomainNamingMaster = $ThisForest.DomainNamingMaster
        PDCEmulator = $ThisDomain.PDCEmulator
        RIDMaster = $ThisDomain.RIDMaster
        InfrastructureMaster = $ThisDomain.InfrastructureMaster
        Sites = (($ThisForest.Sites | Sort-Object) -join ', ')
        SYSVOLReplicationMode = $SYSVOLReplicationMode
    }
    if ($null -ne $Differences) {
        $ADInfoParams.Add('Notes',"MISMATCHED DC LIST: PS: $($AllDomainControllersPS | Out-String) - AD: $($AllDomainControllersAD | Out-String)")
    } else {
        # All good / do nothing
    }
    $ADInfo = [PSCustomObject]$ADInfoParams
    $AllDomainInfo = $AllDomainInfo + $ADInfo

    ##### AD Object info #####
    $DomainObjectInfoParams = @{}
    # OU no delete
    [array]$AllVulnerableOUs = Get-ADObject -Properties ProtectedFromAccidentalDeletion -Filter {(ObjectClass -eq 'organizationalUnit')} -Server $ThisDomain.PDCEmulator | Where-Object -FilterScript {$_.ProtectedFromAccidentalDeletion -eq $false} | Select-Object -ExpandProperty DistinguishedName
    
    # user no expire
    [array]$AllUsersNoExpiryPW = Get-ADUser -Filter {PasswordNeverExpires -eq $true} -Server $ThisDomain.PDCEmulator | Select-Object -ExpandProperty SamAccountName

    # reversible encryption
    [array]$AllUsersReversiblePW = Get-ADUser -Filter {AllowReversiblePasswordEncryption -eq $true} -Server $ThisDomain.PDCEmulator | Select-Object -ExpandProperty SamAccountName

    $DomainObjectInfoParams = @{
        DomainName = $ThisDomain.NetBIOSName
        OUVulnerableToAccidentalDeletion = if ($AllVulnerableOUs.count -gt 0) { ($AllVulnerableOUs -join ', ') } else { 'None - ALL OK' }
        UsersWithNoPasswordExpiry = if ($AllUsersNoExpiryPW.count -gt 0) { ($AllUsersNoExpiryPW -join ', ') } else { 'None - ALL OK' }
        UsersWithReversiblePWEncryption = if ($AllUsersReversiblePW.count -gt 0) { ($AllUsersReversiblePW -join ', ') } else { 'None - ALL OK' }
    }
    $DomainObjectInfo = [PSCustomObject]$DomainObjectInfoParams
    $AllDomainObjectInfo = $AllDomainObjectInfo + $DomainObjectInfo
} # foreach domain

# DC INFO
$AllDCInfo = @()
$FailedDCInfo = @()
$AllDCBacklogs = @()
$inc = 1

foreach ($DC in $AllDomainControllersPS) {
    Write-Verbose "Starting checks on: $($DC.Name)"
    Write-Verbose "DC: $($DC.Name) --- $inc / $($AllDomainControllersPS.count)"
    $inc++

    # Find if PC is ON and responding to WinRM
    $ServerResponding = Test-Connection -Count 1 -ComputerName $DC.Name -Quiet
    # Assume WMF / PowerShell 5.1 is installed and working and if not then set flag to false
    try {
        Test-WSMan -ComputerName $DC.Name -ErrorAction Stop | Out-Null
        $ServerWSManrunning = $true
    }
    catch { $ServerWSManrunning = $false }

    if (($ServerResponding -eq $true) -and ($ServerWSManrunning -eq $true)) {
        # Server responding fine
        try {
            $DCPSSession = New-PSSession -ComputerName $DC.name
            # Invoke it all, don't rely on the inbuilt remoting of Get-WmiObject or other cmdlets
            $OutputObjectParams = Invoke-Command -Session $DCPSSession -HideComputerName -ScriptBlock {
                $OSInfo = Get-WmiObject -Class 'win32_operatingsystem'
                $PCInfo = Get-WmiObject -Class 'win32_computersystem'
                $DiskInfo = Get-WmiObject -Class 'win32_logicaldisk' -Filter {DriveType=3}
                $ADDSDBPath = (Get-Item 'HKLM:SYSTEM\CurrentControlSet\Services\NTDS\Parameters' | Get-ItemProperty).'DSA Working Directory'
                $ADDSLogPath = (Get-Item 'HKLM:SYSTEM\CurrentControlSet\Services\NTDS\Parameters' | Get-ItemProperty).'Database log files path'
                $ADDSSYSVOLPath = (Get-Item 'HKLM:SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' | Get-ItemProperty).SYSVOL
                $IsServerCore = if ((Get-Item 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion' | Get-ItemProperty).InstallationType -eq 'Server Core') { $true } else { $false }
                $OutputObjectParams = @{
                    ComputerName = $env:COMPUTERNAME
                    OperatingSystem = $OSInfo.Caption
                    LastBootTime = $OSInfo.ConvertToDateTime($OSInfo.LastBootUpTime)
                    IsVirtual = if (($PCInfo.model -like "*virtual*") -or ($PCInfo.Manufacturer -eq 'QEMU')) {$true} else {$false}
                    IsGlobalCatalog = $args[0].IsGlobalCatalog
                    NTDSServiceStatus = (Get-Service -Name 'NTDS').Status
                    NetlogonServiceStatus = (Get-Service -Name 'Netlogon').Status
                    DNSServiceStatus = (Get-Service -Name 'DNS').Status
                    IsServerCore = $IsServerCore
                }
                foreach ($Disk in $DiskInfo) {
                    $Freespace = $Disk.FreeSpace / 1GB
                    $TotalSize = $Disk.Size / 1GB
                    $PercentFree = (($Freespace / $TotalSize) * 100)
                    # Only care about ADDS volumes
                    if ($Disk.DeviceId -eq ($ADDSDBPath -split '\\')[0]) {
                        $OutputObjectParams.Add("ADDS volume % free",([math]::round($PercentFree)))
                    }
                    if ($Disk.DeviceId -eq ($ADDSLogPath -split '\\')[0]) {
                        $OutputObjectParams.Add("ADDS log volume % free",([math]::round($PercentFree)))
                    }
                    if ($Disk.DeviceId -eq ($ADDSSYSVOLPath -split '\\')[0]) {
                        $OutputObjectParams.Add("SYSVOL volume % free",([math]::round($PercentFree)))
                    }
                }
                $OutputObjectParams
            } -ErrorAction Stop -ArgumentList $DC

            Write-Verbose "Gathering DFS backlog information from $($DC.name)"
            $DCBacklog = Invoke-Command -Session $DCPSSession -ScriptBlock ${function:Get-DfsrBacklog} -ArgumentList $DC.Name
            $DCBacklog = $DCBacklog | Select-Object -Property ComputerName,ReplicationGroupname,SendingMember,ReceivingMember,BacklogFileCount
            $AllDCBacklogs = $AllDCBacklogs + $DCBacklog

            $OutputObjectParams.Add('NetlogonAccessible',(Test-Path -Path "\\$($DC.HostName)\NETLOGON\"))
            # TODO: FIX BELOW  -  This wont work properly for a multi-domain environment...
            $OutputObjectParams.Add('SYSVOLAccessible',(Test-Path -Path "\\$($DC.HostName)\SYSVOL\$((Get-ADDomain).DNSRoot)"))

            $DCResponse = New-Object -TypeName 'PSCustomObject' -Property $OutputObjectParams
            $AllDCInfo = $AllDCInfo + $DCResponse
        } # try
        catch {
            Write-Verbose "$($DC.Name) failed"
            $FailObject = [PSCustomObject]@{
                ComputerName = $DC.HostName
                DC = $DC
                ServerResponding = $ServerResponding
                ServerWSManrunning = $ServerWSManrunning
            }
            $FailedDCInfo = $FailedDCInfo + $FailObject
        } # catch
    } else {
        Write-Verbose "$($DC.Name) failed"
        $FailObject = [PSCustomObject]@{
            ComputerName = $DC.HostName
            DC = $DC
            ServerResponding = $ServerResponding
            ServerWSManrunning = $ServerWSManrunning
        }
        $FailedDCInfo = $FailedDCInfo + $FailObject
    } # else server not responding fine
} # foreach DC


if ($IsVerbose) {
    Write-Verbose "Domain Info:"
    $AllDomainInfo | Format-Table -AutoSize
    Write-Verbose "DC Info:"
    $AllDCInfo  | Format-Table -AutoSize
    Write-Verbose "DFSR Backlogs"
    $AllDCBacklogs | Format-Table -AutoSize
}

# END AD INFORMATION
#########################################################

#########################################################
# BEGIN MAIN LOOP

# Get all Windows servers with all properties
Write-Verbose "Searching for windows servers in domain: $CurrentDomainName"
$ServerList = Get-ADComputer -Filter { (OperatingSystem -Like "Windows *Server*") } -Properties *

# incremental counter
$inc = 1

foreach ($Server in $ServerList) {
    Write-Verbose "Server: $($Server.Name) --- $inc / $($ServerList.count)"
    $inc++

    if ($IgnoredServers -notcontains $Server.Name) {
        # Server is not filtered
        Write-Verbose "Starting checks on: $($Server.Name)"

        # Find if PC is ON and responding to WinRM
        $ServerResponding = Test-Connection -Count 1 -ComputerName $Server.Name -Quiet
        # Assume WMF / PowerShell 5.1 is installed and working and if not then set flag to false
        try {
            Test-WSMan -ComputerName $Server.Name -ErrorAction Stop | Out-Null
            $ServerWSManrunning = $true
        }
        catch { $ServerWSManrunning = $false }

        if (($ServerResponding -eq $true) -and ($ServerWSManrunning -eq $true)) {
            # Server responding fine
            try {
                $ServerSSession = New-PSSession -ComputerName $Server.name
                $Response = Invoke-Command -Session $ServerSSession -HideComputerName -ScriptBlock {
                    $OutputObjectParams = @{}
                    # Run it all locally
                    $DiskInfo = Get-WmiObject -Class 'win32_logicaldisk' -Filter {DriveType=3}
                    foreach ($Disk in $DiskInfo) {
                        $Freespace = $Disk.FreeSpace / 1GB
                        $TotalSize = $Disk.Size / 1GB
                        $PercentFree = [math]::Round((($Freespace / $TotalSize) * 100))
                    }
                        

                } -ArgumentList $Server
            }
            catch {

            }
        } else {

        } # else server not responding fine
    } else {

    } # else ignored
} # main foreach

# END MAIN LOOP
##########################################################

# Stop script logging
Stop-Transcript | Out-Null