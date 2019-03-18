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
$PSScriptRoot = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition

# Todays date in filename compatible format
$Today = (Get-Date -Format "dd-MM-yy")

# Stop any current transcript / logging & restart logging to same folder as it's run
$ErrorActionPreference = "SilentlyContinue"
Stop-Transcript | Out-Null
$ErrorActionPreference = "Continue"
Start-Transcript -Path (Join-Path -Path $PSScriptRoot -ChildPath "Logs\$Today.log") -Append

# Required modules
Import-Module ActiveDirectory -ErrorAction Stop

# Optional modules
Import-Module FailoverClusters,VMWare.PowerCLI -ErrorAction SilentlyContinue

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
# GET AD INFORMATION

# !Assumption is thje environment is one forest with one root domain only!

$ThisForest = Get-ADForest

$AllDomainInfo = @()
foreach ($Domain in $ThisForest.Domains) {
    $ThisDomain = Get-ADDomain -Identity $Domain
    $AllDomainControllersPS = ( $ThisDomain.ReplicaDirectoryServers + $ThisDomain.ReadOnlyReplicaDirectoryServers ) | Get-ADDomainController
    $AllDomainControllersAD = Get-ADObject -Server $ThisDomain.PDCEmulator -Filter {ObjectClass -eq 'computer'} -SearchBase "OU=Domain Controllers,$($ThisDomain.DistinguishedName)"
    $DCRefObj = $AllDomainControllersPS | Select-Object -ExpandProperty ComputerObjectDN
    $DCDiffObj = $AllDomainControllersAD | Select-Object -ExpandProperty DistinguishedName
    $Differences = Compare-Object -ReferenceObject $DCRefObj -DifferenceObject $DCDiffObj
    if ($null -ne $Differences) {
        # Domain controller issues!
        # investigate!
    } else {
        # All good / do nothing
    }
    
    $ADInfo = [PSCustomObject]@{
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
        GlobalCatalogs = (($ThisForest.GlobalCatalogs | Sort-Object) -join ', ')
        Sites = (($ThisForest.Sites | Sort-Object) -join ', ')
    }
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
            $WSMANRESULTS = Test-WSMan -ComputerName $Server.Name -ErrorAction Stop
            $ServerWSManrunning = $true
        }
        catch { $ServerWSManrunning = $false }

        if (($ServerResponding -eq $true) -and ($ServerWSManrunning -eq $true)) {
            # Server responding fine

        } else {

        } # else server not responding fine
    } else {

    } # else ignored
} # main foreach

# END MAIN LOOP
##########################################################


# Stop script logging
Stop-Transcript | Out-Null