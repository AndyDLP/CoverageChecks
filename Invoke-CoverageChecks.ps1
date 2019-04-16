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
		PS C:\> .\Invoke-CoverageChecks.ps1  -Verbose
	
    .NOTES
        Andrew de la Pole - 2019
        Version 0.9.0
#>
[CmdletBinding()]
Param (
    [Parameter(HelpMessage = "The path to the configuration file")]
    [ValidateScript( { Test-Path -Path $_ } )]
    [string]$ConfigFile = "$PSScriptRoot\Invoke-CoverageChecks.config.ps1"
)

########################################################
# BEGIN DEFINE FUNCTIONS

function Write-Log {
<#
    .SYNOPSIS
        Write to a log file
    
    .DESCRIPTION
        Write to a log file with various options
    
    .PARAMETER Text
        The text to add to the log file
    
    .PARAMETER Type
        The log type, can be WARNING, ERROR or INFO
    
    .PARAMETER Log
        The path to the log file (does not have to exist yet)
    
    .EXAMPLE
        PS C:\> Write-Log -Log $LogFilePath -Type INFO -Text 'This is an informational log entry'
    
    .NOTES
        Original from the internet (unsure of exact source)
        Updated 2019-04-13 by Andy DLP
#>
    [CmdletBinding()]
    param(
    [parameter(Mandatory=$true,
               ValueFromPipeline = $true,
               Position = 2)]
    [string]$Text,
    [parameter(Mandatory=$false,
               Position = 1)]
    [ValidateSet('WARNING','ERROR','INFO')]
    [string]$Type = 'INFO',
    [parameter(Mandatory=$true,
               Position = 0)]
    [ValidateScript( { Test-Path -Path $_ -IsValid } )]
    [string]$Log
    )

    begin {}

    process {
        $logMessage = @((Get-Date).ToString(),'-',$Type,':',$Text) -join ' '
        Add-Content -Path $log -Value $logMessage
    }

    end {}
}

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
        [int]$UpToDateTime = 180
    )
    
    begin {}

    process {
        Write-Verbose "Computer name is: $ComputerName"
        if ($ComputerName -eq $env:COMPUTERNAME) {
            Write-Verbose "Getting update info from local machine"
            $UpdateObj = New-Object -ComObject Microsoft.Update.AutoUpdate
            $LastSearch = $UpdateObj.Results.LastSearchSuccessDate
            $LastInstall = $UpdateObj.Results.LastInstallationSuccessDate
            $UpToDate = if ($LastInstall -lt (Get-Date).AddDays(-$UpToDateTime)) { $false } else { $true }
            $windowsUpdateObject = [PSCustomObject]@{
                ComputerName    = $env:COMPUTERNAME
                LastSearch	    = $LastSearch
                LastInstall	    = $LastInstall
                UpToDate	    = $UpToDate
            }
            $windowsUpdateObject = $windowsUpdateObject | Select-Object ComputerName, LastSearch, LastInstall, UpToDate
        } else {
            Write-Verbose "Getting update info from remote machine: $ComputerName"
            $windowsUpdateObject = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                $UpdateObj = New-Object -ComObject Microsoft.Update.AutoUpdate
                $LastSearch = $UpdateObj.Results.LastSearchSuccessDate
                $LastInstall = Get-HotFix -ComputerName $env:COMPUTERNAME | Sort-Object InstalledOn -Descending | Select-Object -First 1 -ExpandProperty InstalledOn
                $UpToDate = if ($LastInstall -lt (Get-Date).AddDays(-$UpToDateTime)) { $false } else { $true }
                $windowsUpdateObject = [PSCustomObject]@{
                    ComputerName    = $env:COMPUTERNAME
                    LastSearch	    = $LastSearch
                    LastInstall	    = $LastInstall
                    UpToDate	    = $UpToDate
                }
                $windowsUpdateObject
            } -HideComputerName
            $windowsUpdateObject = $windowsUpdateObject | Select-Object ComputerName, LastSearch, LastInstall, UpToDate
        }
        $windowsUpdateObject
    }

    end {}
}

function Get-PendingReboot {
    <#
    .SYNOPSIS
        Gets the pending reboot status on a local or remote computer.
    
    .DESCRIPTION
        This function will query the registry on a local or remote computer and determine if the
        system is pending a reboot, from Microsoft updates, Configuration Manager Client SDK, Pending Computer 
        Rename, Domain Join or Pending File Rename Operations. For Windows 2008+ the function will query the 
        CBS registry key as another factor in determining pending reboot state.  "PendingFileRenameOperations" 
        and "Auto Update\RebootRequired" are observed as being consistant across Windows Server 2003 & 2008.
        
        CBServicing = Component Based Servicing (Windows 2008+)
        WindowsUpdate = Windows Update / Auto Update (Windows 2003+)
        CCMClientSDK = SCCM 2012 Clients only (DetermineIfRebootPending method) otherwise $null value
        PendComputerRename = Detects either a computer rename or domain join operation (Windows 2003+)
        PendFileRename = PendingFileRenameOperations (Windows 2003+)
        PendFileRenVal = PendingFilerenameOperations registry value; used to filter if need be, some Anti-
                         Virus leverage this key for def/dat removal, giving a false positive PendingReboot
    
    .PARAMETER ComputerName
        A single Computer or an array of computer names.  The default is localhost ($env:COMPUTERNAME).
    
    .PARAMETER ErrorLog
        A single path to send error data to a log file.
    
    .EXAMPLE
        PS C:\> Get-PendingReboot -ComputerName (Get-Content C:\ServerList.txt) | Format-Table -AutoSize
        
        Computer CBServicing WindowsUpdate CCMClientSDK PendFileRename PendFileRenVal RebootPending
        -------- ----------- ------------- ------------ -------------- -------------- -------------
        DC01           False         False                       False                        False
        DC02           False         False                       False                        False
        FS01           False         False                       False                        False
    
        This example will capture the contents of C:\ServerList.txt and query the pending reboot
        information from the systems contained in the file and display the output in a table. The
        null values are by design, since these systems do not have the SCCM 2012 client installed,
        nor was the PendingFileRenameOperations value populated.
    
    .EXAMPLE
        PS C:\> Get-PendingReboot
        
        Computer           : WKS01
        CBServicing        : False
        WindowsUpdate      : True
        CCMClient          : False
        PendComputerRename : False
        PendFileRename     : False
        PendFileRenVal     : 
        RebootPending      : True
        
        This example will query the local machine for pending reboot information.
        
    .EXAMPLE
        PS C:\> $Servers = Get-Content C:\Servers.txt
        PS C:\> Get-PendingReboot -Computer $Servers | Export-Csv C:\PendingRebootReport.csv -NoTypeInformation
        
        This example will create a report that contains pending reboot information.
    
    .LINK
        Component-Based Servicing:
        http://technet.microsoft.com/en-us/library/cc756291(v=WS.10).aspx
        
        PendingFileRename/Auto Update:
        http://support.microsoft.com/kb/2723674
        http://technet.microsoft.com/en-us/library/cc960241.aspx
        http://blogs.msdn.com/b/hansr/archive/2006/02/17/patchreboot.aspx
    
        SCCM 2012/CCM_ClientSDK:
        http://msdn.microsoft.com/en-us/library/jj902723.aspx
    
    .NOTES
        Author:  Brian Wilhite
        Email:   bcwilhite (at) live.com
        Date:    29AUG2012
        PSVer:   2.0/3.0/4.0/5.0
        Updated: 27JUL2015
        UpdNote: Added Domain Join detection to PendComputerRename, does not detect Workgroup Join/Change
                 Fixed Bug where a computer rename was not detected in 2008 R2 and above if a domain join occurred at the same time.
                 Fixed Bug where the CBServicing wasn't detected on Windows 10 and/or Windows Server Technical Preview (2016)
                 Added CCMClient property - Used with SCCM 2012 Clients only
                 Added ValueFromPipelineByPropertyName=$true to the ComputerName Parameter
                 Removed $Data variable from the PSObject - it is not needed
                 Bug with the way CCMClientSDK returned null value if it was false
                 Removed unneeded variables
                 Added PendFileRenVal - Contents of the PendingFileRenameOperations Reg Entry
                 Removed .Net Registry connection, replaced with WMI StdRegProv
                 Added ComputerPendingRename
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Position=0,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [Alias("CN","Computer")]
        [String[]]$ComputerName="$env:COMPUTERNAME",
        [String]$ErrorLog
        )
    
    Begin {}## End Begin Script Block
    
    Process {
      Foreach ($Computer in $ComputerName) {
        Try {
            ## Setting pending values to false to cut down on the number of else statements
            $CompPendRen,$PendFileRename,$Pending,$SCCM = $false,$false,$false,$false
                            
            ## Setting CBSRebootPend to null since not all versions of Windows has this value
            $CBSRebootPend = $null
                            
            ## Querying WMI for build version
            $WMI_OS = Get-WmiObject -Class Win32_OperatingSystem -Property BuildNumber, CSName -ComputerName $Computer -ErrorAction Stop
    
            ## Making registry connection to the local/remote computer
            $HKLM = [UInt32] "0x80000002"
            $WMI_Reg = [WMIClass] "\\$Computer\root\default:StdRegProv"
                            
            ## If Vista/2008 & Above query the CBS Reg Key
            If ([Int32]$WMI_OS.BuildNumber -ge 6001) {
                $RegSubKeysCBS = $WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\")
                $CBSRebootPend = $RegSubKeysCBS.sNames -contains "RebootPending"		
            }
                                
            ## Query WUAU from the registry
            $RegWUAURebootReq = $WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\")
            $WUAURebootReq = $RegWUAURebootReq.sNames -contains "RebootRequired"
                            
            ## Query PendingFileRenameOperations from the registry
            $RegSubKeySM = $WMI_Reg.GetMultiStringValue($HKLM,"SYSTEM\CurrentControlSet\Control\Session Manager\","PendingFileRenameOperations")
            $RegValuePFRO = $RegSubKeySM.sValue
    
            ## Query JoinDomain key from the registry - These keys are present if pending a reboot from a domain join operation
            $Netlogon = $WMI_Reg.EnumKey($HKLM,"SYSTEM\CurrentControlSet\Services\Netlogon").sNames
            $PendDomJoin = ($Netlogon -contains 'JoinDomain') -or ($Netlogon -contains 'AvoidSpnSet')
    
            ## Query ComputerName and ActiveComputerName from the registry
            $ActCompNm = $WMI_Reg.GetStringValue($HKLM,"SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName\","ComputerName")            
            $CompNm = $WMI_Reg.GetStringValue($HKLM,"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName\","ComputerName")
    
            If (($ActCompNm -ne $CompNm) -or $PendDomJoin) {
                $CompPendRen = $true
            }
                            
            ## If PendingFileRenameOperations has a value set $RegValuePFRO variable to $true
            If ($RegValuePFRO) {
                $PendFileRename = $true
            }
    
            ## Determine SCCM 2012 Client Reboot Pending Status
            ## To avoid nested 'if' statements and unneeded WMI calls to determine if the CCM_ClientUtilities class exist, setting EA = 0
            $CCMClientSDK = $null
            $CCMSplat = @{
                NameSpace='ROOT\ccm\ClientSDK'
                Class='CCM_ClientUtilities'
                Name='DetermineIfRebootPending'
                ComputerName=$Computer
                ErrorAction='Stop'
            }
            ## Try CCMClientSDK
            Try {
                $CCMClientSDK = Invoke-WmiMethod @CCMSplat
            } Catch [System.UnauthorizedAccessException] {
                $CcmStatus = Get-Service -Name CcmExec -ComputerName $Computer -ErrorAction SilentlyContinue
                If ($CcmStatus.Status -ne 'Running') {
                    Write-Warning "$Computer`: Error - CcmExec service is not running."
                    $CCMClientSDK = $null
                }
            } Catch {
                $CCMClientSDK = $null
            }
    
            If ($CCMClientSDK) {
                If ($CCMClientSDK.ReturnValue -ne 0) {
                    Write-Warning "Error: DetermineIfRebootPending returned error code $($CCMClientSDK.ReturnValue)"          
                }
                If ($CCMClientSDK.IsHardRebootPending -or $CCMClientSDK.RebootPending) {
                    $SCCM = $true
                }
            }
                
            Else {
                $SCCM = $null
            }
    
            ## Creating Custom PSObject and Select-Object Splat
            $SelectSplat = @{
                Property=(
                    'Computer',
                    'CBServicing',
                    'WindowsUpdate',
                    'CCMClientSDK',
                    'PendComputerRename',
                    'PendFileRename',
                    #'PendFileRenVal',
                    'RebootPending'
                )}
            New-Object -TypeName PSObject -Property @{
                Computer=$WMI_OS.CSName
                CBServicing=$CBSRebootPend
                WindowsUpdate=$WUAURebootReq
                CCMClientSDK=$SCCM
                PendComputerRename=$CompPendRen
                PendFileRename=$PendFileRename
                #PendFileRenVal=$RegValuePFRO
                RebootPending=($WUAURebootReq -or $SCCM -or $CBSRebootPend)
            } | Select-Object @SelectSplat
    
        } Catch {
            Write-Warning "$Computer`: $_"
            ## If $ErrorLog, log the file to a user specified location/path
            If ($ErrorLog) {
                Out-File -InputObject "$Computer`,$_" -FilePath $ErrorLog -Append
            }				
        }			
      }## End Foreach ($Computer in $ComputerName)			
    }## End Process

    End {}## End End
}

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
        System.Management.Automation.PSCustomObject
    
    .NOTES
        Updated 2017-11-24
#>
    
    [CmdletBinding(PositionalBinding = $true)]
    [OutputType([PSCustomObject])]
    param
    (
        [Parameter(Mandatory = $true,
                    Position = 0,
                    HelpMessage = 'The folder path to where the last runs XML files will be stored and checked')]
        [ValidateScript({ Test-Path -Path $_ })]
        [string]$LastRunFolder,
        [Parameter(Mandatory = $true,
                    Position = 1,
                    HelpMessage = 'The folder to save the current export of GPOs as XML')]
        [ValidateScript({ Test-Path -Path $_ })]
        [string]$ThisRunFolder
    )
    
    begin {
    }

    process {
        $AllGPOs = Get-GPO -All
        Write-Verbose "Exporting current GPOs to: $ThisRunFolder"
        foreach ($GPO in $AllGPOs) {
            # Export XML to export location
            $DisplayNameNoDots = ($GPo.DisplayName).Replace(".", "")
            $DisplayNameNoDots = $DisplayNameNoDots.Replace(":", "")
            $DisplayNameNoDots = $DisplayNameNoDots.Replace("\", "")
            $DisplayNameNoDots = $DisplayNameNoDots.Replace("/", "")
            $DisplayNameNoDots = $DisplayNameNoDots.Replace("?", "")
            $DisplayNameNoDots = $DisplayNameNoDots.Replace("<", "")
            $DisplayNameNoDots = $DisplayNameNoDots.Replace(">", "")
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
                if ($null -eq $CurrentGPOContent) { $CurrentGPOContent = "" }
                if ($null -eq $LastGPOContent) { $LastGPOContent = "" }
                $Differences = Compare-Object -ReferenceObject $LastGPOContent -DifferenceObject $CurrentGPOContent
                If (($Differences.count) -gt 0) {
                    # GPO Changed
                    Write-Verbose "GPO CHANGED: $($GPO.DisplayName)"
                    $GPOObj = [PSCustomObject]@{
                        GPOName	    = ($GPo.DisplayName)
                        ChangeType  = "Modified"
                    }
                    $GPOObj
                } else {
                    # GPO same
                    Write-Verbose "No Change on $($GPO.DisplayName)"
                }
            } catch {
                # Failed find - could be new?
                Write-Verbose "Failed to find $($GPO.DisplayName)"
            }
        }
        
        $LastGPOs = Get-ChildItem -Path $LastRunFolder | Select-Object -ExpandProperty Name
        $NewGpos = Get-ChildItem -Path $ThisRunFolder | Select-Object -ExpandProperty Name

        # Delete old and move current run
        Get-ChildItem -Path $LastRunFolder | Remove-Item -Include "*.xml" -Force
        Get-ChildItem -Path $ThisRunFolder | Move-Item -Destination $LastRunFolder -Force

        if ($null -eq $NewGpos) { $NewGpos = @("") }
        if ($null -eq $LastGPOs) { $LastGPOs = @("") }
        $Differences = Compare-Object -ReferenceObject $NewGpos -DifferenceObject $LastGPOs

        $NewGPOList = $Differences | Where-Object {
            $_.sideIndicator -eq "<="
        } | Select-Object InputObject -ExpandProperty InputObject
        foreach ($NewGPO in $NewGPOList) {
            $GPOObj = [PSCustomObject]@{
                GPOName	    = $NewGPO
                ChangeType  = "New"
            }
            $GPOObj
        }
        
        $DeletedGposList = $Differences | Where-Object {
            $_.sideIndicator -eq "=>"
        } | Select-Object InputObject -ExpandProperty InputObject
        foreach ($DeletedGPO in $DeletedGposList) {
            $GPOObj = [PSCustomObject]@{
                GPOName	    = $DeletedGPO
                ChangeType  = "Deleted"
            }
            $GPOObj
        }
    }
    
    end {
    }
}

function Format-HTMLTable {
    <#
        .SYNOPSIS
            Format HTML table
        
        .DESCRIPTION
            Format HTML table with conditonal formatting
        
        .PARAMETER Data
            The data to format
        
        .PARAMETER Category
            The category of the data
        
        .PARAMETER ConditionalFormatting
            The conditional formatting
        
        .EXAMPLE
            PS C:\> Format-HTMLTable -Data (Get-Service) -Category 'DFSRBacklogs' -ConditionalFormatting $CF
        
        .NOTES
            Updated 2019-04-14 by Andy DLP
    #>
    [CmdletBinding()]
    param(
        [parameter(Mandatory=$true,
                    Position = 1)]
        [Object[]]$Data,
        [parameter(Mandatory=$true,
                    Position = 2)]
        [ValidateNotNullOrEmpty()]
        [string]$Category,
        [parameter(Mandatory=$false,
                    Position = 3)]
        [ValidateNotNull()]
        [hashtable[]]$ConditionalFormatting = @{}
    )

    $UniqueProperties = @()
    foreach ($Item in $Data) {
        $UniqueProperties = $UniqueProperties + ($Item.PSObject.Properties.name)
    }
    $UniqueProperties = $UniqueProperties | Select-Object -Unique
    $inc = 1
    $Data | ForEach-Object -Process {
        Add-Member -InputObject $_ -MemberType 'NoteProperty' -Name 'I' -Value $inc -Force
        $inc++
    }
    [string]$stringOut = $Data | Select-Object -Property (@('I') + $UniqueProperties) | ConvertTo-Html -Fragment
    [xml]$frag = $stringOut
    Write-Verbose "Property InnerXML fragment: $($frag.InnerXml | Out-String)"
    Write-Log -Log $LogFilePath -Type INFO -Text "Property InnerXML fragment: $($frag.InnerXml | Out-String)"
    $MatchingFilters = $ConditionalFormatting | Where-Object -FilterScript { $_.Category -eq $Category }
    foreach ($filter in $MatchingFilters) {
        for ($i=1;$i -le $frag.table.tr.count-1;$i++) {
            $ColumnHeader = [array]::indexof($frag.table.tr.th,$Filter.Property)
            Write-Verbose "Column header: $ColumnHeader - $($Filter.Property) - $($frag.table.tr.th -join ', ')"
            Write-Log -Log $LogFilePath -Type INFO -Text "Column header: $ColumnHeader - $($Filter.Property) - $($frag.table.tr.th -join ', ')"
            Write-Verbose "HTML value: $($frag.table.tr[$i].td[$ColumnHeader])"
            Write-Log -Log $LogFilePath -Type INFO -Text "HTML value: $($frag.table.tr[$i].td[$ColumnHeader])"
            $prop = $Filter.Property
            $ActualValue = ($Data | Where-Object -FilterScript { $_.I -eq ($frag.table.tr[$i].td[0]) }).$prop
            Write-Verbose "Actual value: $($ActualValue | Out-String)"
            Write-Log -Log $LogFilePath -Type INFO -Text "Actual value: $($ActualValue | Out-String)"
            Write-Verbose "Actual type: $($ActualValue.GetType())"
            Write-Log -Log $LogFilePath -Type INFO -Text "Actual type: $($ActualValue.GetType())"
            Write-Verbose "FilterValue: $($Filter.Value | Out-String)"
            Write-Log -Log $LogFilePath -Type INFO -Text "FilterValue: $($Filter.Value | Out-String)"
            $str = ( 'if ($ActualValue '  + "$($filter.comparison)" + ' $Filter.value ){ $true } else { $false }' )
            Write-Verbose "Code string: $str"
            Write-Log -Log $LogFilePath -Type INFO -Text "Code string: $str"
            $ColourCode = [Scriptblock]::Create($str)
            $Return = Invoke-Command -ScriptBlock $ColourCode -NoNewScope
            Write-Verbose "Code return value: $Return"
            Write-Log -Log $LogFilePath -Type INFO -Text "Code return value: $Return"
            if ($Return -eq $true) {
                $class = $frag.CreateAttribute("class")
                $class.value = "alert"
                $frag.table.tr[$i].childnodes[$ColumnHeader].attributes.append($class) | Out-Null
            } # return true
        } # for each row
    } # foreach
    return ("<H2>$Category</H2>" + $frag.InnerXml)
} # function format HTML table

function Select-Data {
    <#
        .SYNOPSIS
            Format HTML table
        
        .DESCRIPTION
            Format HTML table with conditonal formatting
        
        .PARAMETER Data
            The data to filter
        
        .PARAMETER Category
            The category of the data
        
        .PARAMETER DefaultFilters
            The filters to apply
        
        .NOTES
            Updated 2019-04-15 by Andy DLP
    #>
    [CmdletBinding()]
    param(
        [parameter(Mandatory=$true,
                    Position = 1)]
        [Object[]]$Data,
        [parameter(Mandatory=$true,
                    Position = 2)]
        [ValidateNotNullOrEmpty()]
        [string]$Category,
        [parameter(Mandatory=$false,
                    Position = 3)]
        [ValidateNotNull()]
        [hashtable[]]$DefaultFilters = @{}
    )

    $MatchingFilters = $DefaultFilters | Where-Object -FilterScript { $_.Category -eq $Category }
    foreach ($filter in $MatchingFilters) {
        Write-Verbose "Filter: $($filter | Out-String)"
        Write-Log -Log $LogFilePath -Type INFO -Text "Filter: $($filter | Out-String)"
        switch ($filter.type) {
            'Property' { 
                if ($filter.value -is [array]) {
                    [string]$str = ('$_.' + $Filter.Property + ' ' + $filter.Comparison + ' @(' + ($filter.Value -join ',') + ')')
                } else {
                    [string]$str = ('$_.' + $Filter.Property + ' ' + $filter.Comparison + ' ' + $filter.Value)
                }
                $FilterScript = [Scriptblock]::Create($str)
                $Data = $Data | Where-Object $FilterScript -ErrorAction Continue
            }
            'Display' { 
                $SelectSplat = @{}
                if ($Filter.Action -eq 'Include') {
                    $SelectSplat.Add('Property',$Filter.Properties)
                } elseif ($filter.Action -eq 'Exclude') {
                    $SelectSplat.Add('ExcludeProperty',($Filter.Properties | Where-Object -FilterScript { $_ -ne 'I' }))
                } else {
                    Write-Warning "Failed filter: $($filter.Category) $($filter.Type)"
                    Write-Log -Log $LogFilePath -Type WARNING -Text "Failed filter: $($filter.Category) $($filter.Type)"
                }
                $SortSplat = @{
                    Property = $Filter.SortingProperty
                }
                if ($Filter.SortingType -eq 'Ascending') {
                    # Normal behaviour
                } elseif ($Filter.sortingType -eq 'Descending') {
                    $SortSplat.Add('Descending',$true)
                } else {
                    Write-Warning "Failed sorting $($filter.SortingProperty) $($filter.sortingType)"
                    Write-Log -Log $LogFilePath -Type WARNING -Text "Failed sorting $($filter.SortingProperty) $($filter.sortingType)"
                }
                $Data = $Data | Select-Object @SelectSplat | Sort-Object @SortSplat
            }
            'Hidden' { 
                $Data = $null
            }
            Default {
                # Filter nothing
                Write-Warning "Failed to filter with wrong type $($Filter.Type)"
                Write-Log -Log $LogFilePath -Type WARNING -Text "Failed to filter with wrong type $($Filter.Type)"
            }
        } # switch filter type
    }# foreach filter
    $Data
} # function Select Data


# END DEFINE FUNCTIONS
########################################################

########################################################
# BEGIN SETUP VARIABLES

# Check if verbose flag is set to later dump more info
$IsVerbose = $PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent

# Get PSScriptRoot on PS 2.0
if (-not $PSScriptRoot) {
    $PSScriptRoot = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
}

# Todays date in filename compatible format
$Today = (Get-Date -Format "yyyy-MM-dd-HH-mm-ss")

if ($null -eq (Get-Item -Path "$PSScriptRoot\Data" -ErrorAction SilentlyContinue) ) { mkdir "$PSScriptRoot\Data" | Out-Null }
if ($null -eq (Get-Item -Path "$PSScriptRoot\Logs" -ErrorAction SilentlyContinue)) { mkdir "$PSScriptRoot\Logs" | Out-Null }
$LogFilePath = (Join-Path -Path "$PSScriptRoot\Logs" -ChildPath "$Today.log")


Write-Log -Log $LogFilePath -Type INFO -Text "Computer name: $env:COMPUTERNAME"
Write-Log -Log $LogFilePath -Type INFO -Text "PSVersion: $($PSVersionTable.PSVersion.ToString())"
Write-Log -Log $LogFilePath -Type INFO -Text "Today: $Today"
Write-Log -Log $LogFilePath -Type INFO -Text "PSScriptRoot: $PSScriptRoot"
Write-Log -Log $LogFilePath -Type INFO -Text "IsVerbose: $IsVerbose"
Write-Log -Log $LogFilePath -Type INFO -Text "Logging set to: $LogFilePath"

########################################################
# USER DEFINED VARIABLES ARE NOT HERE

# MODIFY VARIABLES IN THIS CONFIG FILE INSTEAD
if ($null -ne (Get-Item -Path "$PSScriptRoot\Invoke-CoverageChecks.config.ps1")) {
    # Dot source the config file to import the variables to this script's session
    Write-Verbose "Importing user settings from $ConfigFile"
    Write-Log -Log $LogFilePath -Type INFO -Text "Importing user settings from $ConfigFile"
    . "$ConfigFile"
} else {
    Write-Warning "User defined configuration file not found at $ConfigFile, using default settings"
    Write-Log -Log $LogFilePath -Type WARNING -Text "User defined configuration file not found at $ConfigFile, using default settings"
}

# DO NOT MODIFY THIS FILE
########################################################

# Make sure that the user running script is a domain admin
# Ensures full access to all servers for full info grab
# Can replace with another administrator level group if required i.e. ServerAdmins 
$RunningUser = Get-ADUser ($env:USERNAME) -ErrorAction Stop
Write-Verbose "Script running as: $($env:USERNAME)@$($env:USERDNSDOMAIN)"
Write-Log -Log $LogFilePath -Type INFO -Text "Script running as: $($env:USERNAME)@$($env:USERDNSDOMAIN)"
$RunningUserGroups = Get-ADGroup -LDAPFilter ("(member:1.2.840.113556.1.4.1941:={0})" -f ($RunningUser.DistinguishedName)) | Select-Object -ExpandProperty Name
If ($RunningUserGroups -Contains "Domain Admins") {
    Write-Verbose "$($env:USERNAME)@$($env:USERDNSDOMAIN) is a domain admin"
    Write-Log -Log $LogFilePath -Type INFO -Text "$($env:USERNAME)@$($env:USERDNSDOMAIN) is a domain admin"
} else {
    # If user is not a domain admin then stop script
    Write-Warning "$($env:USERNAME)@$($env:USERDNSDOMAIN) is not a domain admin!"
    Write-Log -Log $LogFilePath -Type ERROR -Text "$($env:USERNAME)@$($env:USERDNSDOMAIN) is not a domain admin!"
    Write-Warning "Exiting script..."
    Write-Log -Log $LogFilePath -Type ERROR -Text "Exiting script..."
    exit
}

# If the user defined filters are not in place - use the defaults
if ($null -eq $DefaultFilters) {
    Write-Warning "DefaultFilters variable not found, using system defaults"
    Write-Log -Log $LogFilePath -Type WARNING -Text "DefaultFilters variable not found, using system defaults"
    $DefaultFilters = @(
    @{
        Category = 'Disks'
        Type = 'Property'
        Property = 'PercentFree'
        Comparison = '-lt'
        Value = 100 # only show disks at 100% of less free space (example)
    },
    @{
        Category = 'VMSnapshots'
        Type = 'Display'
        Action = 'Include'
        Properties = @('VIServer','Name','ParentSnapshot','Description','Created','PowerState','VM','SizeGB','IsCurrent','IsReplaySupported')
        SortingProperty = 'VIServer'
        SortingType = 'Ascending'
    },
    @{
        Category = 'LastEvents'
        Type = 'Display'
        Action = 'Include'
        Properties = @('VIServer','IpAddress','UserAgent','CreatedTime','UserName','LoginTime','ChainId','FullFormattedMessage','To','NewStatus')
        SortingProperty = 'VIServer'
        SortingType = 'Ascending'
    },
    @{
        Category = 'VMs'
        Type = 'Display'
        Action = 'Include'
        Properties = @('VIServer','Name','PowerState','NumCpu','CoresPerSocket','MemoryGB','ProvisionedSpaceGB','UsedSpaceGB','Notes','Folder','Version')
        SortingProperty = 'VIServer'
        SortingType = 'Ascending'
    },
    @{
        Category = 'Datastores'
        Type = 'Display'
        Action = 'Include'
        Properties = @('VIServer','Name','Datacenter','CapacityGB','FreeSpaceGB','Accessible','Type','State','FileSystemVersion')
        SortingProperty = 'VIServer'
        SortingType = 'Ascending'
    },
    @{
        Category = 'DFSRBacklogs'
        Type = 'Display'
        Action = 'Include'
        Properties = @('ComputerName','ReplicationGroupname','SendingMember','ReceivingMember','BacklogFileCount')
        SortingProperty = 'ComputerName'
        SortingType = 'Ascending'
    },
    @{
        Category = 'Disks'
        Type = 'Display'
        Action = 'Include'
        Properties = @('ComputerName','Volume','TotalSize','FreeSpace','PercentFree')
        SortingProperty = 'PercentFree'
        SortingType = 'Ascending'
    },
    @{
        Category = 'Unresponsive Domain Controllers'
        Type = 'Display'
        Action = 'Include'
        Properties = @('ComputerName','ServerResponding','ServerWSManrunning')
        SortingProperty = 'ComputerName'
        SortingType = 'Ascending'
    },
    @{
        Category = 'Unresponsive servers'
        Type = 'Display'
        Action = 'Include'
        Properties = @('ComputerName','Error','ServerResponding','ServerWSManrunning','Ignored')
        SortingProperty = 'ComputerName'
        SortingType = 'Ascending'
    },
    @{
        Category = 'ExpiredSoonCertificates'
        Type = 'Display'
        Action = 'Include'
        Properties = @('ComputerName','Subject','Issuer','NotBefore','NotAfter','Thumbprint','HasPrivateKey')
        SortingProperty = 'ComputerName'
        SortingType = 'Ascending'
    },
    @{
        Category = 'GeneralInformation'
        Type = 'Display'
        Action = 'Include'
        Properties = @('ComputerName','OperatingSystem','IsVirtual','IsServerCore','SMB1Enabled','InstallDate','LastBootUpTime','CPUs','MemoryGB')
        SortingProperty = 'ComputerName'
        SortingType = 'Ascending'
    },
    @{
        Category = 'LocalAdministrators'
        Type = 'Display'
        Action = 'Include'
        Properties = @('ComputerName','Group','Members')
        SortingProperty = 'ComputerName'
        SortingType = 'Ascending'
    },
    @{
        Category = 'NonStandardScheduledTasks'
        Type = 'Display'
        Action = 'Include'
        Properties = @(@{n='ComputerName';e={$_.HostName}},'TaskName','Status','Next Run Time','Last Run Time','Last Result','Author','Run As User','Schedule Type')
        SortingProperty = @('ComputerName','Last Run Time')
        SortingType = 'Ascending'
    },
    @{
        Category = 'NonStandardServices'
        Type = 'Display'
        Action = 'Include'
        Properties = @( @{n='ComputerName';e={$_.SystemName}},'Name','DisplayName','State','StartMode','StartName','PathName')
        SortingProperty = 'ComputerName'
        SortingType = 'Ascending'
    },
    @{
        Category = 'PendingReboot'
        Type = 'Display'
        Action = 'Include'
        Properties = @( @{n='ComputerName';e={$_.Computer}},'CBServicing','WindowsUpdate','PendComputerRename','RebootPending','CCMClientSDK' )
        SortingProperty = 'ComputerName'
        SortingType = 'Ascending'
    },
    @{
        Category = 'SharedPrinters'
        Type = 'Display'
        Action = 'Include'
        Properties = @('ComputerName','Printername','IsPingable','PublishedToAD','PrinterAddress','PrinterDriver')
        SortingProperty = 'ComputerName','PrinterName'
        SortingType = 'Ascending'
    },
    @{
        Category = 'UpdateInfo'
        Type = 'Display'
        Action = 'Include'
        Properties = @('ComputerName','UpToDate','LastSearch','LastInstall')
        SortingProperty = 'ComputerName'
        SortingType = 'Ascending'
    }
)
}
Write-Verbose "$($DefaultFilters.Count) filters loaded"
Write-Log -Log $LogFilePath -Type INFO -Text "$($DefaultFilters.Count) filters loaded"

if ($null -eq $IgnoredServers) {
    Write-Warning "IgnoredServers variable not found, using system defaults"
    Write-Log -Log $LogFilePath -Type WARNING -Text "IgnoredServers variable not found, using system defaults"
    # A comma separated list of servers names (strings) that will not be target for information gathering
    $IgnoredServers = @()
}
Write-Verbose ("Servers ignored: " + $IgnoredServers -join ', ')
Write-Log -Log $LogFilePath -Type INFO -Text ("Servers ignored: " + $IgnoredServers -join ', ')


if ($null -eq $ConditionalFormatting) {
    Write-Warning "ConditionalFormatting variable not found, using system defaults"
    Write-Log -Log $LogFilePath -Type WARNING -Text "ConditionalFormatting variable not found, using system defaults"
    $ConditionalFormatting = @(
    @{
        Category = 'DCDiag Results'
        Property = 'FailedTests'
        Comparison = '-ne'
        Value = $null
    },
    @{
        Category = 'Domain Controllers'
        Property = 'NTDSService'
        Comparison = '-eq'
        Value = 'Stopped'
    },
    @{
        Category = 'Domain Controllers'
        Property = 'NetlogonService'
        Comparison = '-eq'
        Value = 'Stopped'
    },
    @{
        Category = 'Domain Controllers'
        Property = 'DNSService'
        Comparison = '-eq'
        Value = 'Stopped'
    },
    @{
        Category = 'Domain Controllers'
        Property = 'NetlogonAccessible'
        Comparison = '-eq'
        Value = $false
    },
    @{
        Category = 'Domain Controllers'
        Property = 'SYSVOLAccessible'
        Comparison = '-eq'
        Value = $false
    },
    @{
        Category = 'SYSVOL Backlog'
        Property = 'BacklogFileCount'
        Comparison = '-ne'
        Value = 0
    },
    @{
        Category = 'Disks'
        Property = 'PercentFree'
        Comparison = '-lt'
        Value = 50
    },
    @{
        Category = 'NonStandardScheduledTasks'
        Property = 'Run As User'
        Comparison = '-match'
        Value = 'administrator'
    },
    @{
        Category = 'NonStandardServices'
        Property = 'State'
        Comparison = '-eq'
        Value = "Stopped"
    },
    @{
        Category = 'NonStandardServices'
        Property = 'StartName'
        Comparison = '-match'
        Value = 'administrator'
    },
    @{
        Category = 'PendingReboot'
        Property = 'RebootPending'
        Comparison = '-eq'
        Value = $true
    },
    @{
        Category = 'ExpiredSoonCertificates'
        Property = 'NotBefore'
        Comparison = '-gt'
        Value = (Get-Date)
    },
    @{
        Category = 'ExpiredSoonCertificates'
        Property = 'NotAfter'
        Comparison = '-lt'
        Value = (Get-Date)
    },
    @{
        Category = 'UpdateInfo'
        Property = 'UpToDate'
        Comparison = '-eq'
        Value = $false
    },
    @{
        Category = 'SharedPrinters'
        Property = 'IsPingable'
        Comparison = '-eq'
        Value = $false
    }
)
}
Write-Verbose ("ConditionalFormatting: " + $ConditionalFormatting -join ', ')
Write-Log -Log $LogFilePath -Type INFO -Text ("ConditionalFormatting: " + $ConditionalFormatting -join ', ')


if ($null -eq $SendEmail) {
    Write-Warning "SendEmail variable not found, using system defaults"
    Write-Log -Log $LogFilePath -Type WARNING -Text "SendEmail variable not found, using system defaults"
    # Change to $true to enable reporting sending via email
    $SendEmail = $false
}
Write-Verbose "Send email enabled: $SendEmail"
Write-Log -Log $LogFilePath -Type INFO -Text "Send email enabled: $SendEmail"

if ($SendEmail -eq $true) {

    if ($null -eq $TargetEmail) {
        Write-Warning "TargetEmail variable not found, using system defaults"
        Write-Log -Log $LogFilePath -Type WARNING -Text "TargetEmail variable not found, using system defaults"
        # A comma separated list of recipients for the email
        $TargetEmail = @(
        "recipient1@example.com",
        "recipient2@example.com"
        )
    }
    Write-Verbose ("Email recipients: " + $TargetEmail -join ', ')
    Write-Log -Log $LogFilePath -Type INFO -Text ("Email recipients: " + $TargetEmail -join ', ')

    if ($null -eq $MailServer) {
        Write-Warning "MailServer variable not found, using system defaults"
        Write-Log -Log $LogFilePath -Type WARNING -Text "MailServer variable not found, using system defaults"
        # The SMTP relay that will allow the email
        $MailServer = "mail.example.com"
    }
    Write-Verbose "Mail server: $MailServer"
    Write-Log -Log $LogFilePath -Type INFO -Text "Mail server: $MailServer"

    if ($null -eq $MailPort) {
        Write-Warning "MailPort variable not found, using system defaults"
        Write-Log -Log $LogFilePath -Type WARNING -Text "MailPort variable not found, using system defaults"
        # Port used for the SMTP relay
        $MailPort = 25
    }
    Write-Verbose "Mail port: $MailPort"
    Write-Log -Log $LogFilePath -Type INFO -Text "Mail port: $MailPort"
    
    if ($null -eq $FromEmail) {
        Write-Warning "FromEmail variable not found, using system defaults"
        Write-Log -Log $LogFilePath -Type WARNING -Text "FromEmail variable not found, using system defaults"
        # The from address for the report email
        $FromEmail = "ServerChecks@example.com"
    }
    Write-Verbose "Mail sender: $FromEmail"
    Write-Log -Log $LogFilePath -Type INFO -Text "Mail sender: $FromEmail"
    
    if ($null -eq $MailSubject) {
        Write-Warning "MailSubject variable not found, using system defaults"
        Write-Log -Log $LogFilePath -Type WARNING -Text "MailSubject variable not found, using system defaults"
        # The subject for the report email 
        $MailSubject = "ECI Coverage Checks - $(Get-Date)"
    }
    Write-Verbose "Mail subject: $MailSubject"
    Write-Log -Log $LogFilePath -Type INFO -Text "Mail subject: $MailSubject"
}

if ($null -eq $VCentersAndESXIHosts) {
    Write-Warning "MailSubject variable not found, using system defaults"
    Write-Log -Log $LogFilePath -Type WARNING -Text "MailSubject variable not found, using system defaults"
    # VCenter servers and ESXI hosts in a comma separated list
    $VCentersAndESXIHosts = @()
}
Write-Verbose ("VMware servers: " + $VCentersAndESXIHosts -join ', ')
Write-Log -Log $LogFilePath -Type INFO -Text ("VMware servers: " + $VCentersAndESXIHosts -join ', ')

# Required modules
$RequiredModules = @(
    'ActiveDirectory',
    'GroupPolicy'
)
if ($VCentersAndESXIHosts.count -gt 0) {$RequiredModules += 'VMWare.PowerCLI'}

Import-Module -Name $RequiredModules -ErrorAction Stop -Verbose:$false

# Optional modules

#Import-Module FailoverClusters,VMWare.PowerCLI -ErrorAction SilentlyContinue -Verbose:$false

# END SETUP VARIABLES
########################################################

########################################################
# GET AD INFORMATION

# !Assumption is the environment is one forest only!

$ThisForest = Get-ADForest

Write-Verbose "Forest name: $($ThisForest.Name)"
Write-Log -Log $LogFilePath -Type INFO -Text "Forest name: $($ThisForest.Name)"

$AllDomainInfo = @()
$AllDomainObjectInfo =@()
foreach ($Domain in $ThisForest.Domains) {
    $ThisDomain = Get-ADDomain -Identity $Domain
    
    Write-Verbose "Domain name: $($ThisDomain.DNSRoot)"
    Write-Log -Log $LogFilePath -Type INFO -Text "Domain name: $($ThisDomain.DNSRoot)"

    $AllDomainControllersPS = ( $ThisDomain.ReplicaDirectoryServers + $ThisDomain.ReadOnlyReplicaDirectoryServers ) | Get-ADDomainController
    $AllDomainControllersAD = Get-ADObject -Server $ThisDomain.PDCEmulator -Filter {ObjectClass -eq 'computer'} -SearchBase "OU=Domain Controllers,$($ThisDomain.DistinguishedName)"
    $DCRefObj = $AllDomainControllersPS | Select-Object -ExpandProperty ComputerObjectDN
    $DCDiffObj = $AllDomainControllersAD | Select-Object -ExpandProperty DistinguishedName
    $Differences = Compare-Object -ReferenceObject $DCRefObj -DifferenceObject $DCDiffObj
    $SYSVOLReplicationMode = switch ((Get-ADObject "CN=DFSR-GlobalSettings,CN=System,$($ThisDomain.DistinguishedName)" -Properties 'msDFSR-Flags').'msDFSR-Flags') {
        0 {'FRS - 0'}
        16 {'FRS - 1'}
        32 {'DFSR - 2'}
        48 {'DFSR - 3'}
        Default {'Unknown (FRS)'}
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
        ADRecycleBinEnabled = [bool]((Get-ADOptionalFeature -filter {Name -eq "Recycle Bin Feature"}).EnabledScopes.Count)
    }
    if ($null -ne $Differences) {
        $ADInfoParams.Add('Notes',"MISMATCHED DC LIST: PS: $($AllDomainControllersPS | Out-String) - AD: $($AllDomainControllersAD | Out-String)")
        Write-Warning "MISMATCHED DC LIST: PS: $($AllDomainControllersPS | Out-String) - AD: $($AllDomainControllersAD | Out-String)"
        Write-Log -Log $LogFilePath -Type WARNING -Text "MISMATCHED DC LIST: PS: $($AllDomainControllersPS | Out-String) - AD: $($AllDomainControllersAD | Out-String)"
    } else {
        Write-Verbose "Domain controllers: $($AllDomainControllersPS -join ', ')"
        Write-Log -Log $LogFilePath -Type INFO -Text "Domain controllers: $($AllDomainControllersPS -join ', ')"
    }
    $ADInfo = [PSCustomObject]$ADInfoParams
    $AllDomainInfo = $AllDomainInfo + $ADInfo

    foreach ($Property in $ADInfo.psobject.properties.Name) {
        Write-Verbose "$($ThisDomain.NetBIOSName) $($Property): $($ADInfo.$Property)"
        Write-Log -Log $LogFilePath -Type INFO -Text "$($ThisDomain.NetBIOSName) $($Property): $($ADInfo.$Property)"
    }

    if ($null -eq (Get-Item -Path "$PSScriptRoot\Data\$($ThisDomain.NetBIOSName)\LastRun" -ErrorAction SilentlyContinue)) { mkdir "$PSScriptRoot\Data\$($ThisDomain.NetBIOSName)\LastRun" | Out-Null }
    if ($null -eq (Get-Item -Path "$PSScriptRoot\Data\$($ThisDomain.NetBIOSName)\ThisRun" -ErrorAction SilentlyContinue)) { mkdir "$PSScriptRoot\Data\$($ThisDomain.NetBIOSName)\ThisRun" | Out-Null }
    $str = @()
    $GPOChanges = Get-GPOChanges -LastRunFolder "$PSScriptRoot\Data\$($ThisDomain.NetBIOSName)\LastRun" -ThisRunFolder "$PSScriptRoot\Data\$($ThisDomain.NetBIOSName)\ThisRun"
    if ($null -ne $GPOChanges) { 
        $GPOChanges | ForEach-Object -Process { $str = $str + ($_.GPOName + " (" + $_.ChangeType + ")") }
        $GPOChanges = $str -join ', '
    }

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
        GPOChanges = if ($null -eq $GPOChanges) { "None" } else { $GPOChanges }
    }
    $DomainObjectInfo = [PSCustomObject]$DomainObjectInfoParams
    $AllDomainObjectInfo = $AllDomainObjectInfo + $DomainObjectInfo

    foreach ($Property in $DomainObjectInfo.psobject.properties.Name) {
        Write-Verbose "$($ThisDomain.NetBIOSName) $($Property): $($DomainObjectInfo.$Property)"
        Write-Log -Log $LogFilePath -Type INFO -Text "$($ThisDomain.NetBIOSName) $($Property): $($DomainObjectInfo.$Property)"
    }
} # foreach domain

# DC INFO
$AllDCInfo = @()
$FailedDCInfo = @()
$AllDCBacklogs = @()
$DCDiagResults = @()
$inc = 0

foreach ($DC in $AllDomainControllersPS) {
    $inc++
    Write-Verbose "Starting checks on: $($DC.Name)"
    Write-Log -Log $LogFilePath -Type INFO -Text "Starting checks on: $($DC.Name)"
    Write-Verbose "DC: $($DC.Name) --- $inc / $($AllDomainControllersPS.count)"
    Write-Log -Log $LogFilePath -Type INFO -Text "DC: $($DC.Name) --- $inc / $($AllDomainControllersPS.count)"

    # Find if PC is ON and responding to WinRM
    $ServerResponding = Test-Connection -Count 1 -ComputerName $DC.Name -Quiet
    try {
        Test-WSMan -ComputerName $DC.Name -ErrorAction Stop | Out-Null
        $ServerWSManrunning = $true
    }
    catch { $ServerWSManrunning = $false }

    if (($ServerResponding -eq $true) -and ($ServerWSManrunning -eq $true)) {
        # Server responding fine
        try {
            # Invoke it all, don't rely on the inbuilt remoting of Get-WmiObject or other cmdlets
            Write-Verbose "Creating PSSession to: $($DC.Name)"
            Write-Log -Log $LogFilePath -Type INFO -Text "Creating PSSession to: $($DC.Name)"
            $DCPSSession = New-PSSession -ComputerName $DC.name -ErrorAction Stop

            Write-Verbose "Gathering DC info from: $($DC.Name)"
            Write-Log -Log $LogFilePath -Type INFO -Text "Gathering DC info from: $($DC.Name)"
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
                    OS = $OSInfo.Caption
                    LastBoot = Get-Date -Date ($OSInfo.ConvertToDateTime($OSInfo.LastBootUpTime)) -Format 'MM/dd/yyyy HH:mm:ss'
                    IsVirtual = if (($PCInfo.model -like "*virtual*") -or ($PCInfo.Manufacturer -eq 'QEMU') -or ($PCInfo.Model -like "*VMware*")) { $true } else { $false }
                    IsGC = $args[0].IsGlobalCatalog
                    NTDSService = (Get-Service -Name 'NTDS' | Select-Object -ExpandProperty Status).ToString()
                    NetlogonService = (Get-Service -Name 'Netlogon' | Select-Object -ExpandProperty Status).ToString()
                    DNSService = (Get-Service -Name 'DNS' | Select-Object -ExpandProperty Status).ToString()
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

            Write-Verbose "Gathering DFSR backlog information from $($DC.name)"
            Write-Log -Log $LogFilePath -Type INFO -Text "Gathering DFSR backlog information from $($DC.name)"
            $DCBacklog = Invoke-Command -Session $DCPSSession -ScriptBlock ${function:Get-DfsrBacklog} -ArgumentList $DC.Name
            $DCBacklog = $DCBacklog | Where-Object -FilterScript { $_.ReplicationGroupName -eq 'Domain System Volume' } | Select-Object -Property ComputerName,ReplicationGroupname,SendingMember,ReceivingMember,BacklogFileCount
            $AllDCBacklogs = $AllDCBacklogs + $DCBacklog

            $OutputObjectParams.Add('NetlogonAccessible',(Test-Path -Path "\\$($DC.HostName)\NETLOGON\"))
            # TODO: FIX BELOW  -  This wont work properly for a multi-domain environment...?
            $OutputObjectParams.Add('SYSVOLAccessible',(Test-Path -Path "\\$($DC.HostName)\SYSVOL\$((Get-ADDomain).DNSRoot)"))

            # dcdiag
            Write-Verbose "Gathering DCDIAG backlog information from $($DC.name)"
            Write-Log -Log $LogFilePath -Type INFO -Text "Gathering DCDIAG backlog information from $($DC.name)"
            $DCDiag = Invoke-Command -Session $DCPSSession -ScriptBlock {
                # DCDiag parsing
                $DCDIAGResult = New-Object System.Object
                $DCDIAGStr = dcdiag.exe
                $DCDIAGResult | Add-Member -name ComputerName -Value $env:COMPUTERNAME -Type NoteProperty -Force
                $PassedStrings = @()
                $FailedStrings = @()
                Foreach ($Entry in $DCDIAGStr) {
                    Switch -Regex ($Entry) {
                        "Starting" {
                            $Testname = ($Entry -replace ".*Starting test: ").Trim()
                        }
                        "passed|failed" {
                            $TestStatus = if ($Entry -match "Passed") { "Passed" } else { "Failed" }
                        } # case pass or pail
                    } # switch

                    if (($TestName -ne $null) -and ($TestStatus -ne $null)) {
                        if ($TestStatus -eq 'Passed') { $PassedStrings = $PassedStrings + $($TestName.Trim()) } else { $FailedStrings = $FailedStrings + $($TestName.Trim()) }
                    } # if not null
                } # foreach line in DCDIAG output
                if ($PassedStrings.Count -gt 0) {
                    $PassedStrings = $PassedStrings | Select-Object -Unique
                    $DCDIAGResult | Add-Member -Type NoteProperty -Name 'PassedTests' -Value ($PassedStrings -join ', ') -Force
                }
                if ($FailedStrings.Count -gt 0) {
                    $PassedStrings = $FailedStrings | Select-Object -Unique
                    $DCDIAGResult | Add-Member -Type NoteProperty -Name 'FailedTests' -Value ($FailedStrings -join ', ') -Force
                }
                $DCDIAGResult
            } # scriptblock
            $DCdiag = $DCDiag | Select-Object -Property ComputerName,PassedTests,FailedTests
            $DCDiagOutputObject
            $DCDiagResults = $DCDiagResults + $DCDiag
            

            $DCResponse = [PSCustomObject]$OutputObjectParams
            # Reorder in selected order
            $DCResponse = $DCResponse | Select-Object -Property ComputerName,NTDSService,NETLOGONService,DNSService,NetlogonAccessible,SYSVOLAccessible,"ADDS volume % free","ADDS log volume % free","SYSVOL volume % free",IsVirtual,IsGC,IsServerCore,OS,LastBoot
            $AllDCInfo = $AllDCInfo + $DCResponse

            foreach ($Property in $DCResponse.psobject.properties.Name) {
                Write-Verbose "$($DC.Name) $($Property): $($DCResponse.$Property)"
                Write-Log -Log $LogFilePath -Type INFO -Text "$($DC.Name) $($Property): $($DCResponse.$Property)"
            }

            Write-Verbose "Removing PSSession to: $($DC.Name)"
            Write-Log -Log $LogFilePath -Type INFO -Text "Removing PSSession to: $($DC.Name)"
            Remove-PSSession -Session $DCPSSession
        } # try
        catch {
            Write-Warning "$($DC.Name) failed"
            Write-Log -Log $LogFilePath -Type WARNING -Text "$($DC.Name) failed"
            $FailObject = [PSCustomObject]@{
                ComputerName = $DC.HostName
                DC = $DC
                ServerResponding = $ServerResponding
                ServerWSManrunning = $ServerWSManrunning
            }
            $FailedDCInfo = $FailedDCInfo + $FailObject
        } # catch
    } else {
        Write-Warning "$($DC.Name) failed"
        Write-Log -Log $LogFilePath -Type WARNING -Text "$($DC.Name) failed"
        $FailObject = [PSCustomObject]@{
            ComputerName = $DC.HostName
            DC = $DC
            ServerResponding = $ServerResponding
            ServerWSManrunning = $ServerWSManrunning
        }
        $FailedDCInfo = $FailedDCInfo + $FailObject
    } # else server not responding fine
} # foreach DC

# END AD INFORMATION
#########################################################

#########################################################
# EXCHANGE

$ExchangeServerList = @()
foreach ($Domain in $AllDomainInfo) {
    Write-Verbose "Getting exchange servers in: $($Domain.DomainDNSRoot)"
    Write-Log -Log $LogFilePath -Type INFO -Text "Getting exchange servers in: $($Domain.DomainDNSRoot)"
    $ExchangeServerList += (Get-ADObject -Filter {objectCategory -eq "msExchExchangeServer"} -SearchBase "cn=Configuration,$((Get-ADDomain -Identity $Domain.DomainDNSRoot).DistinguishedName)" | Select-Object -ExpandProperty Name)
    
    Write-Verbose "Exchange servers in $($Domain.DomainDNSRoot): $($ExchangeServerList -join ', ')"
    Write-Log -Log $LogFilePath -Type INFO -Text "Exchange servers in $($Domain.DomainDNSRoot): $($ExchangeServerList -join ', ')"
}

<#
# SERVER CHECKS
# dns
# ping
# uptime
# version
# IsEdge server
# ISHub transport server
# IsClient access
# ISMailbox server
# Test service health
# Exch v15 service health?
# Get queues / lengths
# get PF DBs - mounted?
# Get MB DBs - mounted?
# MAPI connectivity
# mail flow
# 
# DAG CHECKS
# DB servers
# DB copies
# copy queue
# replay queue
# replay lag
# truncation lag times
# 
# 
#>

# END EXCHANGE
#########################################################

#########################################################
# BEGIN MAIN INFO GATHERING LOOP

# Get all Windows servers with all properties
$ServerList = @()
foreach ($Domain in $AllDomainInfo) {
    Write-Verbose "Searching for windows servers in domain: $($Domain.DomainDNSRoot)"
    Write-Log -Log $LogFilePath -Type INFO -Text "Searching for windows servers in domain: $($Domain.DomainDNSRoot)"
    $ServerList += (Get-ADComputer -Filter { (OperatingSystem -Like "Windows *Server*") } -Properties *)
}
Write-Verbose "All domains server list: $($ServerList -join ', ')"
Write-Log -Log $LogFilePath -Type INFO -Text "All domains server list: $($ServerList -join ', ')"


# incremental counters & variable init
$inc = 0
$AllServerInfo = @()
$FailedServers = @()

foreach ($Server in $ServerList) {
    $inc++
    Write-Verbose "Server: $($Server.Name) --- $inc / $($ServerList.count)"
    Write-Log -Log $LogFilePath -Type INFO -Text "Server: $($Server.Name) --- $inc / $($ServerList.count)"

    if ($IgnoredServers -notcontains $Server.Name) {
        # Server is not filtered
        Write-Verbose "Starting checks on: $($Server.Name)"
        Write-Log -Log $LogFilePath -Type INFO -Text "Starting checks on: $($Server.Name)"

        # Find if PC is ON and responding to WinRM
        $ServerResponding = Test-Connection -Count 2 -ComputerName $Server.Name -Quiet
        # Assume WMF / PowerShell 5.1 is installed and working and if not then set flag to false
        try {
            Test-WSMan -ComputerName $Server.Name -ErrorAction Stop | Out-Null
            $ServerWSManrunning = $true
        }
        catch { $ServerWSManrunning = $false }

        if (($ServerResponding -eq $true) -and ($ServerWSManrunning -eq $true)) {
            # Server responding fine
            try {
                # Run it all locally via an invoked session
                Write-Verbose "Creating PSSession to $($Server.Name)"
                Write-Log -Log $LogFilePath -Type INFO -Text "Creating PSSession to $($Server.Name)"
                $ServerSSession = New-PSSession -ComputerName $Server.name -ErrorAction Stop
                $OutputObjectParams = @{}
                $InstalledRoles = Get-WindowsFeature -ComputerName $Server.name | Where-Object -FilterScript {$_.installed -eq $true} | Select-Object -ExpandProperty Name
                Write-Verbose "$($Server.Name) installed roles: $($InstalledRoles -join ', ')"
                Write-Log -Log $LogFilePath -Type INFO -Text "$($Server.Name) installed roles: $($InstalledRoles -join ', ')"
                $OutputObjectParams = Invoke-Command -Session $ServerSSession -HideComputerName -ScriptBlock {

                    $InstalledRoles = Get-WindowsFeature | Where-Object -FilterScript {$_.installed -eq $true} | Select-Object -ExpandProperty Name

                    # Get some WMI info about the machine
                    $OSInfo = Get-WmiObject -Class 'win32_operatingsystem'
                    $PCInfo = Get-WmiObject -Class 'win32_computersystem'
                    $CPUInfo = Get-WmiObject -Class 'win32_processor'
                    $DiskInfo = Get-WmiObject -Class 'win32_logicaldisk' -Filter {DriveType=3}

                    # General info
                    $OutputObjectParams = @{}

                    $InfoObject = [PSCustomObject]@{
                        GUID = ([GUID]::NewGuid().Guid)
                        ComputerName = $env:COMPUTERNAME
                        OperatingSystem = $OSInfo.Caption
                        IsVirtual = if (($PCInfo.model -like "*virtual*") -or ($PCInfo.Manufacturer -eq 'QEMU') -or ($PCInfo.Model -like "*VMware*")) { $true } else { $false }
                        IsServerCore = if ((Get-Item 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion' | Get-ItemProperty).InstallationType -eq 'Server Core') { $true } else { $false }
                        SMB1Enabled = if ($InstalledRoles -contains 'FS-SMB1') { $true } else { $false }
                        InstallDate = Get-Date -Date ($OSInfo.ConvertToDateTime($OSInfo.InstallDate)) -Format 'MM/dd/yyyy HH:mm:ss'
                        LastBootUpTime = Get-Date -Date ($OSInfo.ConvertToDateTime($OSInfo.LastBootUpTime)) -Format 'MM/dd/yyyy HH:mm:ss'
                        CPUs = ($CPUInfo | Select-Object -ExpandProperty NumberOfLogicalProcessors | Measure-Object -Sum).Sum
                        MemoryGB = [math]::Round(($PCInfo.TotalPhysicalMemory / 1GB))
                    }
                    $OutputObjectParams.Add('GeneralInformation',$InfoObject)

                    # Disk info
                    $Disks = @()
                    foreach ($Disk in $DiskInfo) {
                        $Freespace = $Disk.FreeSpace / 1GB
                        $TotalSize = $Disk.Size / 1GB
                        $PercentFree = (($Freespace / $TotalSize) * 100)
                        $DiskObj = [PSCustomObject]@{
                            GUID = ([GUID]::NewGuid().Guid)
                            ComputerName = $env:COMPUTERNAME
                            Volume = $Disk.DeviceId
                            TotalSize = [math]::Round($TotalSize)
                            FreeSpace = [math]::Round($Freespace)
                            PercentFree = [math]::Round($PercentFree)
                        }
                        $Disks = $Disks + $DiskObj
                    }
                    $OutputObjectParams.Add('Disks',$Disks)

                    # local admins
                    # TODO: Filter domain admins / Administrator account
                    $LocalAdmins = net localgroup "Administrators" | Where-Object -FilterScript {$_ -AND $_ -notmatch "command completed successfully"} | Select-Object -Skip 4
                    $AdminObj = [PSCustomObject]@{
                        GUID = ([GUID]::NewGuid().Guid)
                        ComputerName = $env:COMPUTERNAME
                        Group = 'Administrators'
                        Members = $LocalAdmins
                    }
                    $OutputObjectParams.Add('LocalAdministrators',$AdminObj)

                    # Printers shared from this machine
                    #  TODO: Add port checks + management page check?
                    if ($InstalledRoles -contains 'Print-Server') {
                        $SharedPrinters = Get-Printer -ComputerName $env:COMPUTERNAME | Where-Object -FilterScript { ($_.Shared -eq $true) }
                        if ($null -ne $SharedPrinters) {
                            $PrinterList = @()
                            foreach ($Printer in $SharedPrinters) {
                                $PrinterObjectParams = @{
                                    GUID = ([GUID]::NewGuid().Guid)
                                    ComputerName = $env:COMPUTERNAME
                                    PrinterName = $Printer.Name
                                    PrinterDriver = $Printer.DriverName
                                    PublishedToAD = $Printer.Published
                                }
                                try { $PrinterAddress = (Get-PrinterPort -Name $Printer.PortName -ErrorAction Stop | Select-Object -ExpandProperty 'PrinterHostAddress') }
                                catch { $PrinterAddress = $Printer.PortName }
    
                                $IsPingable = Test-Connection $PrinterAddress -Count 1 -Quiet
                                $PrinterObjectParams.Add('PrinterAddress',$PrinterAddress)
                                $PrinterObjectParams.Add('IsPingable',$IsPingable)
    
                                $PrinterObject = [PSCustomObject]$PrinterObjectParams
                                [array]$PrinterList = $PrinterList + $PrinterObject
                            }
                            $OutputObjectParams.Add('SharedPrinters',$PrinterList)
                        }
                    }

                    # scheduled task with domain / local credentials (non-system)
                    # or system account task created by domain user
                    $IgnoredTaskRunAsUsers = @('INTERACTIVE','SYSTEM','NT AUTHORITY\SYSTEM','LOCAL SERVICE','NETWORK SERVICE','Users','Administrators','Everyone','Authenticated Users')
                    $DomainNames = $args[1] | Select-Object -ExpandProperty DomainName
                    $NonStandardScheduledTasks = schtasks.exe /query /s $env:COMPUTERNAME /V /FO CSV | ConvertFrom-Csv | Where-Object -FilterScript { ($_.TaskName -notmatch 'ShadowCopyVolume') -and ($_.TaskName -notmatch 'G2MUploadTask') -and ($_.TaskName -notmatch 'Optimize Start Menu Cache Files') -and ($_.TaskName -ne "TaskName") -and ( ($_.'Run As User' -notin $IgnoredTaskRunAsUsers) -or (($_.Author -split '\\')[0] -in $DomainNames)  ) }
                    if ($null -ne $NonStandardScheduledTasks) {
                        $NonStandardScheduledTasks | Add-Member -MemberType 'NoteProperty' -Name 'GUID' -Value ([GUID]::NewGuid().Guid)
                        $OutputObjectParams.Add('NonStandardScheduledTasks',$NonStandardScheduledTasks)
                    }

                    # services with domain / local credentials (non-system)
                    $IgnoredServiceRunAsUsers = @('LocalSystem', 'NT AUTHORITY\LocalService', 'NT AUTHORITY\NetworkService','NT AUTHORITY\NETWORK SERVICE','NT AUTHORITY\SYSTEM')
                    $IgnoredServiceNames = @('gupdate','sppsvc','RemoteRegistry','ShellHWDetection','WbioSrvc')
                    $NonStandardServices = Get-WmiObject -Class 'win32_service' | Where-Object -FilterScript { ($_.StartName -notin $IgnoredServiceRunAsUsers) -or ( ($_.Name -notin $IgnoredServiceNames) -and ($_.StartMode -eq 'Auto') -and ($_.State -ne 'Running') ) }
                    if ($null -ne $NonStandardServices) {
                        $NonStandardServices | Add-Member -MemberType 'NoteProperty' -Name 'GUID' -Value ([GUID]::NewGuid().Guid)
                        $OutputObjectParams.Add('NonStandardServices',$NonStandardServices)
                    }

                    # Expired certificates / less than 30 days
                    $ExpiredSoonCertificates = Get-ChildItem -Path 'cert:\LocalMachine\My\' -Recurse | Where-Object -FilterScript { (($_.NotBefore -gt (Get-Date)) -or ($_.NotAfter -lt (Get-Date).AddDays(30))) -and ($null -ne $_.Thumbprint) }
                    if ($null -ne $ExpiredSoonCertificates) {
                        $ExpiredSoonCertificates | Add-Member -MemberType 'NoteProperty' -Name 'ComputerName' -Value $env:COMPUTERNAME
                        $ExpiredSoonCertificates | Add-Member -MemberType 'NoteProperty' -Name 'GUID' -Value ([GUID]::NewGuid().Guid)
                        $OutputObjectParams.Add('ExpiredSoonCertificates',$ExpiredSoonCertificates)
                    }

                    # DHCP information
                    if ($InstalledRoles -contains 'DHCP') {
                        # Check installed sub features (PS cmdlets / RSAT tools etc)
                    }

                    # WSUS information
                    if ($InstalledRoles -contains 'UpdateServices') {
                        # Check installed sub features (PS cmdlets / RSAT tools etc)
                    }

                    # WDS information
                    if ($InstalledRoles -contains 'WDS') {
                        # Check installed sub features (PS cmdlets / RSAT tools etc)
                    }

                    # Hyper-V information
                    if ($InstalledRoles -contains 'Hyper-V') {
                        # Check installed sub features (PS cmdlets / RSAT tools etc)
                    }
                    
                    # Send the resulting hashtable out
                    $OutputObjectParams
                } -ArgumentList $Server,$AllDomainInfo -ErrorAction Stop

                # Get non SYSVOL DFSR backlogs
                if ($InstalledRoles -contains 'FS-DFS-Replication') {
                    $DFSRBacklogs = Invoke-Command -Session $ServerSSession -HideComputerName -ErrorAction Stop -ScriptBlock ${function:Get-DfsrBacklog}  -ArgumentList $Server.Name
                    $DFSRBacklogs = $DFSRBacklogs | Where-Object -FilterScript { $_.ReplicationGroupName -ne 'Domain System Volume' }
                    if ($null -ne $DFSRBacklogs) {
                        $DFSRBacklogs | Add-Member -MemberType 'NoteProperty' -Name 'GUID' -Value ([GUID]::NewGuid().Guid)
                        $OutputObjectParams.Add('DFSRBacklogs',$DFSRBacklogs)
                    }
                }

                # Get Windows Update info
                $UpdateInfo = Invoke-Command -Session $ServerSSession -HideComputerName -ErrorAction Stop -ScriptBlock ${function:Get-RecentUpdateInfo}
                if ($null -ne $UpdateInfo) {
                    $UpdateInfo | Add-Member -MemberType 'NoteProperty' -Name 'GUID' -Value ([GUID]::NewGuid().Guid)
                    $OutputObjectParams.Add('UpdateInfo',$UpdateInfo)
                }

                # pending reboot
                $RebootInfo = Invoke-Command -Session $ServerSSession -HideComputerName -ErrorAction Stop -ScriptBlock ${function:Get-PendingReboot}
                if ($null -ne $RebootInfo) {
                    $RebootInfo | Add-Member -MemberType 'NoteProperty' -Name 'GUID' -Value ([GUID]::NewGuid().Guid)
                    $OutputObjectParams.Add('PendingReboot',$RebootInfo)
                }

                # create object from params
                $ServerObject = [PSCustomObject]$OutputObjectParams
                $AllServerInfo = $AllServerInfo + $ServerObject

                
                foreach ($Property in $ServerObject.psobject.properties.Name) {
                    Write-Verbose "$($Server.Name) $($Property): $($ServerObject.$Property)"
                    Write-Log -Log $LogFilePath -Type INFO -Text "$($Server.Name) $($Property): $($ServerObject.$Property)"
                }

                Write-Verbose "Removing PSSession to $($Server.Name)"
                Write-Log -Log $LogFilePath -Type INFO -Text "Removing PSSession to $($Server.Name)"
                Remove-PSSession -Session $ServerSSession
            }
            catch {
                Write-Warning "Failed to gather information from server: $($server.Name)"
                Write-Log -Log $LogFilePath -Type WARNING -Text "Failed to gather information from server: $($server.Name)"
                $FailObject = [PSCustomObject]@{
                    ComputerName = $Server.Name
                    Server = $Server
                    Error = $_
                    ServerResponding = $ServerResponding
                    ServerWSManrunning = $ServerWSManrunning
                    Ignored = $false
                }
                $FailedServers = $FailedServers + $FailObject
            }
        } else {
            Write-Warning "Failed to gather information from server: $($server.Name)"
            Write-Log -Log $LogFilePath -Type WARNING -Text "Failed to gather information from server: $($server.Name)"
            $FailObject = [PSCustomObject]@{
                ComputerName = $Server.Name
                Server = $Server
                Error = $null
                ServerResponding = $ServerResponding
                ServerWSManrunning = $ServerWSManrunning
                Ignored = $false
            }
            $FailedServers = $FailedServers + $FailObject
        } # else server not responding fine
    } else {
        Write-Verbose "Ignored server: $($Server.Name)"
        Write-Log -Log $LogFilePath -Type INFO -Text "Ignored server: $($Server.Name)"
        $FailObject = [PSCustomObject]@{
            ComputerName = $Server.Name
            Server = $Server
            Error = $null
            ServerResponding = $null
            ServerWSManrunning = $null
            Ignored = $true
        }
        $FailedServers = $FailedServers + $FailObject
    } # else ignored
} # main foreach


# END MAIN INFO GATHERING LOOP
##########################################################

#########################################################
# BEGIN VMWARE

$VMWareInfo = @()
if ($VCentersAndESXIHosts.count -gt 0) {
    Write-Verbose "Beginning info gathering from VMWare servers: $($VCentersAndESXIHosts -join ', ')"
    Write-Log -Log $LogFilePath -Type INFO -Text "Beginning info gathering from VMWare servers: $($VCentersAndESXIHosts -join ', ')"
    $PowerCLICfg = Get-PowerCLIConfiguration -Scope Session
    # Set friendly powercli config
    Set-PowerCLIConfiguration -ProxyPolicy UseSystemProxy -DefaultVIServerMode Multiple -InvalidCertificateAction Ignore -ParticipateInCeip $false -CEIPDataTransferProxyPolicy UseSystemProxy -DisplayDeprecationWarnings $true -WebOperationTimeoutSeconds 600 -Confirm:$false -Scope Session | Out-Null
    $ConnectedVMwareList = @()
    $FailedVMwareList = @()
    foreach ($Server in $VCentersAndESXIHosts) {
        $CanPing = Test-Connection -ComputerName $Server -Quiet -Count 2
        if ($CanPing -eq $true) {
            Write-Verbose "Ping successful to: $server"
            Write-Log -Log $LogFilePath -Type INFO -Text "Ping successful to: $server"
            try {
                # TODO: Add export + import of credentials for easy re-use (run as service account)
                # Below works for same user on same machine only (encrypts the password only) - Run as the user running the script not the principal
                # $Cred = Get-Credential Domain\User | Export-CliXml .\Credential.xml
                # $ImportedCred = Import-CliXml .\credential.xml
                $VIServer = Connect-VIServer -Server $Server -ErrorAction Stop # -Credential $ImportedCred
                $ConnectedVMwareList += $VIServer
                $VMList = Get-VM -Server $VIServer | ForEach-Object -Process { Add-Member -InputObject $_ -MemberType NoteProperty -Name VIServer -Value $server }
                $SnapshotList = $VMList | Get-Snapshot -Server $VIServer | ForEach-Object -Process { Add-Member -InputObject $_ -MemberType NoteProperty -Name VIServer -Value $server }
                $Datastores = Get-Datastore -Server $VIServer | ForEach-Object -Process { Add-Member -InputObject $_ -MemberType NoteProperty -Name VIServer -Value $server }
                $ESXEvents = Get-VIEvent -Server $VIServer | Sort-Object -Property CreatedTime -Descending | Select-Object -First 20 | ForEach-Object -Process { Add-Member -InputObject $_ -MemberType NoteProperty -Name VIServer -Value $server }
                $VMWareServer = [PSCustomObject]@{
                    VMs = $VMList
                    VMSnapshots = $SnapshotList
                    Datastores = $Datastores
                    LastEvents = $ESXEvents
                }
                $VMWareInfo = $VMWareInfo + $VMWareServer
            } # try
            catch {
                Write-Error "Error with server: $server"
                Write-Log -Log $LogFilePath -Type ERROR -Text "Error with server: $server"
                $FailedVMwareList += [PSCustomObject]@{
                    Server = $Server
                    Error = $_
                    CanPing = $true
                }
            }
        } else {
            Write-Error "Ping unsuccessful to: $server"
            Write-Log -Log $LogFilePath -Type ERROR -Text "Ping unsuccessful to: $server"
            $FailedVMwareList += [PSCustomObject]@{
                Server = $Server
                Error = $null
                CanPing = $false
            }
        } # else can ping
    } # foreach vmware server
    
    # Set it back to how it was
    Set-PowerCLIConfiguration -ProxyPolicy ($PowerCLICfg.ProxyPolicy) -DefaultVIServerMode ($PowerCLICfg.DefaultVIServerMode) -InvalidCertificateAction ($PowerCLICfg.InvalidCertificateAction) -ParticipateInCeip ($PowerCLICfg.ParticipateInCeip) -CEIPDataTransferProxyPolicy ($PowerCLICfg.CEIPDataTransferProxyPolicy) -DisplayDeprecationWarnings ($PowerCLICfg.DisplayDeprecationWarnings) -WebOperationTimeoutSeconds ($PowerCLICfg.WebOperationTimeoutSeconds) -Confirm:$false -Scope Session | Out-Null
} # vmware servers specified

# END VMWARE
#########################################################

##########################################################
# BEGIN OUTPUT

if ($null -eq $CSSHeaders) {
    Write-Warning "CSSHeaders variable not found, using system default"
    Write-Log -Log $LogFilePath -Type WARNING -Text "CSSHeaders variable not found, using system default"
    $CSSHeaders = @"
<style type="text/css">
body {
	font-family: Verdana, Geneva, Arial, Helvetica, sans-serif;
  	margin: auto;
	max-width: 85%;
}

table {
	border-collapse: collapse;
	border: 1px black solid;
	font: 10pt Verdana, Geneva, Arial, Helvetica, sans-serif;
	color: black;
	margin-bottom: 10px;
	box-shadow: 10px 10px 5px #888;
}
 
table td {
	color: #000;
	font-size: 12px;
	padding-left: 0px;
	padding-right: 20px;
	text-align: left;
}
 
table th {
	color: #fff;
	background: #276dab;
	font-size: 12px;
	font-weight: bold;
	padding-left: 0px;
	padding-right: 20px;
	text-align: left;
}


h1 {
	text-align: center;
	clear: both; font-size: 130%;
	color:#354B5E;
	font-family: Verdana, Geneva, Arial, Helvetica, sans-serif;
}

h2 {
	clear: both; font-size: 115%;
	color:#354B5E;
	font-family: Verdana, Geneva, Arial, Helvetica, sans-serif;
}

h3 {
	clear: both;
	font-size: 100%;
	margin-left: 20px;
	margin-top: 30px;
	color:#475F77;
	font-family: Verdana, Geneva, Arial, Helvetica, sans-serif;
}

h4 {
	clear: both;
	font-size: 75%;
	margin-left: 20px;
	margin-top: 30px;
	color:#475F77;
	font-family: Verdana, Geneva, Arial, Helvetica, sans-serif;
}

p {
	margin-left: 20px;
	font-size: 12px;
}

.alert {
	color: red;
	font-weight: bold;
	}
 
table.list{ float: left; }
 
table.list td:nth-child(1) {
	font-weight: bold;
	border-right: 1px grey solid;
	text-align: right;
}
 
table.list td:nth-child(2) { padding-left: 7px; }
table tr:nth-child(even) td:nth-child(even) { background: #ececec; }
table tr:nth-child(odd) td:nth-child(odd) { background: #c8c8c8; }
table tr:nth-child(even) td:nth-child(odd) { background: #ececec; }
table tr:nth-child(odd) td:nth-child(even) { background: #c8c8c8; }
div.column { width: 320px; float: left; }
div.first{ padding-right: 20px; border-right: 3px grey solid; }
div.second{ margin-left: 30px; }
table{ margin-left: 20px; }

</style>
"@
}

$fragments = @()
$fragments = $fragments + "<H1>ECI Coverage Report - $(Get-Date)</H1>"

# AD Fragements
foreach ($domain in $AllDomainInfo) {
    $DomainString = '<div id="report"><table>
    <colgroup><col/><col/></colgroup>
    <tr><th>Attribute</th><th>Value</th></tr>'
    #$ColourCoded = ''
    
    foreach ($Property in ($domain.PSObject.Properties.name)) {
        $DomainString = $DomainString + ("<tr><td>$Property</td>" + "<td>" + ($domain.psobject.Properties | Where-Object -FilterScript {$_.name -eq $Property}).value + "</td></tr>")
    
    }
    $DomainString = $DomainString + "</table>"
    $ObjectInfo = ($AllDomainObjectInfo | Where-Object -FilterScript {$_.DomainName -eq $Domain.DomainName} | Select-Object DomainName,OUVulnerableToAccidentalDeletion,UsersWithNoPasswordExpiry,UsersWithReversiblePWEncryption,GPOChanges)
    $ObjectString = "<table>
    <colgroup><col/><col/></colgroup>
    <tr><th>Object</th><th>Value</th></tr>"
    foreach ($Property in ($ObjectInfo.PSObject.Properties.name)) {
        $ObjectString = $ObjectString + ("<tr><td>$Property</td>" + "<td>" + ($ObjectInfo.psobject.Properties | Where-Object -FilterScript {$_.name -eq $Property}).value + "</td></tr>")
    }
    $ObjectString = $ObjectString + "</table>"
    $fragments = $fragments + ("<H2>DomainInfo: $($domain.DomainName)</H2>" + $DomainString + "<br><H2>MonitoredADObjects: $($Domain.DomainName)</H2>" + $ObjectString + "<br>")
}

# DC Info fragments
$AllDCInfo = Select-Data -Data $AllDCInfo -Category 'Domain Controllers' -DefaultFilters $DefaultFilters
$fragments = $fragments + (Format-HTMLTable -Data $AllDCInfo -ConditionalFormatting $ConditionalFormatting -Category 'Domain Controllers')

# DC diag fragments
$DCDiagResults = Select-Data -Data $DCDiagResults -Category 'DCDiag Results' -DefaultFilters $DefaultFilters
$fragments = $fragments + (Format-HTMLTable -Data $DCDiagResults -ConditionalFormatting $ConditionalFormatting -Category 'DCDiag Results')

# DFSR fragments
$AllDCBacklogs = Select-Data -Data $AllDCBacklogs -Category 'SYSVOL Backlog' -DefaultFilters $DefaultFilters
$fragments = $fragments + ((Format-HTMLTable -Data $AllDCBacklogs -ConditionalFormatting $ConditionalFormatting -Category 'SYSVOL Backlog') + "<p>A file count of -1 means the DFSR management tools are not installed</p>")

# Failed DCs
if ($FailedDCInfo.Count -gt 0) {
    $fragments = $fragments + '<br>------------------------------------------------------------------------------------------------------------------------------------<br>'
    $FailedDCInfo = Select-Data -Data $FailedDCInfo -Category 'Unresponsive Domain Controllers' -DefaultFilters $DefaultFilters
    $fragments = $fragments + (Format-HTMLTable -Data $FailedDCInfo -ConditionalFormatting $ConditionalFormatting -Category 'Unresponsive Domain Controllers')
}

# Failed servers
if ($FailedServers.Count -gt 0) {
    $fragments = $fragments + '<br>------------------------------------------------------------------------------------------------------------------------------------<br>'
    $FailedServers = Select-Data -Data $FailedServers -Category 'Unresponsive servers' -DefaultFilters $DefaultFilters
    $fragments = $fragments + (Format-HTMLTable -Data $FailedServers -ConditionalFormatting $ConditionalFormatting -Category 'Unresponsive servers')
}

# VMWare Vcenter fragments
if ($VCentersAndESXIHosts.count -gt 0) {
    $fragments = $fragments + '<br>------------------------------------------------------------------------------------------------------------------------------------<br>'
    $fragments = $fragments + '<H1>VMWare Infrastructure</H1>'

    # unresponsive servers
    if ($FailedVMwareList.count -gt 0) {
        $FailedDCInfo = Select-Data -Data $FailedVMwareList -Category 'Unresponsive VMWare Servers' -DefaultFilters $DefaultFilters
        $fragments = $fragments + (Format-HTMLTable -Data $FailedVMwareList -ConditionalFormatting $ConditionalFormatting -Category 'Unresponsive VMWare Servers')
    }
    
    $UniqueProperties = @()
    foreach ($Item in $VMWareInfo) {
        $UniqueProperties = $UniqueProperties + ($Item.PSObject.Properties.name)
    }
    $UniqueProperties = $UniqueProperties | Select-Object -Unique | Sort-Object
    Write-Verbose "Unique server properties: $($UniqueProperties | Out-String)"
    Write-Log -Log $LogFilePath -Type INFO -Text "Unique server properties: $($UniqueProperties | Out-String)"
    foreach ($Property in $UniqueProperties) {
        $info = $VMWareInfo | Select-Object -ExpandProperty $Property -ErrorAction SilentlyContinue
        $FilteredInfo = Select-Data -Data $info -Category $Property -DefaultFilters $DefaultFilters
        if ($null -ne $FilteredInfo) {
            $fragments = $fragments + (Format-HTMLTable -Data $FilteredInfo -ConditionalFormatting $ConditionalFormatting -Category $Property)
        } # not null info
    } # foreach property
} # VMWare Servers specified

$fragments = $fragments + '<br>------------------------------------------------------------------------------------------------------------------------------------<br>'
$fragments = $fragments + '<H1>All Server Information</H1>'

# Server Info fragments

##################################
$UniqueProperties = @()
foreach ($ServerInfo in $AllServerInfo) {
    $UniqueProperties = $UniqueProperties + ($ServerInfo.PSObject.Properties.name)
}
$UniqueProperties = $UniqueProperties | Select-Object -Unique | Sort-Object
Write-Verbose "Unique server properties: $($UniqueProperties | Out-String)"
Write-Log -Log $LogFilePath -Type INFO -Text "Unique server properties: $($UniqueProperties | Out-String)"
foreach ($Property in $UniqueProperties) {
    $info = $AllServerInfo | Select-Object -ExpandProperty $Property -ErrorAction SilentlyContinue
    $FilteredInfo = Select-Data -Data $info -Category $Property -DefaultFilters $DefaultFilters
    if ($null -ne $FilteredInfo) {
        $fragments = $fragments + (Format-HTMLTable -Data $FilteredInfo -ConditionalFormatting $ConditionalFormatting -Category $Property)
    } # not null info
} # foreach property
##################################
$fragments = $fragments + "</div>"

# Build HTML file
$OutputHTMLFile = ConvertTo-Html -Body ($fragments -join '') -Head $CSSHeaders
if ($null -eq (Get-Item -Path "$PSScriptRoot\Reports" -ErrorAction SilentlyContinue)) { mkdir "$PSScriptRoot\Reports" | Out-Null }
$OutputHTMLFile | Out-File -FilePath "$PSScriptRoot\Reports\Report-$Today.html" -Encoding ascii -Force
Write-Verbose "HTML File output path: $PSScriptRoot\Reports\Report-$Today.html"
Write-Log -Log $LogFilePath -Type INFO -Text "HTML File output path: $PSScriptRoot\Reports\Report-$Today.html"

if ($IsVerbose) {
    Invoke-Item -Path "$PSScriptRoot\Reports\Report-$Today.html"
}

# Output to PDF?
# https://wkhtmltopdf.org/usage/wkhtmltopdf.txt

if ($SendEmail) {
    Write-Verbose "Sending email to: $($TargetEmail -join ', ')"
    Write-Log -Log $LogFilePath -Type INFO -Text "Sending email to: $($TargetEmail -join ', ')"
    Send-MailMessage -To $TargetEmail -From $FromEmail -Port $MailPort -SmtpServer $MailServer -Attachments ("$PSScriptRoot\Reports\Report-$Today.html") -BodyAsHtml -Body (Get-Content -Path "$PSScriptRoot\Reports\Report-$Today.html" -Raw) -Subject $MailSubject -ErrorAction Continue
}

# END OUTPUT
##########################################################

Write-Verbose "END OF SCRIPT - $(Get-Date)"
Write-Log -Log $LogFilePath -Type INFO -Text "END OF SCRIPT - $(Get-Date)"
