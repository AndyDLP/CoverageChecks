#region config
<#
Define a filter for the outputted data
Make sure that for multiple filters, you have a comma between filter definitions

This does not apply for AD info / Domain controller info / SYSVOL backlog info (yet)

Possible values for filters:
 - Category        = Whatever the heading is before the table in the outputted report, can change with additional data
 - Type            = Property - For defining thresholds on a property e.g. The example below can be changed to only show Disks with the property 'PercentFree' of less than 30 (%) by change the value to 30
                   = Display  - For defining what properties show and how to sort the output table. Some filters are already in place with this option
                   = Hidden   - Set to this option to fully hide the category (even if there are potential issues within it)
 - Property        = [Only available for a filter types: Property] - Specify the property name / column header to filter on
 - Comparison      = [Only available for a filter types: Property] - Specify the comparison i.e. greater than or less than.
                     See PowerShell comparison operators: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_operators?view=powershell-6
 - Value           = [Only available for a filter types: Property] - Specify the value to filter against

 - Action          = [Only available for a filter type of Display] - Specify whether to Include or Exclude properties
 - Properties      = [Only available for a filter type of Display] - Specify which properties (As a comma separated list of strings) to show / hide. Enter a star "*" for all properties. Is passed verbatim to Select-Object so hashtables work for renaming column headers
 - SortingProperty = [Only available for a filter type of Display] - Specify a property to sort the resulting table on
 - SortingType     = [Only available for a filter type of Display] - Specify the sorting type to use; either Ascending or Descending

#>

$DefaultFilters = @(
    @{
        Category = 'Disks'
        Type = 'Property'
        Property = 'PercentFree'
        Comparison = '-lt'
        Value = 100 # only show disks at 100% of less free space (example)
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

<#
Define conditional formatting for the outputted data
Make sure that for multiple conditions, you have a comma between condition definitions

This does not apply for AD info / Domain controller info / SYSVOL backlog info (yet)

Possible values for conditions:
 - Category        = Whatever the heading is before the table in the outputted report
 - Property        = Specify the property name / column header to format on
 - Comparison      = Specify the comparison i.e. greater than or less than.
                     See PowerShell comparison operators: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_operators?view=powershell-6
 - Value           = Specify the value to filter against

#>
$ConditionalFormatting = @(
    @{
        Category = 'DCDiag Results'
        Property = 'Connectivity'
        Comparison = '-eq'
        Value = 'Failed'
    },
    @{
        Category = 'DCDiag Results'
        Property = 'Advertising'
        Comparison = '-eq'
        Value = 'Failed'
    },
    @{
        Category = 'DCDiag Results'
        Property = 'FrsEvent'
        Comparison = '-eq'
        Value = 'Failed'
    },
    @{
        Category = 'DCDiag Results'
        Property = 'DFSREvent'
        Comparison = '-eq'
        Value = 'Failed'
    },
    @{
        Category = 'DCDiag Results'
        Property = 'SysVolCheck'
        Comparison = '-eq'
        Value = 'Failed'
    },
    @{
        Category = 'DCDiag Results'
        Property = 'KccEvent'
        Comparison = '-eq'
        Value = 'Failed'
    },
    @{
        Category = 'DCDiag Results'
        Property = 'KnowsOfRoleHolders'
        Comparison = '-eq'
        Value = 'Failed'
    },
    @{
        Category = 'DCDiag Results'
        Property = 'MachineAccount'
        Comparison = '-eq'
        Value = 'Failed'
    },
    @{
        Category = 'DCDiag Results'
        Property = 'NCSecDesc'
        Comparison = '-eq'
        Value = 'Failed'
    },
    @{
        Category = 'DCDiag Results'
        Property = 'NetLogons'
        Comparison = '-eq'
        Value = 'Failed'
    },
    @{
        Category = 'DCDiag Results'
        Property = 'ObjectsReplicated'
        Comparison = '-eq'
        Value = 'Failed'
    },
    @{
        Category = 'DCDiag Results'
        Property = 'Replications'
        Comparison = '-eq'
        Value = 'Failed'
    },
    @{
        Category = 'DCDiag Results'
        Property = 'RidManager'
        Comparison = '-eq'
        Value = 'Failed'
    },
    @{
        Category = 'DCDiag Results'
        Property = 'Services'
        Comparison = '-eq'
        Value = 'Failed'
    },
    @{
        Category = 'DCDiag Results'
        Property = 'SystemLog'
        Comparison = '-eq'
        Value = 'Failed'
    },
    @{
        Category = 'DCDiag Results'
        Property = 'VerifyReferences'
        Comparison = '-eq'
        Value = 'Failed'
    },
    @{
        Category = 'DCDiag Results'
        Property = 'CheckSDRefDom'
        Comparison = '-eq'
        Value = 'Failed'
    },
    @{
        Category = 'DCDiag Results'
        Property = 'CrossRefValidation'
        Comparison = '-eq'
        Value = 'Failed'
    },
    @{
        Category = 'DCDiag Results'
        Property = 'LocatorCheck'
        Comparison = '-eq'
        Value = 'Failed'
    },
    @{
        Category = 'DCDiag Results'
        Property = 'Intersite'
        Comparison = '-eq'
        Value = 'Failed'
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

# Specify a list of VCenter servers or ESXI hosts to gather information from
# It is assumed that AD authentication has been enabled for the user running this script
# TODO: Add option to specify different credentials (Save to CLIXML?)
$VCentersAndESXIHosts = @()

# A comma separated list of servers names (strings) that will not be target for information gathering
$IgnoredServers = @(
    "BC-LUX-02",	"BC-LUX-DC01",	"BC-NEWYORK-DC1",	"BC-HAMBURG-DC1",	"BC-GUER-DC02",	"BC-SASDC-DC01",	"BC-LONDON-DC01",	"BC-LONDON-AP2",	"BC-LONDON-AP02",	"BC-LONDON-DC1",	"BC-LONDON-AP1",	"BC-LONDON-TS01",	"BC-LONDON-TS02",	"BC-LONDON-TS04",	"BC-LONDON-TS03",	"INTRANET01",	"BC-HAMBURG-RIS",	"BC-STAGING-01",	"BC-STAGING-DE",	"BC-STAGING-IT",	"BC-STAGING-CH",	"BC-LONDON-10",	"BC-SAS-01",	"BC-PARIS-RE",	"BC-LUX-03",	"BC-INTRANET-01",	"BC-GUERNSEY-DC",	"BC-PARIS-DCTEMP",	"BC-PARIS-BB",	"BC-PARIS-DC",	"BC-HAMBURG-02",	"BC-HAMBURG-BB",	"BC-PARIS-01",	"BC-LUX-DC",	"BC-PARIS-02",	"BC-HAMBURG-TS1",	"BC-GUERNSEY-01",	"BC-LONDON-DEV3",	"BC-PARIS-AP1",	"BC-LONDON-07",	"BC-LONDON-AP01",	"BC-LONDON-DEV1",	"BC-LUX-DC1",	"BC-LONDON-DC2",	"BC-LUX-AP3",	"BC-LUX-AP2",	"BC-LONDON-WEB1",	"BC-PARIS-EX2",	"BC-PARIS-EX1",	"BC-LONDON-EX2",	"BC-LONDON-AP4",	"BC-LONDON-AP5",	"BC-LONDON-EX1",	"BC-LONDON-AP7",	"BC-LONDON-04",	"BC-PARIS-BB1",	"BC-LONDON-EV1",	"BC-PARIS-AP3",	"BC-LONDON-AP6",	"BC-NEWYORK-FP1",	"BC-HAMBURG-AP3",	"BC-HAMBURG-AP1",	"BC-LONDON-11",	"BC-LUX-BE01",	"BC-LONDON-PRXY",	"BC-GUER-VCNTR",	"BC-LONDON-BE01",	"BC-PARIS-AP2",	"BC-LONDON-EX02",	"BC-LONDON-EX01",	"BC-LONDON-VCNTR",	"BC-HAMBURG-AP2",	"BC-LUX-EXC02",	"BC-LONDON-CRM13",	"BC-NY-EXC01",	"BC-NEWYORK-AP1",	"BC-SRV_LDN_CRM",	"BC-HAMBURG-EX1",	"BC-LUX-AP1",	"DAG-EXC-US",	"BC-LUX-SRM",	"BC-LUX-EXC01",	"BC-SASDC-EXC01",	"BC-LONDON-SCCM",	"BC-LONDON-BES",	"BC-SQL-TEST",	"BC-LONDON-TS00",	"BC-PARIS-BB2",	"BC-NEWYORK-EX1",	"BC-SASDC-BE01",	"BC-HAMBURG-BU01",	"BC-GUERNSEY-AP1",	"BC-GUER-BE01",	"BC-LONDON-AP05",	"BC-LONDON-05",	"BC-LONDON-EVDA",	"BC-LONDON-AP3",	"BC-LONDON-AP03",	"BC-LONDON-DC02",	"BC-LONDON-NXPSE",	"BC-LONDON-EMS1",	"BC-HAMBURG-EMS1",	"BC-HAMBURG-DC2",	"BC-GUER-SCDP",	"BC-LUX-FP01",	"BC-HAMBURG-AP7",	"BC-GUER-CCH",	"BC-LUX-BE1",	"BC-HAMBURG-SRM",	"BCP-LON-UBA01",	"BCP-GUE-DEVEFRO",	"BC-LONDON-MDM1",	"BC-NEWYORK-DC3",	"BC-LONDON-CAS1",	"BC-HAMBURG-AR1",	"BC-LONDON-08",	"BC-LONDON-VRNS",	"BC-LONDON-VRNSA",	"BC-LONDON-ESM",	"BC-GUER-DB01",	"BC-LONDON-AP04",	"BC-LONDON-DB01",	"BC-HAMBURG-AP5",	"BC-HAMBURG-AR2",	"BCP-GUE-DEVDB01",	"BC-NEWYORK-AP3",	"BC-HAMBURG-AP6",	"BC-HAMBURG-BU2",	"BC-NEWYORK-SRM",	"BC-LONDON-MDM2",	"BC-SASDC-SRMGU",	"BC-GUER-EFRONT",	"BC-LONDON-EV01",	"BC-LONDON-DB02",	"BC-SASDC-SRMLO",	"BC-LONDON-09",	"BC-LUX-EMS1",	"BCP-GUE-ZERTO"
)

# Change to $true to enable reporting sending via email
$SendEmail = $false

# Only define the below if email is enabled
if ($SendEmail -eq $true) {
    # A comma separated list of recipients for the email
    $TargetEmail = @(
    "recipient1@example.com"
    )

    # The SMTP relay that will allow the email
    $MailServer = "mail.example.com"
    
    # Port used for the SMTP relay
    $MailPort = 25
    
    # The from address for the report email
    $FromEmail = "ServerChecks@example.com"
    
    # The subject for the report email 
    $MailSubject = "Coverage Checks - $(Get-Date)"
}

# Report CSS

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

#endregion