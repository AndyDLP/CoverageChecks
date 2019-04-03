#region Filters
<#
Define a filter for the outputted data
Make sure that for multiple filters, you have a comma between filter definitions

This does not apply for AD info / Domain controller info / DFSR info (yet)

Possible values for filters:
 - Category        = Whatever the heading is before the table in the outputted report, can change with additional data
 - Type            = Property - For defining thresholds on a property e.g. The example below can be changed to only show Disks with the property 'PercentFree' of less than 30 (%) by change the value to 30
                   = Display  - For defining what properties show and how to sort the output table. Some filters are already in place with this option
                   = Colour   - For defining a level or threshold at which the property will show in a colour (red for now)
                   = Hidden   - Set to this option to fully hide the category (even if there are potential issues within it)
 - Property        = [Only available for a filter types: Property & Colour] - Specify the property name / column header to filter on
 - Comparison      = [Only available for a filter types: Property & Colour] - Specify the comparison i.e. greater than or less than.
                     See PowerShell comparison operators: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_operators?view=powershell-6
 - Value           = [Only available for a filter types: Property & Colour] - Specify the value to filter against

 - Action          = [Only available for a filter type of Display] - Specify whether to Include or Exclude properties
 - Properties      = [Only available for a filter type of Display] - Specify which properties (As a comma separated list of strings) to show / hide. Enter a star "*" for all properties. Is passed verbatim to Select-Object so hashtables work for renaming column headers
 - SortingProperty = [Only available for a filter type of Display] - Specify a property to sort the resulting table on
 - SortingType     = [Only available for a filter type of Display] - Specify the sorting type to use; either Ascending or Descending

 - 
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
        Category = 'Disks'
        Type = 'Colour'
        Property = 'PercentFree'
        Comparison = '-lt'
        Value = 100
    },
    @{
        Category = 'Disks'
        Type = 'Display'
        Action = 'Include'
        Properties = '*'
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
        Properties = '*'
        SortingProperty = 'ComputerName'
        SortingType = 'Ascending'
    },
    @{
        Category = 'LocalAdministrators'
        Type = 'Display'
        Action = 'Include'
        Properties = '*'
        SortingProperty = 'ComputerName'
        SortingType = 'Ascending'
    },
    @{
        Category = 'NonStandardScheduledTasks'
        Type = 'Display'
        Action = 'Include'
        Properties = @('HostName','TaskName','Status','Next Run Time','Last Run Time','Last Result','Author','Run As User','Schedule Type')
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

# Specify a list of VCenter servers or ESXI hosts to gather information from
# It is assumed that AD authentication has been enabled for the user running this script
$VCentersAndESXIHosts = @()

# A comma separated list of servers names (strings) that will not be target for information gathering
$IgnoredServers = @(
    'HV-01',
    'JENKINS',
    'PSTEST',
    'SCCM-01',
    'PASSWORDSTATE',
    'SCVMM',
    'GLR-WIN1',
    'SQL-01',
    'SRV1'
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
    $MailSubject = "ECI Coverage Checks - $(Get-Date)"
}
#endregion