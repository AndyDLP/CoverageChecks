<#
Define a filter for the outputted data - Will supercede any default filters 
To add more filters, clone the below and remove the hashes (#) to enable it.
Make sure that for multiple filters, you have a comma between filter definitions

This does not apply for AD info / Domain controller info / DFSR info (yet)

Possible values for filters:
 - Category   = Whatever the heading is before the table in the outputted report, can change with additional data
 - Type       = Property - For defining thresholds on a property e.g. The example below can be changed to only show Disks with the property 'PercentFree' of less than 30 (%) by change the value to 30
              = Display  - For defining what properties show and how to sort the output table. Some filters are already in place with this option
              = Hidden   - Set to this option to fully hide the category (even if there are potential issues within it)
 - Property   = [Only available for a filter type of Property] - Specify the property name / column header to filter on
 - Comparison = [Only available for a filter type of Property] - Specify the comparison i.e. greater than or less than.
                See PowerShell comparison operators: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_operators?view=powershell-6
 - Value      = [Only available for a filter type of Property] - Specify the value to filter against







#>

$DefaultFilters = @(
    [PSCustomObject]@{
        Category = 'Disks'
        Type = 'Property'
        Property = 'PercentFree'
        Comparison = '-lt'
        Value = 100
    },
    [PSCustomObject]@{
        Category = 'Disks'
        Type = 'Display'
        Action = 'Include'
        Properties = '*'
        SortingProperty = 'PercentFree'
        SortingType = 'Ascending'
    },
    [PSCustomObject]@{
        Category = 'ExpiredSoonCertificates'
        Type = 'Display'
        Action = 'Include'
        Properties = @('ComputerName','Subject','Issuer','NotBefore','NotAfter','Thumbprint','HasPrivateKey')
        SortingProperty = 'ComputerName'
        SortingType = 'Ascending'
    },
    [PSCustomObject]@{
        Category = 'GeneralInformation'
        Type = 'Display'
        Action = 'Include'
        Properties = '*'
        SortingProperty = 'ComputerName'
        SortingType = 'Ascending'
    },
    [PSCustomObject]@{
        Category = 'LocalAdministrators'
        Type = 'Display'
        Action = 'Include'
        Properties = '*'
        SortingProperty = 'ComputerName'
        SortingType = 'Ascending'
    },
    [PSCustomObject]@{
        Category = 'NonStandardScheduledTasks'
        Type = 'Display'
        Action = 'Include'
        Properties = @('HostName','TaskName','Status','Next Run Time','Last Run Time','Last Result','Author','Run As User','Schedule Type')
        SortingProperty = @('ComputerName','Last Run Time')
        SortingType = 'Ascending'
    },
    [PSCustomObject]@{
        Category = 'NonStandardServices'
        Type = 'Display'
        Action = 'Include'
        Properties = @( @{n='ComputerName';e={$_.SystemName}},'Name','DisplayName','State','StartMode','StartName','PathName')
        SortingProperty = 'ComputerName'
        SortingType = 'Ascending'
    },
    [PSCustomObject]@{
        Category = 'PendingReboot'
        Type = 'Display'
        Action = 'Include'
        Properties = @( @{n='ComputerName';e={$_.Computer}},'CBServicing','WindowsUpdate','PendComputerRename','RebootPending','CCMClientSDK' )
        SortingProperty = 'ComputerName'
        SortingType = 'Ascending'
    },
    [PSCustomObject]@{
        Category = 'SharedPrinters'
        Type = 'Display'
        Action = 'Include'
        Properties = @('ComputerName','Printername','IsPingable','PublishedToAD','PrinterAddress','PrinterDriver')
        SortingProperty = 'ComputerName','PrinterName'
        SortingType = 'Ascending'
    },
    [PSCustomObject]@{
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