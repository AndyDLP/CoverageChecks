# Engineer Coverage Checks Script / Project

## Version 1.0 Information Gathered

- Active Directory:
  - Domain controller list:
  - Version of OS
  - Disk usage on AD DS volume(s)
  - Global catalog state
  - AD DS service status (netlogon, NTDS & DNS)
  - Domain / Forest info
  - Domain functional level
  - Forest functional level
  - SYSVOL accessibility
  - NETLOGON accessibility
  - Operations masters
  - SYSVOL DFSR backlog
- Object info
  - Users with non-expiring passwords
  - Users with PW stored with reversible encryption
  - Count of OUs / containers / critical objects without protection from accidental deletion
- General server info:
  - Stopped auto-starting services & those with non-standard users (i.e. eciadmin or other domain accounts)
  - Local administrator list
  - Disk space on all volumes
  - Non-SYSVOL DFSR Backlogs
  - Get pending reboots
  - Find all printers and check state
  - Find all scheduled tasks running under local or domain / administrative accounts
  - Last Windows update check
  - Certificates with < 30 days until expiry


## To do

- Check DFSR
- Check Disk Space
- Check RAM and CPU usage
- Check Critical and Error event logs 
- Check automatic services that are started 
- Exchange (DAG, DB, Connectivity)
- DCs 
- Uptime 
- DNS 
- VMware ESX
