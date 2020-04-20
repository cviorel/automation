<#
    .SYNOPSIS
        This script will create a new SQL DB for DSC. You must run this script from the SQL server that will host the DSC DB.

    .DESCRIPTION
        Run this script to create a new SQL database on the specified SQL server and apply permissions to the new DB for the pull server(s) AD computer accounts.

    .PARAMETER SQLServerName
        The name of the SQL server that will host the DSC database.
        Example: 'MySQLServer.corp.com'
        Required: False
        Type: String
        Parameter Sets: All
        Position: Named
        Default Value: none
        Accept pipeline input: False
        Accept wildcard characters: False

    .EXAMPLE
        PS C:\> CreateDSCDB.ps1 -SQLServerName "MySQLServer"

        The script will create a database named "DSC" on the SQL server named "MySQLServer".

    .NOTES
        Author: Mike Nickerson
#>

[cmdletbinding()]
param (
    [parameter(HelpMessage = "The name of the SQL server where the DSC database is hosted. The default is the local computer.")]
    [string]$SQLServerName = $env:COMPUTERNAME
)

$query = Get-Content -Path .\CreateDSCPullDB.sql

$checkDB = @'
SELECT name FROM sys.databases WHERE name='DSC'
'@

$addPermissionsQuery = @'
CREATE LOGIN [{0}\{1}] FROM WINDOWS WITH DEFAULT_DATABASE=[master], DEFAULT_LANGUAGE=[us_english];
GO

USE [DSC]

CREATE USER [{1}] FOR LOGIN [{0}\{1}] WITH DEFAULT_SCHEMA=[db_datareader]
GO

ALTER ROLE [db_datareader] ADD MEMBER [{1}]
GO

ALTER ROLE [db_datawriter] ADD MEMBER [{1}]
GO

ALTER ROLE [db_owner] ADD MEMBER [{1}]
GO
'@

# Check to see if the DSC DB is already created
$dbExists = Invoke-Sqlcmd -Query $checkDB -ServerInstance "$SQLServerName,1433"
if (!($dbExists)) {
    Write-Output "Creating the new DSC DB on $SQLServerName..."
    try {
        Invoke-Sqlcmd -Query $query -ServerInstance "$SQLServerName,1433"
    }
    catch {
        Write-Warning -Message "Unable to create DSC database."
        $_.Exception.Message
    }
}
else {
    Write-Output "The database already exists. Continuing..."
}

# Set up SQL logins and assign DB rights
Write-Output "Creating DSC Pull Server computer account logins and assigning rights to the DSC DB..."
$sysDomain = "NT AUTHORITY"
$sysName = "SYSTEM"
$querySys = $addPermissionsQuery -f $sysDomain, $sysName

$domain = ($dscPullserver -split '\\')[0]
$domain = $domain.ToUpper()

$name = ($dscPullserver -split '\\')[1]
$name = $name.ToUpper() + "`$"

$query = $addPermissionsQuery -f $domain, $name

# Add 'NT AUTHORITY\SYSTEM' and assign rights to the DSC DB
Invoke-Sqlcmd -Query $querySys -ServerInstance "$sqlServername,1433"

# Add DSC pull server computer account and assign rights to the DSC DB
try {
    Invoke-Sqlcmd -Query $query -ServerInstance "$sqlServername,1433"
}
catch {
    $_.Exception.Message
}
