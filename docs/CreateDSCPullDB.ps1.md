---
external help file: -help.xml
Module Name:
online version:
schema: 2.0.0
---

# CreateDSCPullDB.ps1

## SYNOPSIS

This script will create a new SQL DB for DSC.
You must run this script from the SQL server that will host the DSC DB.

## SYNTAX

```PowerShell
CreateDSCPullDB.ps1 [[-SQLServerName] <String>] [<CommonParameters>]
```

## DESCRIPTION

Run this script to create a new SQL database on the specified SQL server and apply permissions to the new DB for the pull server(s) AD computer accounts.

## EXAMPLES

### EXAMPLE 1

```PowerShell
CreateDSCDB.ps1 -SQLServerName "MySQLServer"
```

The script will create a database named "DSC" on the SQL server named "MySQLServer".

## PARAMETERS

### -SQLServerName

The name of the SQL server that will host the DSC database.
Example: 'MySQLServer.corp.com'
Required: False
Type: String
Parameter Sets: All
Position: Named
Default Value: none
Accept pipeline input: False
Accept wildcard characters: False

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: $env:COMPUTERNAME
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

Author: Mike Nickerson

## RELATED LINKS
