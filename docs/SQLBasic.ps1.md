---
external help file: -help.xml
Module Name:
online version: https://public.cyber.mil/stigs/
schema: 2.0.0
---

# SQLBasic.ps1

## SYNOPSIS

This script will compile a DSC MOF configuration file for a basic SQL Server 2016 installation.

## SYNTAX

```PowerShell
SQLBasic.ps1 [[-Destination] <String>] [-SqlServiceCred] <PSCredential> [-AgtServiceCred] <PSCredential>
 [[-SysAdmins] <String[]>] [<CommonParameters>]
```

## DESCRIPTION

Run this script to create a Desired State Configuration MOF file.
The MOF file can then be placed on the pull server and distributed.
The default feature for this configuration is the SQL DB Engine but other supported features can be added as needed.

## EXAMPLES

### EXAMPLE 1

```PowerShell
SQLBasic -ComputerName 'localhost' -OutputPath "C:\Temp" -Verbose
```

This example will compile a MOF file from the 'SQLBasic' DSC onfiguration script.

## PARAMETERS

### -AgtServiceCred

PSCredential object for the SQL Agent service account.

```yaml
Type: PSCredential
Parameter Sets: (All)
Aliases:

Required: True
Position: 3
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Destination

Output path for the compiled MOF file.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SqlServiceCred

PSCredential object for the SQL service account.

```yaml
Type: PSCredential
Parameter Sets: (All)
Aliases:

Required: True
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SysAdmins

String array of sysadmin user names or group names to add to the SQL server permissions.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases:

Required: False
Position: 4
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

Important: Some parameter values presented in this script may be examples only and should be changed before this script is used in a testing or production scenario.
Carefully review all configuration values before deployment.

Items denoted with a 'V' and a five digit number (Example: 'V-73287') are configuration items from the official DISA STIG reference guides.
Each 'V' number corresponds to a STIG finding.

Important: This DSC configuration script also makes use of a PSD data file for full configuration flexibility.
The accompanying SQLBasic.psd1 file contains default/example values for some items and should be updated before using this configuration.

Example values for DB mail parameters:

- DBMailAccountName  = 'Database Mail'
- DBMailOperatorName = 'DBA Team'
- DBMailEmailAddress = 'dbateam@corp.com'
- DBMailServerName   = 'smtp.corp.com'

The values in this script use the following example disk layout for a SQL installation:

- C: - OS - 96-128 GB
- B: - Backups - 50 GB
- E: - Data - 50 GB
- L: - Logs - 20 GB
- S: - Program Files - 30 GB
- T: - Temp DB - 20 GB

Author: Mike Nickerson

## RELATED LINKS

[https://public.cyber.mil/stigs/](https://public.cyber.mil/stigs/)

[https://stigviewer.com/stig/ms_sql_server_2016_database/](https://stigviewer.com/stig/ms_sql_server_2016_database/)

[https://stigviewer.com/stig/ms_sql_server_2016_instance/](https://stigviewer.com/stig/ms_sql_server_2016_instance/)
