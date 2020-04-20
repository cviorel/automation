---
external help file: -help.xml
Module Name:
online version: https://public.cyber.mil/stigs/
schema: 2.0.0
---

# DomainController.ps1

## SYNOPSIS

This script will compile a DSC MOF configuration file.

## SYNTAX

```PowerShell
DomainController.ps1 [[-Destination] <String>] [<CommonParameters>]
```

## DESCRIPTION

This script will configure a Windows domain controller with STIG-recommended setttings.

Run this script to create a Desired State Configuration MOF file.

## EXAMPLES

### EXAMPLE 1

```PowerShell
DomainController -ComputerName 'localhost' -OutputPath "C:\Temp" -Verbose
```

This example will compile a MOF file from the 'DomainController' DSC onfiguration script.

## PARAMETERS

### -Destination

{{ Fill Destination Description }}

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: D:\git\repos\Automation\DSC\src\configurations\compiled
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

Author: Mike Nickerson

## RELATED LINKS

[https://public.cyber.mil/stigs/](https://public.cyber.mil/stigs/)

[https://stigviewer.com/stig/windows_server_2016/](https://stigviewer.com/stig/windows_server_2016/)
