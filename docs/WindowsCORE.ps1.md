---
external help file: -help.xml
Module Name:
online version: https://public.cyber.mil/stigs/
schema: 2.0.0
---

# WindowsCORE.ps1

## SYNOPSIS

This script will compile a DSC MOF configuration file.

## SYNTAX

```PowerShell
WindowsCORE.ps1 [[-Destination] <String>] [<CommonParameters>]
```

## DESCRIPTION

This configuration will add domain-specific users and groups to the local Administrators group and will configure User Rights Assignment settings.

Run this script to create a Desired State Configuration MOF file.

## EXAMPLES

### EXAMPLE 1

```PowerShell
WindowsCore -ComputerName 'localhost' -OutputPath "C:\Temp" -Verbose
```

This example will compile a MOF file from the 'WindowsCore' DSC onfiguration script.

## PARAMETERS

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

[https://docs.microsoft.com/en-us/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server](https://docs.microsoft.com/en-us/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server)
