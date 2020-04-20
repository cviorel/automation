---
external help file: -help.xml
Module Name:
online version: https://public.cyber.mil/stigs/
schema: 2.0.0
---

# WindowsBaseOS.ps1

## SYNOPSIS

This script will compile a DSC MOF configuration file.

## SYNTAX

```PowerShell
WindowsBaseOS.ps1 [[-Destination] <String>] [[-AdminName] <String>] [[-GuestName] <String>]
 [<CommonParameters>]
```

## DESCRIPTION

Run this script to create a Desired State Configuration MOF file that covers the settings needed for a hardened Windows OS installation.

## EXAMPLES

### EXAMPLE 1

```PowerShell
WindowsBaseOS -ComputerName 'localhost' -OutputPath "C:\Temp" -Verbose
```

This example will compile a MOF file from the 'WindowsBaseOS' DSC onfiguration script.

## PARAMETERS

### -AdminName

New name for the local administrator account.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
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

### -GuestName

New name for the local guest account.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 3
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

If a logon message is required, be sure to edit lines 1098 & 1099 as appropriate.
(See Windows Server 2016 STIG findings V-73647 & V-73649)

Author: Mike Nickerson

## RELATED LINKS

[https://public.cyber.mil/stigs/](https://public.cyber.mil/stigs/)

[https://stigviewer.com/stig/windows_server_2016/](https://stigviewer.com/stig/windows_server_2016/)
