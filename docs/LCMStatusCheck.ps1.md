---
external help file: -help.xml
Module Name:
online version: https://docs.microsoft.com/en-us/powershell/scripting/dsc/pull-server/update-nodes-manually?view=powershell-7
schema: 2.0.0
---

# LCMStatusCheck.ps1

## SYNOPSIS

Build pipeline utility script for checking DSC node status.

## SYNTAX

```PowerShell
LCMStatusCheck.ps1 [-Node] <String> [<CommonParameters>]
```

## DESCRIPTION

Build pipeline utility script for checking DSC node status.

## EXAMPLES

### EXAMPLE 1

```PowerShell
LCMStatusCheck.ps1 -Node "MyNode"
```

Runs the script and checks the specified DSC node for the LCM configuration status.

## PARAMETERS

### -Node

Computer name to test.
Example: 'DSC-Client01'
Required: True
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

Required: True
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

[https://docs.microsoft.com/en-us/powershell/scripting/dsc/pull-server/update-nodes-manually?view=powershell-7](https://docs.microsoft.com/en-us/powershell/scripting/dsc/pull-server/update-nodes-manually?view=powershell-7)

[https://docs.microsoft.com/en-us/powershell/scripting/dsc/managing-nodes/metaconfig?view=powershell-7](https://docs.microsoft.com/en-us/powershell/scripting/dsc/managing-nodes/metaconfig?view=powershell-7)
