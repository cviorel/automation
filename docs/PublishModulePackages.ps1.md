---
external help file: -help.xml
Module Name:
online version:
schema: 2.0.0
---

# PublishModulePackages.ps1

## SYNOPSIS

This script stages required PowerShell DSC modules on a pull server.

## SYNTAX

```PowerShell
PublishModulePackages.ps1 [<CommonParameters>]
```

## DESCRIPTION

After deploying and configuring a web-based pull server, the script will attempt to download and stage the required DSC modules for client configurations.
Any needed modules will be downloaded and installed from the Microsoft PowerShell Gallery or other configured repository.

## EXAMPLES

### EXAMPLE 1

```PowerShell
Publish-ModulePackages -ModuleList @("AuditPolicyDSC", "SecurityPolicyDSC")
```

This example will download and stage the specified PowerShell modules for use on a DSC pull server.

## PARAMETERS

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

Author: Mike Nickerson

## RELATED LINKS
