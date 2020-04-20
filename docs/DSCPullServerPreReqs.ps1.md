---
external help file: -help.xml
Module Name:
online version:
schema: 2.0.0
---

# DSCPullServerPreReqs.ps1

## SYNOPSIS

Installs required PowerShell DSC modules on a pull server.

## SYNTAX

```PowerShell
DSCPullServerPreReqs.ps1 [<CommonParameters>]
```

## DESCRIPTION

Installs required PowerShell DSC modules on a pull server as a pre-requisite for deploying a new pull server or updating the DSC modules on a currently deployed server.

## EXAMPLES

### EXAMPLE 1

```PowerShell
DSCPullServerPreReqs.ps1
```

When run on the pull server itself, this script will download and install the specified modules with the specified versions.
You must ensure the correct module names and versions are listed.
The script will attempt to install the modules from the Microsoft PowerShell Gallery (PSGallery) and then will attempt to use any other configured repositories if the PSGallery is inaccessible or does not host the required modules.

## PARAMETERS

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

Author: Mike Nickerson

## RELATED LINKS
