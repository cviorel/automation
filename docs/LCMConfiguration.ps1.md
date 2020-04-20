---
external help file: -help.xml
Module Name:
online version: https://docs.microsoft.com/en-us/powershell/scripting/dsc/managing-nodes/metaconfig?view=powershell-7
schema: 2.0.0
---

# LCMConfiguration.ps1

## SYNOPSIS

This script will configure the LCM on a DSC client.

## SYNTAX

```PowerShell
LCMConfiguration.ps1 [[-ComputerName] <String>] [-PullServerName] <String> [-RegKey] <String>
 [[-ApplicationType] <String>] [<CommonParameters>]
```

## DESCRIPTION

This script will configure the DSC Local Configuration Manager component to register with the DSC pull server and pull the required DSC configuration documents.
The specific DSC onfigurations that will be applied are determined based on the type of operating system installation (core vs.
desktop experience) and any installed server applications (SQL or IIS).

## EXAMPLES

### EXAMPLE 1

```PowerShell
LCMConfiguration.ps1 -PullServerName "mydscserver.domain.com" -RegKey "764215ba-aad1-459d-86e8-acb24f117e12"
```

This example will perform the Local Configuration Manager configuration operation on the local computer using the specified pull server URL and registration GUID.

### EXAMPLE 2

```PowerShell
LCMConfiguration.ps1 -ComputerName "RemoteServer01" -PullServerName "mydscserver.domain.com" -RegKey "764215ba-aad1-459d-86e8-acb24f117e12" -ApplicationType "IIS"
```

This example will perform the Local Configuration Manager configuration operation on the remote computer named "RemoteServer01" using the specified pull server URL and registration GUID.
The LCM will also be configured to pull the IIS-specific partial configuration.

## PARAMETERS

### -ApplicationType

Use this parameter to specify if SQL Server or IIS are installed on the target client system.
Valid choices are 'SQL', 'IIS' or 'DomainController'.
Optional.
Example: 'SQL
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
Position: 4
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ComputerName

The name of a remote computer to configure.
If not provided, the local computer will be used.
Optional.
Example: 'MyComputer'
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
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -PullServerName

The pull server's name.
Example: 'pullserver.corp.local'
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
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -RegKey

A GUID that will be used for DSC clients to register with the pull server.
Required.
Example: '13664f48-68b2-4582-94bd-f9bf6cdb794c'
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

Author: Mike Nickerson

## RELATED LINKS

[https://docs.microsoft.com/en-us/powershell/scripting/dsc/managing-nodes/metaconfig?view=powershell-7](https://docs.microsoft.com/en-us/powershell/scripting/dsc/managing-nodes/metaconfig?view=powershell-7)
