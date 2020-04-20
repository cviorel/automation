---
external help file: dsc-help.xml
Module Name: dsc
online version: https://docs.microsoft.com/en-us/powershell/
schema: 2.0.0
---

# Publish-DscModuleAndMof

## SYNOPSIS

Package DSC modules and mof configuration document and publish them on an enterprise DSC pull server in the required format.

## SYNTAX

```PowerShell
Publish-DscModuleAndMof [-Source] <String> [-Force] [[-ModuleNameList] <String[]>] [<CommonParameters>]
```

## DESCRIPTION

Uses Publish-DscModulesAndMof function to package DSC modules into zip files with the version info.
Publishes the zip modules on "$env:ProgramFiles\WindowsPowerShell\DscService\Modules".
Publishes all mof configuration documents that are present in the $Source folder on "$env:ProgramFiles\WindowsPowerShell\DscService\Configuration"-
Use $Force to overwrite the version of the module that exists in the PowerShell module path with the version from the $source folder.
Use $ModuleNameList to specify the names of the modules to be published if the modules do not exist in $Source folder.

## EXAMPLES

### EXAMPLE 1

```PowerShell
Publish-DscModuleAndMof -Source C:\LocalDepot -ModuleNameList @("xWebAdministration", "xPhp")
```

Packages and publishes the specified modules.

## PARAMETERS

### -Force

Switch to overwrite the module in PSModulePath with the version provided in $Sources.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -ModuleNameList

Package and publish the modules listed in $ModuleNameList based on PowerShell module path content.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Source

The folder that contains the configuration mof documents and modules to be published on Pull server.
Everything in this folder will be packaged and published.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
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

## RELATED LINKS

[https://docs.microsoft.com/en-us/powershell/](https://docs.microsoft.com/en-us/powershell/)
