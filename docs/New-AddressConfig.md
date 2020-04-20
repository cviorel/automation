---
external help file: dsc-help.xml
Module Name: dsc
online version:
schema: 2.0.0
---

# New-AddressConfig

## SYNOPSIS

Helper function that creates a formatted Base64 string.

## SYNTAX

```PowerShell
New-AddressConfig [[-Index] <Int32>] [[-IP] <String>] [[-Subnet] <String>] [[-Allow] <Boolean>]
 [<CommonParameters>]
```

## DESCRIPTION

Helper function that creates a formatted Base64 string used by the New-RemoteRestrictions function.

## EXAMPLES

### EXAMPLE 1

```PowerShell
New-AddressConfig -Index 0 -IP "10.0.0.1" -Subnet "255.0.0.0" -Allow $false
```

Creates the IP/subnet configuration for a Base64 string that can be used by the New-RemoteRestrictions function.

## PARAMETERS

### -Allow

A boolean value that specifies if global connections are allowed or not.
Example: $true
Required: False
Type: Bool
Parameter Sets: All
Position: Named
Default Value: none
Accept pipeline input: False
Accept wildcard characters: False

```yaml
Type: Boolean
Parameter Sets: (All)
Aliases:

Required: False
Position: 4
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -Index

Use this parameter to specify if all connections are denied by default or not.
Example: 0
Required: False
Type: Int
Parameter Sets: All
Position: Named
Default Value: none
Accept pipeline input: False
Accept wildcard characters: False

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: 0
Accept pipeline input: False
Accept wildcard characters: False
```

### -IP

IP address in dotted-quad format.
Example: '192.168.0.1'
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
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Subnet

Subnet mask in dotted-quad format.
Example: '255.255.0.0'
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
