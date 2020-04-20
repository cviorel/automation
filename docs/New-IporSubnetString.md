---
external help file: dsc-help.xml
Module Name: dsc
online version:
schema: 2.0.0
---

# New-IporSubnetString

## SYNOPSIS

Helper function that creates a Base64 string.

## SYNTAX

```PowerShell
New-IporSubnetString [[-IP] <String>] [[-IPTemplateString] <String>] [[-IPOffset] <Int32>] [<CommonParameters>]
```

## DESCRIPTION

Helper function that creates a Base64 string based on a template text string.

## EXAMPLES

### EXAMPLE 1

```PowerShell
PS C:\> $IP = "10.0.0.0"
PS C:\> $IPTemplate = "AwEDAQMBAwEC"
PS C:\> New-IPorSubnetString -IP $IP -IPTemplateString $IPTemplate -IPOffset 1
```

Creates a Base64 string using the provided template string and IP address.

## PARAMETERS

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
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -IPOffset

Helps set the format for the Base64 string.
Example: 1
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
Position: 3
Default value: 0
Accept pipeline input: False
Accept wildcard characters: False
```

### -IPTemplateString

A text string that sets the format for the Base64 string produced by the function.
Example: 'AwEDAQMBAwEC'
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

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

Author: Mike Nickerson

## RELATED LINKS
