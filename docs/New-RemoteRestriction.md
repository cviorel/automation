---
external help file: dsc-help.xml
Module Name: dsc
online version: https://docs.microsoft.com/en-us/powershell/
schema: 2.0.0
---

# New-RemoteRestriction

## SYNOPSIS

Generates the RemoteRestrictions registry value for IIS remote management.

## SYNTAX

```PowerShell
New-RemoteRestriction [-GlobalDeny] <Boolean> [[-Addresses] <String[]>] [<CommonParameters>]
```

## DESCRIPTION

Generates a Base64 value for the RemoteRestrictions registry value used to set HKLM\SOFTWARE\Microsoft\WebManagement\Server\RemoteRestrictions to a set of allowed/denied IP addresses.
Use this script to generate a base64 string to use in a DSC configuration script that will be used to configure an IIS web server.

## EXAMPLES

### EXAMPLE 1

```PowerShell
New-RemoteRestriction -GlobalDeny $True -Addresses "1.1.1.1/255.255.255.255"
```

Globally deny access and only allow connections from a specific IP address.

### EXAMPLE 2

```PowerShell
New-RemoteRestriction -GlobalDeny $True -Addresses "1.1.1.0/255.255.255.0", "2.2.2.0/255.255.255.0"
```

Globally deny access and only allow connections from two specified subnets.

### EXAMPLE 3

```PowerShell
New-RemoteRestriction -GlobalDeny $False -Addresses "1.1.1.0/255.255.255.0", "2.2.2.0/255.255.255.0"
```

Globally allow access and deny 2 ips and subnets

## PARAMETERS

### -Addresses

A string array consisting of an IP address/subnet mask value that can specify a single IP address or subnet of IP addresses.

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

### -GlobalDeny

Use this parameter to specify if all connections are denied by default or not.

```yaml
Type: Boolean
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: False
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

[https://docs.microsoft.com/en-us/powershell/](https://docs.microsoft.com/en-us/powershell/)
