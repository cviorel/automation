function New-AddressConfig {
    <#
    .SYNOPSIS
        Helper function that creates a formatted Base64 string.

    .DESCRIPTION
        Helper function that creates a formatted Base64 string used by the New-RemoteRestrictions function.

    .PARAMETER Index
        Use this parameter to specify if all connections are denied by default or not.
        Example: 0
        Required: False
        Type: Int
        Parameter Sets: All
        Position: Named
        Default Value: none
        Accept pipeline input: False
        Accept wildcard characters: False

    .PARAMETER IP
        IP address in dotted-quad format.
        Example: '192.168.0.1'
        Required: False
        Type: String
        Parameter Sets: All
        Position: Named
        Default Value: none
        Accept pipeline input: False
        Accept wildcard characters: False

    .PARAMETER Subnet
        Subnet mask in dotted-quad format.
        Example: '255.255.0.0'
        Required: False
        Type: String
        Parameter Sets: All
        Position: Named
        Default Value: none
        Accept pipeline input: False
        Accept wildcard characters: False

    .PARAMETER Allow
        A boolean value that specifies if global connections are allowed or not.
        Example: $true
        Required: False
        Type: Bool
        Parameter Sets: All
        Position: Named
        Default Value: none
        Accept pipeline input: False
        Accept wildcard characters: False

    .EXAMPLE
        PS C:\> New-AddressConfig -Index 0 -IP "10.0.0.1" -Subnet "255.0.0.0" -Allow $false

        Creates the IP/subnet configuration for a Base64 string that can be used by the New-RemoteRestrictions function.

    .INPUTS

    .OUTPUTS

    .NOTES
        Author: Mike Nickerson
    #>

    [cmdletbinding()]
    param (
        [parameter(HelpMessage = "Use this parameter to specify if all connections are denied by default or not.")]
        [int]$Index,

        [parameter(HelpMessage = "IP address in dotted-quad format.")]
        [string]$IP,

        [parameter(HelpMessage = "Subnet mask in dotted-quad format.")]
        [string]$Subnet,

        [parameter(HelpMessage = "A boolean value that specifies if global connections are allowed or not.")]
        [bool]$Allow
    )

    $IPTemplate = "AwEDAQMBAwEC"
    $IPConfig = New-IPorSubnetString -IP $IP -IPTemplateString $IPTemplate -IPOffset 1

    $subnetTemplate = "LgQD/wP/A/8D/wMA"
    $subnetConfig = New-IPorSubnetString -IP $Subnet -IPTemplateString $subnetTemplate -IPOffset 3
    $addressConfig = [System.Convert]::FromBase64String("AQAAABkDAAAAAQAAAC4EAwEDAQMBAwECAAAALgQD/wP/A/8D/wMAAABn".Replace($IPTemplate, $IPConfig).Replace($subnetTemplate, $subnetConfig))
    [System.Buffer]::BlockCopy([System.BitConverter]::GetBytes($Index), 0, $addressConfig, 0, 4)
    $addressConfig[$addressConfig.Count - 1] =
    if ($Allow) {
        104
    }
    else {
        103
    }
    return [System.Convert]::ToBase64String($addressConfig)
}