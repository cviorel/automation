function New-IporSubnetString {
    <#
    .SYNOPSIS
        Helper function that creates a Base64 string.

    .DESCRIPTION
        Helper function that creates a Base64 string based on a template text string.

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

    .PARAMETER IPTemplateString
        A text string that sets the format for the Base64 string produced by the function.
        Example: 'AwEDAQMBAwEC'
        Required: False
        Type: String
        Parameter Sets: All
        Position: Named
        Default Value: none
        Accept pipeline input: False
        Accept wildcard characters: False

    .PARAMETER IPOffset
        Helps set the format for the Base64 string.
        Example: 1
        Required: False
        Type: Int
        Parameter Sets: All
        Position: Named
        Default Value: none
        Accept pipeline input: False
        Accept wildcard characters: False

    .EXAMPLE
        PS C:\> $IP = "10.0.0.0"
        PS C:\> $IPTemplate = "AwEDAQMBAwEC"
        PS C:\> New-IPorSubnetString -IP $IP -IPTemplateString $IPTemplate -IPOffset 1

        Creates a Base64 string using the provided template string and IP address.

    .INPUTS

    .OUTPUTS

    .NOTES
        Author: Mike Nickerson
    #>

    [cmdletbinding()]
    param (
        [parameter(HelpMessage = "IP address in dotted-quad format.")]
        [string]$IP,

        [parameter(HelpMessage = "A text string that sets the format for the Base64 string produced by the function.")]
        [string]$IPTemplateString,

        [parameter(HelpMessage = "Helps set the format for the Base64 string.")]
        [int]$IPOffset
    )

    $IPTemplate = [System.Convert]::FromBase64String($IPTemplateString)
    $IPParts = $IP.Split('.')
    $IPTemplate[$IPOffset] = [System.Convert]::ToByte($IPParts[0])
    $IPTemplate[$IPOffset + 2] = [System.Convert]::ToByte($IPParts[1])
    $IPTemplate[$IPOffset + 4] = [System.Convert]::ToByte($IPParts[2])
    $IPTemplate[$IPOffset + 6] = [System.Convert]::ToByte($IPParts[3])
    return [System.Convert]::ToBase64String($IPTemplate)
}