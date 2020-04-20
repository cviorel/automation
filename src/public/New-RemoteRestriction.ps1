function New-RemoteRestriction {
    <#
    .SYNOPSIS
        Generates the RemoteRestrictions registry value for IIS remote management.

    .DESCRIPTION
        Generates a Base64 value for the RemoteRestrictions registry value used to set HKLM\SOFTWARE\Microsoft\WebManagement\Server\RemoteRestrictions to a set of allowed/denied IP addresses. Use this script to generate a base64 string to use in a DSC configuration script that will be used to configure an IIS web server.

    .PARAMETER GlobalDeny
        Use this parameter to specify if all connections are denied by default or not.

    .PARAMETER Addresses
        A string array consisting of an IP address/subnet mask value that can specify a single IP address or subnet of IP addresses.

    .EXAMPLE
        PS C:\> New-RemoteRestriction -GlobalDeny $True -Addresses "1.1.1.1/255.255.255.255"

        Globally deny access and only allow connections from a specific IP address.

    .EXAMPLE
        PS C:\> New-RemoteRestriction -GlobalDeny $True -Addresses "1.1.1.0/255.255.255.0", "2.2.2.0/255.255.255.0"

        Globally deny access and only allow connections from two specified subnets.

    .EXAMPLE
        PS C:\> New-RemoteRestriction -GlobalDeny $False -Addresses "1.1.1.0/255.255.255.0", "2.2.2.0/255.255.255.0"

        Globally allow access and deny 2 ips and subnets

    .INPUTS

    .OUTPUTS

    .NOTES
        Author: Mike Nickerson

    .LINK
        https://docs.microsoft.com/en-us/powershell/
#>

    [cmdletbinding()]
    param (
        [parameter(Mandatory = $true, HelpMessage = "Use this parameter to specify if all connections are denied by default or not.")]
        [bool]$GlobalDeny,

        [parameter(HelpMessage = "A string array consisting of an IP address/subnet mask value that can specify a single IP address or subnet of IP addresses.")]
        [string[]]$Addresses
    )

    $header = [System.Convert]::FromBase64String("/wEZAgAAAAEAAABnAgAAABkAAAAA")
    $addressCountBytes = [System.BitConverter]::GetBytes($addresses.Count)
    [System.Buffer]::BlockCopy($addressCountBytes, 0, $header, 17, 4)
    $header[11] = If ($GlobalDeny) { 104 } else { 103 }
    $remoteRestrictions = [System.Convert]::ToBase64String($header)
    $index = 0
    foreach ($address in $addresses) {
        $ip = $address.Split('/')[0]
        $subnet = $address.Split('/')[1]
        $remoteRestrictions += (New-AddressConfig -index $index -ip $ip -subnet $subnet -allow (-Not $GlobalDeny))
        $index++
    }
    return $remoteRestrictions
}