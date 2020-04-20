<#
    .SYNOPSIS
        This script will configure the LCM on a DSC client.

    .DESCRIPTION
        This script will configure the DSC Local Configuration Manager component to register with the DSC pull server and pull the required DSC configuration documents. The specific DSC onfigurations that will be applied are determined based on the type of operating system installation (core vs. desktop experience) and any installed server applications (SQL or IIS).

    .PARAMETER ComputerName
        The name of a remote computer to configure. If not provided, the local computer will be used. Optional.
        Example: 'MyComputer'
        Required: False
        Type: String
        Parameter Sets: All
        Position: Named
        Default Value: none
        Accept pipeline input: False
        Accept wildcard characters: False

    .PARAMETER DSCPullServer
        The pull server's name.
        Example: 'pullserver.corp.local'
        Required: True
        Type: String
        Parameter Sets: All
        Position: Named
        Default Value: none
        Accept pipeline input: False
        Accept wildcard characters: False

    .PARAMETER RegKey
        A GUID that will be used for DSC clients to register with the pull server. Required.
        Example: '13664f48-68b2-4582-94bd-f9bf6cdb794c'
        Required: True
        Type: String
        Parameter Sets: All
        Position: Named
        Default Value: none
        Accept pipeline input: False
        Accept wildcard characters: False

    .PARAMETER ServerType
        Use this parameter to specify if SQL Server or IIS are installed on the target client system. Valid choices are 'SQL', 'IIS' or 'DomainController'. Optional.
        Example: 'SQL
        Required: False
        Type: String
        Parameter Sets: All
        Position: Named
        Default Value: none
        Accept pipeline input: False
        Accept wildcard characters: False

    .EXAMPLE
        PS C:\> LCMConfiguration.ps1 -DSCPullServer "mydscserver.domain.com" -RegKey "764215ba-aad1-459d-86e8-acb24f117e12"

        This example will perform the Local Configuration Manager configuration operation on the local computer using the specified pull server URL and registration GUID.

    .EXAMPLE
        PS C:\> LCMConfiguration.ps1 -ComputerName "RemoteServer01" -DSCPullServer "mydscserver.domain.com" -RegKey "764215ba-aad1-459d-86e8-acb24f117e12" -ServerType "IIS"

        This example will perform the Local Configuration Manager configuration operation on the remote computer named "RemoteServer01" using the specified pull server URL and registration GUID. The LCM will also be configured to pull the IIS-specific partial configuration.

    .INPUTS

    .OUTPUTS

    .NOTES
        Author: Mike Nickerson

    .LINK
        https://docs.microsoft.com/en-us/powershell/scripting/dsc/managing-nodes/metaconfig?view=powershell-7
#>

[cmdletbinding()]
param (
    [parameter(HelpMessage = "The name of a remote computer to configure. If a value is not provided, the local computer will be used. Optional.")]
    [string]$ComputerName,

    [parameter(Mandatory = $true, HelpMessage = "URL for the DSC pull server. Required.")]
    [string]$DSCPullServer,

    [parameter(Mandatory = $true, HelpMessage = "A GUID that will be used for DSC clients to register with the pull server. Required.")]
    [string]$RegKey,

    [parameter(HelpMessage = "Use this parameter if the target client system is an application or special server. Valid choices are 'SQL', 'IIS' or 'DomainController'. Optional.")]
    [ValidateSet('SQL', 'IIS', 'DomainController')]
    [string]$ServerType
)

$scriptBlock = {
    #* Ensure TLS protocols are enabled
    $protocols = [System.Net.SecurityProtocolType]'TLS,TLS11,TLS12'
    [System.Net.ServicePointManager]::SecurityProtocol = $protocols

    if (!($args[0])) {
        $ComputerName = $env:COMPUTERNAME
    }
    else {
        $ComputerName = $args[0]
    }

    $DSCPullServer = $args[1]

    $RegKey = $args[2]

    if (!($args[3])) {
        if ((Get-WindowsFeature -Name "Web-Server").Installed) {
            $ServerType = "IIS"
        }
        else {
            $ServerType = $null
        }
    }
    else {
        $ServerType = $args[3]
    }

    switch ((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").InstallationType) {
        "Server" { $osConfig = "WindowsGUI" }
        "Server Core" { $osConfig = "WindowsCORE" }
    }

    if (($ServerType -eq "IIS") -or ($ServerType -eq "SQL") -or ($ServerType -eq "DomainController")) {
        $confNames = @("WindowsBaseOS", "$($osConfig)", "$($ServerType)")
        [DSCLocalConfigurationManager()]
        Configuration LCMConfiguration {
            param (
                [string]$NodeName = $ComputerName
            )
            Node $NodeName {
                Settings {
                    RefreshMode          = 'Pull'
                    ConfigurationMode    = 'ApplyAndAutoCorrect'
                    RebootNodeIfNeeded   = $true
                    RefreshFrequencyMins = 30
                    AllowModuleOverwrite = $true
                }
                ConfigurationRepositoryWeb "PSDSCPullServer" {
                    ServerURL          = "https://$($DSCPullServer):8080/PSDSCPullServer.svc"
                    RegistrationKey    = "$($RegKey)"
                    ConfigurationNames = $confNames
                }
                ReportServerWeb "PSDSCReportServer" {
                    ServerURL       = "https://$($DSCPullServer):8080/PSDSCPullServer.svc"
                    RegistrationKey = "$($RegKey)"
                }
                PartialConfiguration "WindowsBaseOS" {
                    Description         = "Windows Base Operating System Configuration"
                    ConfigurationSource = @("[ConfigurationRepositoryWeb]PSDSCPullServer")
                }
                PartialConfiguration "$($osConfig)" {
                    Description         = "Operating System Installation Type Configuration (GUI or CORE)"
                    ConfigurationSource = @("[ConfigurationRepositoryWeb]PSDSCPullServer")
                    DependsOn           = '[PartialConfiguration]WindowsBaseOS'
                }
                PartialConfiguration "$($ServerType)" {
                    Description         = "$($ServerType)-specific Configuration"
                    ConfigurationSource = @("[ConfigurationRepositoryWeb]PSDSCPullServer")
                    DependsOn           = '[PartialConfiguration]WindowsBaseOS'
                }
            }
        }
    }
    else {
        $confNames = @("WindowsBaseOS", $osConfig)
        [DSCLocalConfigurationManager()]
        Configuration LCMConfiguration {
            param (
                [string]$NodeName = $ComputerName
            )
            Node $NodeName {
                Settings {
                    RefreshMode          = 'Pull'
                    ConfigurationMode    = 'ApplyAndAutoCorrect'
                    RebootNodeIfNeeded   = $true
                    RefreshFrequencyMins = 30
                    AllowModuleOverwrite = $true
                }
                ConfigurationRepositoryWeb "PSDSCPullServer" {
                    ServerURL          = "https://$($DSCPullServer):8080/PSDSCPullServer.svc"
                    RegistrationKey    = "$($RegKey)"
                    ConfigurationNames = $confNames
                }
                ReportServerWeb "PSDSCReportServer" {
                    ServerURL       = "https://$($DSCPullServer):8080/PSDSCPullServer.svc"
                    RegistrationKey = "$($RegKey)"
                }
                PartialConfiguration "WindowsBaseOS" {
                    Description         = "Windows Base Operating System Configuration"
                    ConfigurationSource = @("[ConfigurationRepositoryWeb]PSDSCPullServer")
                }
                PartialConfiguration "$($osConfig)" {
                    Description         = "Operating System Installation Type Configuration (GUI or CORE)"
                    ConfigurationSource = @("[ConfigurationRepositoryWeb]PSDSCPullServer")
                    DependsOn           = '[PartialConfiguration]WindowsBaseOS'
                }
            }
        }
    }

    if (!(Test-Path -Path "C:\Temp\DSCConfig\")) {
        New-Item -Path "C:\Temp" -Name "DSCConfig" -ItemType Directory -Force -Verbose
    }

    LCMConfiguration -NodeName $ComputerName -OutputPath "C:\Temp\DSCConfig\" -Verbose
    Set-DscLocalConfigurationManager -Path "C:\Temp\DSCConfig\" -Force -Verbose
}

if ($ComputerName) {
    Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock -ArgumentList @($ComputerName, $DSCPullServer, $RegKey, $ServerType) -Verbose
}
else {
    Invoke-Command -ScriptBlock $scriptBlock -ArgumentList @($ComputerName, $DSCPullServer, $RegKey, $ServerType) -Verbose
}