<#
    .SYNOPSIS
        This script will compile a DSC MOF configuration file.

    .DESCRIPTION
        This configuration will add domain-specific users and groups to the local Administrators group and will configure User Rights Assignment settings.

        Run this script to create a Desired State Configuration MOF file.

    .PARAMETER OutputPath
        Output path for the compiled MOF file.
        Example: "C:\Temp"
        Required: False
        Type: String
        Parameter Sets: All
        Position: Named
        Default Value: none
        Accept pipeline input: False
        Accept wildcard characters: False

    .EXAMPLE
        PS C:\> WindowsCore -ComputerName 'localhost' -OutputPath "C:\Temp" -Verbose

        This example will compile a MOF file from the 'WindowsCore' DSC onfiguration script.

    .NOTES
        Important: Some parameter values presented in this script may be examples only and should be changed before this script is used in a testing or production scenario. Carefully review all configuration values before deployment.

        Items denoted with a 'V' and a five digit number (Example: 'V-73287') are configuration items from the official DISA STIG reference guides. Each 'V' number corresponds to a STIG finding.

        Author: Mike Nickerson

    .LINK
        https://public.cyber.mil/stigs/

    .LINK
        https://stigviewer.com/stig/windows_server_2016/

    .LINK
        https://docs.microsoft.com/en-us/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server
#>

[cmdletbinding()]
param (
    [parameter(HelpMessage = "Output path for the compiled MOF file.")]
    [string]$Destination
)

Configuration WindowsCORE {

    param (
        [parameter(HelpMessage = "The computer name for the target DSC client.")]
        [string]$ComputerName = 'localhost'
    )

    #* Import DSC modules
    Import-DscResource -ModuleName 'PSDscResources' -ModuleVersion 2.12.0.0
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion 8.0.0

    Node $Computername {

        #* WindowsFeatureSet resource from the PSDscResources module
        WindowsFeatureSet 'Windows Core - Disable Features' {
            Name                 = @(
                'Print-Services',
                'Print-Server',
                'Print-LPD-Service'
            )
            Ensure               = 'Absent'
            IncludeAllSubFeature = $true
        }

        #* ServiceSet resource from the PSDscResources module
        ServiceSet 'Windows Core - Disable Unused Services' {
            Name        = @(
                'SharedAccess', #? Internet Connection Sharing (ICS)
                'lltdsvc', #? Link-Layer Topology Discovery Mapper
                'wisvc' #? Windows Insider Service
            )
            StartupType = 'Disabled'
            State       = 'Stopped'
        }
    }
}

Write-Host "##[command] Compiling WindowsCORE configuration..."
WindowsCORE -OutputPath "$($Destination)" -Verbose
Rename-Item -Path "$($Destination)\localhost.mof" -NewName "WindowsCORE.mof" -Verbose
Write-Host "##[command] Creating WindowsCORE checksum..."
New-DscChecksum -Path "$($Destination)\WindowsCORE.mof" -Force -Verbos
