<#
    .SYNOPSIS
        This script will compile a DSC MOF configuration file.

    .DESCRIPTION
        This script will configure a Windows domain controller with STIG-recommended setttings.

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
        PS C:\> DomainController -ComputerName 'localhost' -OutputPath "C:\Temp" -Verbose

        This example will compile a MOF file from the 'DomainController' DSC onfiguration script.

    .NOTES
        Important: Some parameter values presented in this script may be examples only and should be changed before this script is used in a testing or production scenario. Carefully review all configuration values before deployment.

        Items denoted with a 'V' and a five digit number (Example: 'V-73287') are configuration items from the official DISA STIG reference guides. Each 'V' number corresponds to a STIG finding.

        Author: Mike Nickerson

    .LINK
        https://public.cyber.mil/stigs/

    .LINK
        https://stigviewer.com/stig/windows_server_2016/
#>

[cmdletbinding()]
param (
    [parameter()]
    [string]$Destination = "D:\git\repos\Automation\DSC\src\configurations\compiled"
)

Configuration DomainController {

    param (
        [parameter(HelpMessage = "The computer name for the target DSC client.")]
        [string]$ComputerName = 'localhost'
    )

    #* Import DSC modules
    Import-DscResource -ModuleName 'PSDscResources' -ModuleVersion 2.12.0.0
    Import-DscResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion 2.10.0.0

    Node $Computername {

        AccountPolicy KerbPolicy {
            Name                                                 = 'KerberosPolicies'
            Enforce_user_logon_restrictions                      = 'Enabled' #? V-73359
            Maximum_lifetime_for_service_ticket                  = 600 #? V-73361
            Maximum_lifetime_for_user_ticket                     = 10 #? V-73363
            Maximum_lifetime_for_user_ticket_renewal             = 7 #? V-73365
            Maximum_tolerance_for_computer_clock_synchronization = 5 #? V-73367
        }

        UserRightsAssignment 'Windows Server 2016 Domain Controller - Enable computer and user accounts to be trusted for delegation (V-73777)' {
            Policy   = 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
            Identity = 'BUILTIN\Administrators'
            Force    = $true
        }

        Registry 'Windows Server 2016 Domain Controller - Restrict Remote SAM (V-73677)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
            ValueName = 'RestrictRemoteSAM'
            ValueType = 'String'
            ValueData = 'O:BAG:BAD:(A;;RC;;;BA)'
            Force     = $true
        }

        SecurityOption 'Windows Server 2016 Domain Controller - Domain controller LDAP server signing requirements (V-73629, V-73631)' {
            Name                                                      = 'DCLocalSecurityPolicies'
            Domain_Controller_LDAP_server_signing_requirements        = 'Require Signing'
            Domain_Controller_Refuse_machine_account_password_changes = 'Disabled'
        }
    }
}

Write-Host "##[command] Compiling DomainController configuration..."
DomainController -OutputPath "$($Destination)" -Verbose
Rename-Item -Path "$($Destination)\localhost.mof" -NewName "DomainController.mof" -Verbose
Write-Host "##[command] Creating DomainController checksum..."
New-DscChecksum -Path "$($Destination)\DomainController.mof" -Force -Verbose