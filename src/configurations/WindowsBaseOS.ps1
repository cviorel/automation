<#
    .SYNOPSIS
        This script will compile a DSC MOF configuration file.

    .DESCRIPTION
        Run this script to create a Desired State Configuration MOF file that covers the settings needed for a hardened Windows OS installation.

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

    .PARAMETER AdminName
        New name for the local administrator account.
        Required: False
        Type: String
        Parameter Sets: All
        Position: Named
        Default Value: none
        Accept pipeline input: False
        Accept wildcard characters: False

    .PARAMETER GuestName
        New name for the local guest account.
        Required: False
        Type: String
        Parameter Sets: All
        Position: Named
        Default Value: none
        Accept pipeline input: False
        Accept wildcard characters: False

    .EXAMPLE
        PS C:\> WindowsBaseOS -ComputerName 'localhost' -OutputPath "C:\Temp" -Verbose

        This example will compile a MOF file from the 'WindowsBaseOS' DSC onfiguration script.

    .NOTES
        Important: Some parameter values presented in this script may be examples only and should be changed before this script is used in a testing or production scenario. Carefully review all configuration values before deployment.

        Items denoted with a 'V' and a five digit number (Example: 'V-73287') are configuration items from the official DISA STIG reference guides. Each 'V' number corresponds to a STIG finding.

        If a logon message is required, be sure to edit lines 1098 & 1099 as appropriate. (See Windows Server 2016 STIG findings V-73647 & V-73649)

        Author: Mike Nickerson

    .LINK
        https://public.cyber.mil/stigs/

    .LINK
        https://stigviewer.com/stig/windows_server_2016/
#>

[cmdletbinding()]
param (
    [parameter(HelpMessage = "Output path for the compiled MOF file.")]
    [string]$Destination,

    [parameter(HelpMessage = "New name for the local administrator account.")]
    [string]$AdminName,

    [parameter(HelpMessage = "New name for the local guest account.")]
    [string]$GuestName
)

Configuration WindowsBaseOS {

    param (
        [string]$ComputerName = 'localhost'
    )

    # Import DSC modules
    Import-DscResource -ModuleName 'PSDscResources' -ModuleVersion 2.12.0.0
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion 8.0.0
    Import-DscResource -ModuleName 'AuditPolicyDSC' -ModuleVersion 1.4.0.0
    Import-DscResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion 2.10.0.0
    Import-DscResource -ModuleName 'NetworkingDSC' -ModuleVersion 7.4.0.0

    Node $ComputerName {

        #region Firewall Rules

        Firewall 'Firewall - RemoteDesktop-UserMode-In-TCP' {
            Name    = 'RemoteDesktop-UserMode-In-TCP'
            Ensure  = 'Present'
            Enabled = $true
        }

        Firewall 'Firewall - RemoteDesktop-UserMode-In-UDP' {
            Name    = 'RemoteDesktop-UserMode-In-UDP'
            Ensure  = 'Present'
            Enabled = $true
        }

        Firewall 'Firewall - RemoteEventLogSvc-In-TCP' {
            Name    = 'RemoteEventLogSvc-In-TCP'
            Ensure  = 'Present'
            Enabled = $true
        }

        Firewall 'Firewall - RemoteEventLogSvc-NP-In-TCP' {
            Name    = 'RemoteEventLogSvc-NP-In-TCP'
            Ensure  = 'Present'
            Enabled = $true
        }

        Firewall 'Firewall - RemoteEventLogSvc-RPCSS-In-TCP' {
            Name    = 'RemoteEventLogSvc-RPCSS-In-TCP'
            Ensure  = 'Present'
            Enabled = $true
        }

        Firewall 'Firewall - Allow Configuration Manager Client Notification Inbound' {
            Name      = 'Allow-CM-10123-Inbound'
            Action    = 'Allow'
            Profile   = ('Domain', 'Private')
            Direction = 'Inbound'
            LocalPort = '10123'
            Protocol  = 'TCP'
            Service   = 'CcmExec'
            Ensure    = 'Present'
            Enabled   = $true
        }

        Firewall 'Firewall - Allow Configuration Manager Client Notification Outbound' {
            Name      = 'Allow-CM-10123-Outbound'
            Action    = 'Allow'
            Profile   = ('Domain', 'Private')
            Direction = 'Outbound'
            LocalPort = '10123'
            Protocol  = 'TCP'
            Service   = 'CcmExec'
            Ensure    = 'Present'
            Enabled   = $true
        }

        Firewall 'Firewall - WINRM-HTTP-In-TCP' {
            Name    = 'WINRM-HTTP-In-TCP'
            Ensure  = 'Present'
            Enabled = 'True'
        }

        Firewall 'Firewall - WINRM-HTTPs-In-TCP' {
            Name        = 'WINRM-HTTPs-In-TCP'
            DisplayName = 'Windows Remote Management (HTTPs-In)'
            Action      = 'Allow'
            Profile     = ('Domain', 'Private')
            Protocol    = 'TCP'
            LocalPort   = '5986'
            Direction   = 'Inbound'
            Ensure      = 'Present'
            Enabled     = 'True'
        }

        Firewall 'Firewall - RemoteFwAdmin-In-TCP' {
            Name    = 'RemoteFwAdmin-In-TCP'
            Ensure  = 'Present'
            Enabled = 'True'
        }

        Firewall 'Firewall - FPS-NB_Datagram-In-UDP' {
            Name    = 'FPS-NB_Datagram-In-UDP'
            Ensure  = 'Present'
            Enabled = 'True'
        }

        Firewall 'Firewall - FPS-NB_Datagram-Out-UDP' {
            Name    = 'FPS-NB_Datagram-Out-UDP'
            Ensure  = 'Present'
            Enabled = 'True'
        }

        Firewall 'Firewall - FPS-NB_Name-In-UDP' {
            Name    = 'FPS-NB_Name-In-UDP'
            Ensure  = 'Present'
            Enabled = 'True'
        }

        Firewall 'Firewall - FPS-NB_Name-Out-UDP' {
            Name    = 'FPS-NB_Name-Out-UDP'
            Ensure  = 'Present'
            Enabled = 'True'
        }

        Firewall 'Firewall - FPS-NB_Session-In-TCP' {
            Name    = 'FPS-NB_Session-In-TCP'
            Ensure  = 'Present'
            Enabled = 'True'
        }

        Firewall 'Firewall - FPS-NB_Session-Out-TCP' {
            Name    = 'FPS-NB_Session-Out-TCP'
            Ensure  = 'Present'
            Enabled = 'True'
        }

        Firewall 'Firewall - FPS-RPCSS-In-TCP' {
            Name    = 'FPS-RPCSS-In-TCP'
            Ensure  = 'Present'
            Enabled = 'True'
        }

        Firewall 'Firewall - FPSSMBD-iWARP-In-TCP' {
            Name    = 'FPSSMBD-iWARP-In-TCP'
            Ensure  = 'Present'
            Enabled = 'True'
        }

        Firewall 'Firewall - FPS-SMB-In-TCP' {
            Name    = 'FPS-SMB-In-TCP'
            Ensure  = 'Present'
            Enabled = 'True'
        }

        Firewall 'Firewall - FPS-SMB-Out-TCP' {
            Name    = 'FPS-SMB-Out-TCP'
            Ensure  = 'Present'
            Enabled = 'True'
        }

        #endregion Firewall Rules

        #region Local Auditing Policies (AuditPolicyDSC Module)

        AuditPolicyOption 'Audit Policy Option - Crash On Audit Fail' {
            Name  = 'CrashOnAuditFail'
            Value = 'Disabled'
        }

        AuditPolicyOption 'Audit Policy Option - Full Privilege Auditing' {
            Name  = 'FullPrivilegeAuditing'
            Value = 'Disabled'
        }

        AuditPolicyOption 'Audit Policy Option - Audit Base Objects' {
            Name  = 'AuditBaseObjects'
            Value = 'Disabled'
        }

        AuditPolicyOption 'Audit Policy Option - Audit Base Directories' {
            Name  = 'AuditBaseDirectories'
            Value = 'Disabled'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Account Lockout Success (V-73443)' {
            Name      = 'Account Lockout'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Application Generated Success' {
            Name      = 'Application Generated'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Application Group Management Success' {
            Name      = 'Application Group Management'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Audit Policy Change Success (V-73461)' {
            Name      = 'Audit Policy Change'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Authentication Policy Change Success (V-73465)' {
            Name      = 'Authentication Policy Change'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Authorization Policy Change Success (V-73467)' {
            Name      = 'Authorization Policy Change'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Central Policy Staging Success' {
            Name      = 'Central Policy Staging'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Certification Services Success' {
            Name      = 'Certification Services'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Computer Account Management Success (V-73417)' {
            Name      = 'Computer Account Management'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Credential Validation Success (V-73413)' {
            Name      = 'Credential Validation'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Detailed Directory Service Replication Success' {
            Name      = 'Detailed Directory Service Replication'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Detailed File Share Success' {
            Name      = 'Detailed File Share'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Directory Service Access Success (V-73435)' {
            Name      = 'Directory Service Access'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Directory Service Changes Success (V-73439)' {
            Name      = 'Directory Service Changes'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Directory Service Replication Success' {
            Name      = 'Directory Service Replication'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Distribution Group Management Success' {
            Name      = 'Distribution Group Management'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - DPAPI Activity Success' {
            Name      = 'DPAPI Activity'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - File Share Success' {
            Name      = 'File Share'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - File System Success' {
            Name      = 'File System'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Filtering Platform Connection Success' {
            Name      = 'Filtering Platform Connection'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Filtering Platform Packet Drop Success' {
            Name      = 'Filtering Platform Packet Drop'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Filtering Platform Policy Change Success' {
            Name      = 'Filtering Platform Policy Change'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Group Membership Success (V-73447)' {
            Name      = 'Group Membership'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Handle Manipulation Success' {
            Name      = 'Handle Manipulation'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - IPsec Driver Success (V-73473)' {
            Name      = 'IPsec Driver'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - IPsec Extended Mode Success' {
            Name      = 'IPsec Extended Mode'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - IPsec Main Mode Success' {
            Name      = 'IPsec Main Mode'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - IPsec Quick Mode Success' {
            Name      = 'IPsec Quick Mode'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Kerberos Authentication Service Success' {
            Name      = 'Kerberos Authentication Service'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Kerberos Service Ticket Operations Success' {
            Name      = 'Kerberos Service Ticket Operations'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Kernel Object Success' {
            Name      = 'Kernel Object'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Logoff Success (V-73449)' {
            Name      = 'Logoff'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Logon Success (V-73451)' {
            Name      = 'Logon'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - MPSSVC Rule-Level Policy Change Success' {
            Name      = 'MPSSVC Rule-Level Policy Change'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Network Policy Server Success' {
            Name      = 'Network Policy Server'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Non Sensitive Privilege Use Success' {
            Name      = 'Non Sensitive Privilege Use'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Other Account Logon Events Success' {
            Name      = 'Other Account Logon Events'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Other Account Management Events Success (V-73419)' {
            Name      = 'Other Account Management Events'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Other Logon/Logoff Events Success' {
            Name      = 'Other Logon/Logoff Events'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Other Object Access Events Success' {
            Name      = 'Other Object Access Events'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Other Policy Change Events Success' {
            Name      = 'Other Policy Change Events'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Other Privilege Use Events Success' {
            Name      = 'Other Privilege Use Events'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Other System Events Success (V-73477)' {
            Name      = 'Other System Events'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Plug and Play Events Success (V-73431)' {
            Name      = 'Plug and Play Events'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Process Creation Success (V-73433)' {
            Name      = 'Process Creation'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Process Termination Success' {
            Name      = 'Process Termination'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Registry Success' {
            Name      = 'Registry'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Removable Storage Success (V-73457)' {
            Name      = 'Removable Storage'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - RPC Events Success' {
            Name      = 'RPC Events'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - SAM Success' {
            Name      = 'SAM'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Security Group Management Success (V-73423)' {
            Name      = 'Security Group Management'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Security State Change Success (V-73481)' {
            Name      = 'Security State Change'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Security System Extension Success (V-73483)' {
            Name      = 'Security System Extension'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Sensitive Privilege Use Success (V-73469)' {
            Name      = 'Sensitive Privilege Use'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Special Logon Success (V-73455)' {
            Name      = 'Special Logon'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - System Integrity Success (V-73489)' {
            Name      = 'System Integrity'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Token Right Adjusted Events Success' {
            Name      = 'Token Right Adjusted Events'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - User / Device Claims Success' {
            Name      = 'User / Device Claims'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - User Account Management Success (V-73427)' {
            Name      = 'User Account Management'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Account Lockout Failure (V-73445)' {
            Name      = 'Account Lockout'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Application Generated Failure' {
            Name      = 'Application Generated'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Application Group Management Failure' {
            Name      = 'Application Group Management'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Audit Policy Change Failure (V-73463)' {
            Name      = 'Audit Policy Change'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Authentication Policy Change Failure' {
            Name      = 'Authentication Policy Change'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Authorization Policy Change Failure' {
            Name      = 'Authorization Policy Change'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Central Policy Staging Failure' {
            Name      = 'Central Policy Staging'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Certification Services Failure' {
            Name      = 'Certification Services'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Computer Account Management Failure' {
            Name      = 'Computer Account Management'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Credential Validation Failure (V-73415)' {
            Name      = 'Credential Validation'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Detailed Directory Service Replication Failure' {
            Name      = 'Detailed Directory Service Replication'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Detailed File Share Failure' {
            Name      = 'Detailed File Share'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Directory Service Access Failure (V-73437)' {
            Name      = 'Directory Service Access'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Directory Service Changes Failure (V-73441)' {
            Name      = 'Directory Service Changes'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Directory Service Replication Failure' {
            Name      = 'Directory Service Replication'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Distribution Group Management Failure' {
            Name      = 'Distribution Group Management'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - DPAPI Activity Failure' {
            Name      = 'DPAPI Activity'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - File Share Failure' {
            Name      = 'File Share'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - File System Failure' {
            Name      = 'File System'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Filtering Platform Connection Failure' {
            Name      = 'Filtering Platform Connection'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Filtering Platform Packet Drop Failure' {
            Name      = 'Filtering Platform Packet Drop'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Filtering Platform Policy Change Failure' {
            Name      = 'Filtering Platform Policy Change'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Group Membership Failure' {
            Name      = 'Group Membership'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Handle Manipulation Failure' {
            Name      = 'Handle Manipulation'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - IPsec Driver Failure (V-73475)' {
            Name      = 'IPsec Driver'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - IPsec Extended Mode Failure' {
            Name      = 'IPsec Extended Mode'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - IPsec Main Mode Failure' {
            Name      = 'IPsec Main Mode'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - IPsec Quick Mode Failure' {
            Name      = 'IPsec Quick Mode'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Kerberos Authentication Service Failure' {
            Name      = 'Kerberos Authentication Service'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Kerberos Service Ticket Operations Failure' {
            Name      = 'Kerberos Service Ticket Operations'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Kernel Object Failure' {
            Name      = 'Kernel Object'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Logoff Failure' {
            Name      = 'Logoff'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Logon Failure (V-73453)' {
            Name      = 'Logon'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - MPSSVC Rule-Level Policy Change Failure' {
            Name      = 'MPSSVC Rule-Level Policy Change'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Network Policy Server Failure' {
            Name      = 'Network Policy Server'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Non Sensitive Privilege Use Failure' {
            Name      = 'Non Sensitive Privilege Use'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Other Account Logon Events Failure' {
            Name      = 'Other Account Logon Events'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Other Logon/Logoff Events Failure' {
            Name      = 'Other Logon/Logoff Events'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Other Object Access Events Failure' {
            Name      = 'Other Object Access Events'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Other Policy Change Events Failure' {
            Name      = 'Other Policy Change Events'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Other Privilege Use Events Failure' {
            Name      = 'Other Privilege Use Events'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Other System Events Failure (V-73479)' {
            Name      = 'Other System Events'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Plug and Play Events Failure' {
            Name      = 'Plug and Play Events'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Process Creation Failure' {
            Name      = 'Process Creation'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Process Termination Failure' {
            Name      = 'Process Termination'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Registry Failure' {
            Name      = 'Registry'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Removable Storage Failure (V-73459)' {
            Name      = 'Removable Storage'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - RPC Events Failure' {
            Name      = 'RPC Events'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - SAM Failure' {
            Name      = 'SAM'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Security Group Management Failure' {
            Name      = 'Security Group Management'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Security State Change Failure' {
            Name      = 'Security State Change'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Sensitive Privilege Use Failure (V-73471)' {
            Name      = 'Sensitive Privilege Use'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Special Logon Failure' {
            Name      = 'Special Logon'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - System Integrity Failure (V-73491)' {
            Name      = 'System Integrity'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - Token Right Adjusted Events Failure' {
            Name      = 'Token Right Adjusted Events'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - User / Device Claims Failure' {
            Name      = 'User / Device Claims'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Subcategory - User Account Management Failure (V-73429)' {
            Name      = 'User Account Management'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        #endregion Local Auditing Policies (AuditPolicyDSC Module)

        #region Local Security Options (SecurityPolicyDSC Module)

        SecurityOption 'Local Security Policy' {
            Name                                                                                                            = 'LocalSecurityOptions'
            Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only                                       = 'Enabled' #? Windows Server 2016 STIG Finding V-73621
            Accounts_Block_Microsoft_accounts                                                                               = 'Users cant add or log on with Microsoft accounts'
            Accounts_Rename_administrator_account                                                                           = "$($AdminName)" #? Windows Server 2016 STIG Finding V-73623
            Accounts_Rename_guest_account                                                                                   = "$($GuestName)" #? Windows Server 2016 STIG Finding V-73625
            Accounts_Guest_account_status                                                                                   = 'Disabled' #? Windows Server 2016 STIG Finding V-73809

            Audit_Shut_down_system_immediately_if_unable_to_log_security_audits                                             = 'Disabled'
            Audit_Audit_the_access_of_global_system_objects                                                                 = 'Disabled'
            Audit_Audit_the_use_of_Backup_and_Restore_privilege                                                             = 'Disabled'
            Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings = 'Enabled' #? Windows Server 2016 STIG Finding V-73627

            Devices_Allow_undock_without_having_to_log_on                                                                   = 'Enabled'
            Devices_Allowed_to_format_and_eject_removable_media                                                             = 'Administrators'
            Devices_Prevent_users_from_installing_printer_drivers                                                           = 'Enabled'
            Devices_Restrict_CD_ROM_access_to_locally_logged_on_user_only                                                   = 'Enabled'
            Devices_Restrict_floppy_access_to_locally_logged_on_user_only                                                   = 'Enabled'

            Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always                                              = 'Enabled' #? Windows Server 2016 STIG Finding V-73633
            Domain_member_Digitally_encrypt_secure_channel_data_when_possible                                               = 'Enabled' #? Windows Server 2016 STIG Finding V-73635
            Domain_member_Digitally_sign_secure_channel_data_when_possible                                                  = 'Enabled' #? Windows Server 2016 STIG Finding V-73637
            Domain_member_Disable_machine_account_password_changes                                                          = 'Disabled' #? Windows Server 2016 STIG Finding V-73639
            Domain_member_Maximum_machine_account_password_age                                                              = '30' #? Windows Server 2016 STIG Finding V-73641
            Domain_member_Require_strong_Windows_2000_or_later_session_key                                                  = 'Enabled' #? Windows Server 2016 STIG Finding V-73643

            Interactive_logon_Display_user_information_when_the_session_is_locked                                           = 'User display name only'
            Interactive_logon_Do_not_display_last_user_name                                                                 = 'Enabled'
            Interactive_logon_Do_not_require_CTRL_ALT_DEL                                                                   = 'Disabled'
            Interactive_logon_Machine_account_lockout_threshold                                                             = '10'
            Interactive_logon_Machine_inactivity_limit                                                                      = '900' #? Windows Server 2016 STIG Finding V-73645
            # Interactive_logon_Message_text_for_users_attempting_to_log_on                                                   = "<LOGON_MESSAGE_TEXT>" #? Windows Server 2016 STIG Finding V-73647
            # Interactive_logon_Message_title_for_users_attempting_to_log_on                                                  = "<LOGON_MESSAGE_TITLE>" #? Windows Server 2016 STIG Finding V-73649
            Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available                 = 4 #? Windows Server 2016 STIG Finding V-73651
            Interactive_logon_Prompt_user_to_change_password_before_expiration                                              = '14'
            Interactive_logon_Require_Domain_Controller_authentication_to_unlock_workstation                                = 'Disabled'
            Interactive_logon_Require_smart_card                                                                            = 'Disabled'
            Interactive_logon_Smart_card_removal_behavior                                                                   = 'Lock Workstation' #? Windows Server 2016 STIG Finding V-73807

            Microsoft_network_client_Digitally_sign_communications_always                                                   = 'Enabled' #? Windows Server 2016 STIG Finding V-73653
            Microsoft_network_client_Digitally_sign_communications_if_server_agrees                                         = 'Enabled' #? Windows Server 2016 STIG Finding V-73655
            Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers                                   = 'Disabled' #? Windows Server 2016 STIG Finding V-73657

            Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session                                 = '15' #? Windows Server 2016 STIG Finding V-73659
            Microsoft_network_server_Digitally_sign_communications_always                                                   = 'Enabled' #? Windows Server 2016 STIG Finding V-73661
            Microsoft_network_server_Digitally_sign_communications_if_client_agrees                                         = 'Enabled' #? Windows Server 2016 STIG Finding V-73663
            Microsoft_network_server_Disconnect_clients_when_logon_hours_expire                                             = 'Enabled'
            Microsoft_network_server_Server_SPN_target_name_validation_level                                                = 'Off'

            Network_access_Allow_anonymous_SID_Name_translation                                                             = 'Disabled' #? Windows Server 2016 STIG Finding V-73665
            Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts                                               = 'Enabled' #? Windows Server 2016 STIG Finding V-73667
            Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares                                    = 'Enabled' #? Windows Server 2016 STIG Finding V-73669
            Network_access_Do_not_allow_storage_of_passwords_and_credentials_for_network_authentication                     = 'Enabled' #? Windows Server 2016 STIG Finding V-73671
            Network_access_Let_Everyone_permissions_apply_to_anonymous_users                                                = 'Disabled' #? Windows Server 2016 STIG Finding V-73673
            Network_access_Named_Pipes_that_can_be_accessed_anonymously                                                     = '7' #? Windows Server 2016 STIG Finding V-73675
            Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares                                              = 'Enabled' #? Windows Server 2016 STIG Finding V-73675
            Network_access_Sharing_and_security_model_for_local_accounts                                                    = 'Classic - Local users authenticate as themselves'

            Network_security_Allow_LocalSystem_NULL_session_fallback                                                        = 'Disabled' #? Windows Server 2016 STIG Finding V-73681
            Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change                                    = 'Enabled' #? Windows Server 2016 STIG Finding V-73687
            Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM                                           = 'Enabled' #? Windows Server 2016 STIG Finding V-73679
            Network_security_LDAP_client_signing_requirements                                                               = 'Negotiate Signing' #? Windows Server 2016 STIG Finding V-73693
            Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities                  = 'Disabled' #? Windows Server 2016 STIG Finding V-73683
            Network_security_LAN_Manager_authentication_level                                                               = 'Send NTLMv2 responses only. Refuse LM & NTLM' #? Windows Server 2016 STIG Finding V-73691
            Network_security_Force_logoff_when_logon_hours_expire                                                           = 'Enabled' #? Windows Server 2016 STIG Finding V-73689
            Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients                       = 'Both options checked' #? Windows Server 2016 STIG Finding V-73695
            Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers                       = 'Both options checked' #? Windows Server 2016 STIG Finding V-73697
            Network_security_Configure_encryption_types_allowed_for_Kerberos                                                = ('AES128_HMAC_SHA1', 'AES256_HMAC_SHA1', 'FUTURE') #? Windows Server 2016 STIG Finding V-73685

            Recovery_console_Allow_automatic_administrative_logon                                                           = 'Disabled'
            Recovery_console_Allow_floppy_copy_and_access_to_all_drives_and_folders                                         = 'Disabled'

            Shutdown_Allow_system_to_be_shut_down_without_having_to_log_on                                                  = 'Disabled'
            Shutdown_Clear_virtual_memory_pagefile                                                                          = 'Disabled'

            System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer                            = 'User must enter a password each time they use a key' #? Windows Server 2016 STIG Finding V-73699
            System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing                            = 'Enabled' #? Windows Server 2016 STIG Finding V-73701

            System_objects_Require_case_insensitivity_for_non_Windows_subsystems                                            = 'Enabled' #? Windows Server 2016 STIG Finding V-73703
            System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links                      = 'Enabled' #? Windows Server 2016 STIG Finding V-73705

            System_settings_Use_Certificate_Rules_on_Windows_Executables_for_Software_Restriction_Policies                  = 'Disabled'

            User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account                                 = 'Enabled' #? Windows Server 2016 STIG Finding V-73707
            User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop       = 'Disabled' #? Windows Server 2016 STIG Finding V-73709
            User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode                 = 'Prompt for consent on the secure desktop' #? Windows Server 2016 STIG Finding V-73711
            User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users                                        = 'Automatically deny elevation request' #? Windows Server 2016 STIG Finding V-73713
            User_Account_Control_Detect_application_installations_and_prompt_for_elevation                                  = 'Enabled' #? Windows Server 2016 STIG Finding V-73715
            User_Account_Control_Only_elevate_executables_that_are_signed_and_validated                                     = 'Disabled'
            User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations                  = 'Enabled' #? Windows Server 2016 STIG Finding V-73717
            User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode                                              = 'Enabled' #? Windows Server 2016 STIG Finding V-73719
            User_Account_Control_Switch_to_the_secure_desktop_when_prompting_for_elevation                                  = 'Enabled'
            User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations                          = 'Enabled' #? Windows Server 2016 STIG Finding V-73721
        }

        #endregion Local Security Options (SecurityPolicyDSC Module)

        #region Local Account Policies (SecurityPolicyDSC Module)

        AccountPolicy 'Local Account Policies' {
            Name                                        = 'AccountPolicies'
            Account_lockout_duration                    = '15' #? Windows Server 2016 STIG Finding V-73309
            Account_lockout_threshold                   = '3' #? Windows Server 2016 STIG Finding V-73311
            Reset_account_lockout_counter_after         = '15' #? Windows Server 2016 STIG Finding V-73313
            Enforce_password_history                    = '24' #? Windows Server 2016 STIG Finding V-73315
            Maximum_Password_Age                        = '60' #? Windows Server 2016 STIG Finding V-73317
            Minimum_Password_Age                        = '1' #? Windows Server 2016 STIG Finding V-73319
            Minimum_Password_Length                     = '14' #? Windows Server 2016 STIG Finding V-73321
            Password_must_meet_complexity_requirements  = 'Enabled' #? Windows Server 2016 STIG Finding V-73323
            Store_passwords_using_reversible_encryption = 'Disabled' #? Windows Server 2016 STIG Finding V-73325
        }

        #endregion Local Account Policies (SecurityPolicyDSC Module)

        #region User Rights Assignment (SecurityPolicyDSC Module)

        UserRightsAssignment 'User Rights - Adjust_memory_quotas_for_a_process' {
            Policy   = 'Adjust_memory_quotas_for_a_process'
            Identity = 'NT AUTHORITY\LOCAL SERVICE', 'NT AUTHORITY\NETWORK SERVICE', 'BUILTIN\Administrators'
            Force    = $true
        }

        UserRightsAssignment 'User Rights - Bypass_traverse_checking' {
            Policy   = 'Bypass_traverse_checking'
            Identity = 'BUILTIN\Administrators', 'NT AUTHORITY\Authenticated Users', 'NT AUTHORITY\LOCAL SERVICE', 'NT AUTHORITY\NETWORK SERVICE'
            Force    = $true
        }

        #? Windows Server 2016 STIG Findings V-73759 & V-73757
        UserRightsAssignment 'User Rights - Deny_access_to_this_computer_from_the_network (V-73759, V-73757)' {
            Policy   = 'Deny_access_to_this_computer_from_the_network'
            Identity = 'BUILTIN\Guests'
            Force    = $true
        }

        #? Windows Server 2016 STIG Finding V-73763 & V-73761
        UserRightsAssignment 'User Rights - Deny_log_on_as_a_batch_job (V-73763, V-73761)' {
            Policy   = 'Deny_log_on_as_a_batch_job'
            Identity = 'BUILTIN\Guests'
            Force    = $true
        }

        #? Windows Server 2016 STIG Findings V-73767 & V-73765
        UserRightsAssignment 'User Rights - Deny_log_on_as_a_service (V-73767, V-73765)' {
            Policy   = 'Deny_log_on_as_a_service'
            Identity = 'BUILTIN\Guests'
            Force    = $true
        }

        #? Windows Server 2016 STIG Findings V-73771 & V-73769
        UserRightsAssignment 'User Rights - Deny_log_on_locally (V-73771, V-73769)' {
            Policy   = 'Deny_log_on_locally'
            Identity = 'BUILTIN\Guests'
            Force    = $true
        }

        #? Windows Server 2016 STIG Finding V-73775 & V-73773
        UserRightsAssignment 'User Rights - Deny_log_on_through_Remote_Desktop_Services (V-73775, V-73773)' {
            Policy   = 'Deny_log_on_through_Remote_Desktop_Services'
            Identity = 'BUILTIN\Guests'
            Force    = $true
        }

        #? Windows Server 2016 STIG Finding V-73729
        UserRightsAssignment 'User Rights - Access_Credential_Manager_as_a_trusted_caller (V-73729)' {
            Policy   = 'Access_Credential_Manager_as_a_trusted_caller'
            Identity = ''
            Force    = $true
        }

        #? Windows Server 2016 STIG Finding V-73733
        UserRightsAssignment 'User Rights - Access_this_computer_from_the_network (V-73733, V-73731)' {
            Policy   = 'Access_this_computer_from_the_network'
            Identity = 'BUILTIN\Administrators', 'NT AUTHORITY\Authenticated Users', 'NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS'
            Force    = $true
        }

        #? Windows Server 2016 STIG Finding V-73735
        UserRightsAssignment 'User Rights - Act_as_part_of_the_operating_system (V-73735)' {
            Policy   = 'Act_as_part_of_the_operating_system'
            Identity = ''
            Force    = $true
        }

        #? Windows Server 2016 STIG Finding V-73737
        UserRightsAssignment 'User Rights - Add_workstations_to_domain (V-73737)' {
            Policy   = 'Add_workstations_to_domain'
            Identity = 'BUILTIN\Administrators'
            Force    = $true
        }

        #? Windows Server 2016 STIG Finding V-73739
        UserRightsAssignment 'User Rights - Allow_log_on_locally (V-73739)' {
            Policy   = 'Allow_log_on_locally'
            Identity = 'BUILTIN\Administrators'
            Force    = $true
        }

        #? Windows Server 2016 STIG Finding V-73741
        UserRightsAssignment 'User Rights - Allow_log_on_through_Remote_Desktop_Services (V-73741)' {
            Policy   = 'Allow_log_on_through_Remote_Desktop_Services'
            Identity = 'BUILTIN\Administrators'
            Force    = $true
        }

        #? Windows Server 2016 STIG Finding V-73743
        UserRightsAssignment 'User Rights - Back_up_files_and_directories (V-73743)' {
            Policy   = 'Back_up_files_and_directories'
            Identity = 'BUILTIN\Administrators'
            Force    = $true
        }

        UserRightsAssignment 'User Rights - Change_the_system_time' {
            Policy   = 'Change_the_system_time'
            Identity = 'BUILTIN\Administrators', 'NT AUTHORITY\LOCAL SERVICE'
            Force    = $true
        }

        #? Windows Server 2016 STIG Finding V-73745
        UserRightsAssignment 'User Rights - Create_a_pagefile (V-73745)' {
            Policy   = 'Create_a_pagefile'
            Identity = 'BUILTIN\Administrators'
            Force    = $true
        }

        #? Windows Server 2016 STIG Finding V-73747
        UserRightsAssignment 'User Rights - Create_a_token_object (V-73747)' {
            Policy   = 'Create_a_token_object'
            Identity = ''
            Force    = $true
        }

        #? Windows Server 2016 STIG Finding V-73749
        UserRightsAssignment 'User Rights - Create_global_objects (V-73749)' {
            Policy   = 'Create_global_objects'
            Identity = 'BUILTIN\Administrators', 'NT AUTHORITY\SERVICE', 'NT AUTHORITY\LOCAL SERVICE', 'NT AUTHORITY\NETWORK SERVICE'
            Force    = $true
        }

        #? Windows Server 2016 STIG Finding V-73751
        UserRightsAssignment 'User Rights - Create_permanent_shared_objects (V-73751)' {
            Policy   = 'Create_permanent_shared_objects'
            Identity = ''
            Force    = $true
        }

        #? Windows Server 2016 STIG Finding V-73753
        UserRightsAssignment 'User Rights - Create_symbolic_links (V-73753)' {
            Policy   = 'Create_symbolic_links'
            Identity = 'BUILTIN\Administrators'
            Force    = $true
        }

        #? Windows Server 2016 STIG Finding V-73755
        UserRightsAssignment 'User Rights - Debug_programs (V-73755)' {
            Policy   = 'Debug_programs'
            Identity = 'BUILTIN\Administrators'
            Force    = $true
        }

        #? Windows Server 2016 STIG Finding V-73779
        UserRightsAssignment 'User Rights - Enable_computer_and_user_accounts_to_be_trusted_for_delegation (V-73779)' {
            Policy   = 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
            Identity = ''
            Force    = $true
        }

        #? Windows Server 2016 STIG Finding V-73781
        UserRightsAssignment 'User Rights - Force_shutdown_from_a_remote_system (V-73781)' {
            Policy   = 'Force_shutdown_from_a_remote_system'
            Identity = 'BUILTIN\Administrators'
            Force    = $true
        }

        #? Windows Server 2016 STIG Finding V-73783
        UserRightsAssignment 'User Rights - Generate_security_audits (V-73783)' {
            Policy   = 'Generate_security_audits'
            Identity = 'NT AUTHORITY\LOCAL SERVICE', 'NT AUTHORITY\NETWORK SERVICE'
            Force    = $true
        }

        #? Windows Server 2016 STIG Finding V-73785
        UserRightsAssignment 'User Rights - Impersonate_a_client_after_authentication (V-73785)' {
            Policy   = 'Impersonate_a_client_after_authentication'
            Identity = 'BUILTIN\Administrators', 'NT AUTHORITY\SERVICE', 'NT AUTHORITY\LOCAL SERVICE', 'NT AUTHORITY\NETWORK SERVICE'
            Force    = $true
        }

        UserRightsAssignment 'User Rights - Increase_a_process_working_set' {
            Policy   = 'Increase_a_process_working_set'
            Identity = 'BUILTIN\Administrators'
            Force    = $true
        }

        #? Windows Server 2016 STIG Finding V-73787
        UserRightsAssignment 'User Rights - Increase_scheduling_priority (V-73787)' {
            Policy   = 'Increase_scheduling_priority'
            Identity = 'BUILTIN\Administrators'
            Force    = $true
        }

        #? Windows Server 2016 STIG Finding V-73789
        UserRightsAssignment 'User Rights - Load_and_unload_device_drivers (V-73789)' {
            Policy   = 'Load_and_unload_device_drivers'
            Identity = 'BUILTIN\Administrators'
            Force    = $true
        }

        #? Windows Server 2016 STIG Finding V-73791
        UserRightsAssignment 'User Rights - Lock_pages_in_memory (V-73791)' {
            Policy   = 'Lock_pages_in_memory'
            Identity = ''
            Force    = $true
        }

        UserRightsAssignment 'User Rights - Log_on_as_a_batch_job' {
            Policy   = 'Log_on_as_a_batch_job'
            Identity = 'BUILTIN\Administrators'
            Force    = $true
        }

        #? Windows Server 2016 STIG Finding V-73793
        UserRightsAssignment 'User Rights - Manage_auditing_and_security_log (V-73793)' {
            Policy   = 'Manage_auditing_and_security_log'
            Identity = 'BUILTIN\Administrators'
            Force    = $true
        }

        UserRightsAssignment 'User Rights - Modify_an_object_label' {
            Policy   = 'Modify_an_object_label'
            Identity = 'BUILTIN\Administrators'
            Force    = $true
        }

        #? Windows Server 2016 STIG Finding V-73795
        UserRightsAssignment 'User Rights - Modify_firmware_environment_values (V-73795)' {
            Policy   = 'Modify_firmware_environment_values'
            Identity = 'BUILTIN\Administrators'
            Force    = $true
        }

        #? Windows Server 2016 STIG Finding V-73797
        UserRightsAssignment 'User Rights - Perform_volume_maintenance_tasks (V-73797)' {
            Policy   = 'Perform_volume_maintenance_tasks'
            Identity = 'BUILTIN\Administrators'
            Force    = $true
        }

        #? Windows Server 2016 STIG Finding V-73799
        UserRightsAssignment 'User Rights - Profile_single_process (V-73799)' {
            Policy   = 'Profile_single_process'
            Identity = 'BUILTIN\Administrators'
            Force    = $true
        }

        UserRightsAssignment 'User Rights - Remove_computer_from_docking_station' {
            Policy   = 'Remove_computer_from_docking_station'
            Identity = 'BUILTIN\Administrators'
            Force    = $true
        }

        #? Windows Server 2016 STIG Finding V-73801
        UserRightsAssignment 'User Rights - Restore_files_and_directories (V-73801)' {
            Policy   = 'Restore_files_and_directories'
            Identity = 'BUILTIN\Administrators'
            Force    = $true
        }

        UserRightsAssignment 'User Rights - Shut_down_the_system' {
            Policy   = 'Shut_down_the_system'
            Identity = 'BUILTIN\Administrators'
            Force    = $true
        }

        #? Windows Server 2016 STIG Finding V-73803
        UserRightsAssignment 'User Rights - Take_ownership_of_files_or_other_objects (V-73803)' {
            Policy   = 'Take_ownership_of_files_or_other_objects'
            Identity = 'BUILTIN\Administrators'
            Force    = $true
        }

        #endregion User Rights Assignment (SecurityPolicyDSC Module)

        #region Other Windows Security Items

        Registry 'System Certificates - Disable Root Auto Update' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\SystemCertificates\AuthRoot'
            ValueName = 'DisableRootAutoUpdate'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Disable Windows Consumer Features' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CloudContent'
            ValueName = 'DisableWindowsConsumerFeatures'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        #? Windows Server 2016 STIG Finding V-73513
        Registry 'Device Guard - Enable Virtualization Based Security (V-73513)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard'
            ValueName = 'EnableVirtualizationBasedSecurity'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        #? Windows Server 2016 STIG Finding V-73513
        Registry 'Device Guard - Require Platform Security Features (V-73513)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard'
            ValueName = 'RequirePlatformSecurityFeatures'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        #? Windows Server 2016 STIG Finding V-73517
        Registry 'Device Guard - Hypervisor Enforced Code Integrity (V-73517)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard'
            ValueName = 'HypervisorEnforcedCodeIntegrity'
            ValueType = 'DWord'
            ValueData = '2'
            Force     = $true
        }

        #? Windows Server 2016 STIG Finding V-73515
        Registry 'Device Guard - LsaCfgFlags' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard'
            ValueName = 'LsaCfgFlags'
            ValueType = 'DWord'
            ValueData = '2'
            Force     = $true
        }

        Registry 'App Compatibility - Disable Engine' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\AppCompat'
            ValueName = 'DisableEngine'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'App Compatibility - Disable PcaUI' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\AppCompat'
            ValueName = 'DisablePcaUI'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        #? Windows Server 2016 STIG Finding V-73543
        Registry 'App Compatibility - Disable Inventory (V-73543)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat'
            ValueName = 'DisableInventory'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'AppX - Allow All Trusted Apps' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\Appx'
            ValueName = 'AllowAllTrustedApps'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        #? Windows Server 2016 STIG Finding V-73533
        Registry 'Do not Enumerate Local Users (V-73533)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\System'
            ValueName = 'EnumerateLocalUsers'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        #? Windows Server 2016 STIG Finding V-73559
        Registry 'Enable Smart Screen (V-73559)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\System'
            ValueName = 'EnableSmartScreen'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        #? Windows Server 2016 STIG Finding V-73597
        Registry 'WinRM - Client Do not Allow Digest (V-73597)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client'
            ValueName = 'AllowDigest'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        #? Windows Server 2016 STIG Finding V-73595
        Registry 'WinRM - Client Do not Allow Unencrypted Traffic (V-73595)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client'
            ValueName = 'AllowUnencryptedTraffic'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        #? Windows Server 2016 STIG Finding V-73593
        Registry 'WinRM - Client Do not Allow Basic Authentication (V-73593)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client'
            ValueName = 'AllowBasic'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        #? Windows Server 2016 STIG Finding V-73603
        Registry 'WinRM - Service Disable Run As (V-73603)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service'
            ValueName = 'DisableRunAs'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        #? Windows Server 2016 STIG Finding V-73599
        Registry 'WinRM - Service Do not Allow Basic Authentication (V-73599)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service'
            ValueName = 'AllowBasic'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        #? Windows Server 2016 STIG Finding V-73601
        Registry 'WinRM - Service Do not Allow Unencrypted Traffic (V-73601)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service'
            ValueName = 'AllowUnencryptedTraffic'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry 'WinRM - Allow Auto Config' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service'
            ValueName = 'AllowAutoConfig'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'WinRM - IPv4 Filter' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service'
            ValueName = 'IPv4Filter'
            ValueType = 'String'
            ValueData = '*'
            Force     = $true
        }

        Registry 'WinRM - IPv6 Filter' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service'
            ValueName = 'IPv6Filter'
            ValueType = 'String'
            ValueData = '*'
            Force     = $true
        }

        Registry 'Windows Remote Shell - Idle Timeout' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\WinRS'
            ValueName = 'IdleTimeout'
            ValueType = 'DWord'
            ValueData = '900000'
            Force     = $true
        }

        Registry 'Windows Remote Shell - Allow Remote Shell Access' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\WinRS'
            ValueName = 'AllowRemoteShellAccess'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        #? Windows Server 2016 STIG Finding V-73541
        Registry 'RPC - Restrict Remote Clients (V-73541)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows NT\Rpc'
            ValueName = 'RestrictRemoteClients'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        #endregion Other Windows Security Items

        #region SCHANNEL/Crypto and Authentication

        #? New local Administrator account
        User 'Local Accounts - Administrator' {
            UserName                 = $AdminName
            Disabled                 = $false
            Ensure                   = 'Present'
            FullName                 = $AdminName
            Description              = ''
            PasswordNeverExpires     = $true
            PasswordChangeRequired   = $false
            PasswordChangeNotAllowed = $false
        }

        #? Built-in local Guest account
        User 'Local Accounts - Guest' {
            UserName                 = $GuestName
            Disabled                 = $true
            Ensure                   = 'Present'
            FullName                 = $GuestName
            Description              = ''
            PasswordNeverExpires     = $true
            PasswordChangeRequired   = $false
            PasswordChangeNotAllowed = $true
        }

        Group 'Local Guests Group Members' {
            GroupName        = 'Guests'
            Ensure           = 'Present'
            MembersToInclude = "localhost\$($GuestName)"
        }

        Registry 'Disable Biometrics' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Biometrics'
            ValueName = 'Enabled'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry 'Block User Input Methods For SignIn' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Control Panel\International'
            ValueName = 'BlockUserInputMethodsForSignIn'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Disable Auto Admin Logon' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
            ValueName = 'AutoAdminLogon'
            ValueType = 'String'
            ValueData = '0'
            Force     = $true
        }

        Registry 'Microsoft Virtual System Migration Service - Allow Default Credentials' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowDefaultCredentials'
            ValueName = '1'
            ValueType = 'String'
            ValueData = 'Microsoft Virtual System Migration Service/*'
            Force     = $true
        }

        Registry 'Microsoft Virtual System Migration Service - Allow Default Credentials When NTLMOnly' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowDefCredentialsWhenNTLMOnly'
            ValueName = '2'
            ValueType = 'String'
            ValueData = 'Microsoft Virtual System Migration Service/*'
            Force     = $true
        }

        Registry 'Microsoft Virtual Console Service - Allow Default Credentials' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowDefaultCredentials'
            ValueName = '2'
            ValueType = 'String'
            ValueData = 'Microsoft Virtual Console Service/*'
            Force     = $true
        }

        Registry 'Microsoft Virtual Console Service - Allow Default Credentials When NTLMOnly' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowDefCredentialsWhenNTLMOnly'
            ValueName = '1'
            ValueType = 'String'
            ValueData = 'Microsoft Virtual Console Service/*'
            Force     = $true
        }

        Registry 'Credentials Delegation - Allow Default Credentials' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation'
            ValueName = 'AllowDefaultCredentials'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Credentials Delegation - Concatenate Defaults-Allow Default' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation'
            ValueName = 'ConcatenateDefaults_AllowDefault'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Credentials Delegation - Allow Default Credentials When NTLMOnly' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation'
            ValueName = 'AllowDefCredentialsWhenNTLMOnly'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Credentials Delegation - Concatenate Defaults-Allow Default NTLM Only' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation'
            ValueName = 'ConcatenateDefaults_AllowDefNTLMOnly'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Smart Cards - Enable Smart card PnP' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\ScPnP'
            ValueName = 'EnableScPnP'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Smart Cards - Disable Smart card PnP Notification' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\ScPnP'
            ValueName = 'ScPnPNotification'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry 'Enable SchUseStrongCrypto for .NetFramework v4.0.30319 (Wow6432)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319'
            ValueName = 'SchUseStrongCrypto'
            ValueType = 'Dword'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Enable SchUseStrongCrypto for .NetFramework v4.0.30319' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319'
            ValueName = 'SchUseStrongCrypto'
            ValueType = 'Dword'
            ValueData = '1'
            Force     = $true
        }

        Registry 'SCHANNEL Ciphers - Disable AES 128/128' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128'
            ValueName = 'Enabled'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry 'SCHANNEL Ciphers - Disable DES 168/168' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 168/168'
            ValueName = 'Enabled'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry 'SCHANNEL Ciphers - Disable DES 56/56' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56'
            ValueName = 'Enabled'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry 'SCHANNEL Ciphers - Disable RC2 128/128' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128'
            ValueName = 'Enabled'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry 'SCHANNEL Ciphers - Disable RC2 40/128' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128'
            ValueName = 'Enabled'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry 'SCHANNEL Ciphers - Disable RC2 56/128' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128'
            ValueName = 'Enabled'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry 'SCHANNEL Ciphers - Disable RC4 128/128' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128'
            ValueName = 'Enabled'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry 'SCHANNEL Ciphers - Disable RC4 40/128' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128'
            ValueName = 'Enabled'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry 'SCHANNEL Ciphers - Disable RC4 56/128' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128'
            ValueName = 'Enabled'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry 'SCHANNEL Ciphers - Disable RC4 64/128' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128'
            ValueName = 'Enabled'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry 'SCHANNEL Ciphers - Disable Triple DES 168/168' {
            Ensure    = 'Absent'
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168/168'
            ValueName = 'Enabled'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry 'SCHANNEL Protocols - Set SSL 2.0 Client-DisabledByDefault On' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client'
            ValueName = 'DisabledByDefault'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'SCHANNEL Protocols - Set SSL 2.0 Server-DisabledByDefault On' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server'
            ValueName = 'DisabledByDefault'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'SCHANNEL Protocols - Disable SSL 2.0 Client' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client'
            ValueName = 'Enabled'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry 'SCHANNEL Protocols - Disable SSL 2.0 Server' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server'
            ValueName = 'Enabled'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry 'SCHANNEL Protocols - Set SSL 3.0 Client-DisabledByDefault On' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client'
            ValueName = 'DisabledByDefault'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'SCHANNEL Protocols - Set SSL 3.0 Server-DisabledByDefault On' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server'
            ValueName = 'DisabledByDefault'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'SCHANNEL Protocols - Disable SSL 3.0 Client' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client'
            ValueName = 'Enabled'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry 'SCHANNEL Protocols - Disable SSL 3.0 Server' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server'
            ValueName = 'Enabled'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry 'SCHANNEL Protocols - Set TLS 1.0 Client-DisabledByDefault On' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client'
            ValueName = 'DisabledByDefault'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'SCHANNEL Protocols - Set TLS 1.0 Server-DisabledByDefault On' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server'
            ValueName = 'DisabledByDefault'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'SCHANNEL Protocols - Disable TLS 1.0 Client' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client'
            ValueName = 'Enabled'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry 'SCHANNEL Protocols - Disable TLS 1.0 Server' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server'
            ValueName = 'Enabled'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry 'SCHANNEL Protocols - Set TLS 1.1 Client-DisabledByDefault Off' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client'
            ValueName = 'DisabledByDefault'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry 'SCHANNEL Protocols - Set TLS 1.1 Server-DisabledByDefault Off' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server'
            ValueName = 'DisabledByDefault'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry 'SCHANNEL Protocols - Enable TLS 1.1 Client' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client'
            ValueName = 'Enabled'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'SCHANNEL Protocols - Enable TLS 1.1 Server' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server'
            ValueName = 'Enabled'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'SCHANNEL Protocols - Set TLS 1.2 Client-DisabledByDefault Off' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client'
            ValueName = 'DisabledByDefault'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry 'SCHANNEL Protocols - Set TLS 1.2 Server-DisabledByDefault Off' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server'
            ValueName = 'DisabledByDefault'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry 'SCHANNEL Protocols - TLS 1.2 Client-Enabled' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client'
            ValueName = 'Enabled'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'SCHANNEL Protocols - TLS 1.2 Server-Enabled' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server'
            ValueName = 'Enabled'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'SCHANNEL Hashes - Disable MD5' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5'
            ValueName = 'Enabled'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry 'SCHANNEL Hashes - Disable SHA' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA'
            ValueName = 'Enabled'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        #? Windows Server 2016 STIG Finding V-73507
        Registry 'Windows Authentication - Do not Allow Insecure Guest Authentication (V-73507)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'
            ValueName = 'AllowInsecureGuestAuth'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        #? Windows Server 2016 STIG Finding V-73487
        Registry 'Credentials UI - Do not Enumerate Administrators (V-73487)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI'
            ValueName = 'EnumerateAdministrators'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        #? Windows Server 2016 STIG Finding V-73495
        Registry 'Local Account Token Filter Policy (V-73495)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName = 'LocalAccountTokenFilterPolicy'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry 'CredSSP CVE-2018-0886 Mitigation' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters'
            ValueName = 'AllowEncryptionOracle'
            ValueType = 'Dword'
            ValueData = '1'
            Force     = $true
        }

        #endregion SCHANNEL/Crypto and Authentication

        #region Remote Desktop Settings

        Registry 'RDP - Disable Client COM Port Mapping' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'fDisableCcm'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        #? Windows Server 2016 STIG Finding V-73569
        Registry 'RDP - Disable Client Drive Mapping (V-73569)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'fDisableCdm'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'RDP - Logging Enabled' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'LoggingEnabled'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        #? Windows Server 2016 STIG Finding V-73571
        Registry 'RDP - Always Prompt for Password (V-73571)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'fPromptForPassword'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        #? Windows Server 2016 STIG Finding V-73575
        Registry 'RDP - Minimum Encryption Level (V-73575)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'MinEncryptionLevel'
            ValueType = 'DWord'
            ValueData = '3'
            Force     = $true
        }

        Registry 'RDP - Per Session Temp Dir' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'PerSessionTempDir'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'RDP - Delete Temp Dirs On Exit' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'DeleteTempDirsOnExit'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        #? Windows Server 2016 STIG Finding V-73573
        Registry 'RDP - Encrypt RPC Traffic (V-73573)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'fEncryptRPCTraffic'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'RDP - Enable Smart Cards' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'fEnableSmartCard'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'RDP - Max Ticket Expiry Units' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'MaxTicketExpiryUnits'
            ValueType = 'String'
            ValueData = ' '
            Force     = $true
        }

        Registry 'RDP - Max Ticket Expiry' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'MaxTicketExpiry'
            ValueType = 'String'
            ValueData = ' '
            Force     = $true
        }

        Registry 'RDP - Licensing Mode' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'LicensingMode'
            ValueType = 'DWord'
            ValueData = '2'
            Force     = $true
        }

        Registry 'RDP - Disable Auto Reconnect' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'fDisableAutoReconnect'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry 'RDP - Enable Keep Alive' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'KeepAliveEnable'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'RDP - Keep Alive Interval' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'KeepAliveInterval'
            ValueType = 'DWord'
            ValueData = '3'
            Force     = $true
        }

        Registry 'RDP - Disable Select Network Detect' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'SelectNetworkDetect'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry 'RDP - Max Disconnection Time' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'MaxDisconnectionTime'
            ValueType = 'DWord'
            ValueData = '86400000'
            Force     = $true
        }

        Registry 'RDP - Max Idle Time' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'MaxIdleTime'
            ValueType = 'DWord'
            ValueData = '86400000'
            Force     = $true
        }

        Registry 'RDP - Max Connection Time' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'MaxConnectionTime'
            ValueType = 'DWord'
            ValueData = '172800000'
            Force     = $true
        }

        Registry 'RDP - Reset Broken Session' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'fResetBroken'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'RDP - Security Layer' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'SecurityLayer'
            ValueType = 'DWord'
            ValueData = '2'
            Force     = $true
        }

        Registry 'RDP - Disable Solicited Remote Assistance' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'fUseMailto'
            ValueType = 'String'
            ValueData = ' '
            Force     = $true
        }

        Registry 'RDP - User Authentication' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'UserAuthentication'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'RDP - Do not Deny TS Connections' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'fDenyTSConnections'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        #? Windows Server 2016 STIG Finding V-73567
        Registry 'RDP - Disable Password Saving (V-73567)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'DisablePasswordSaving'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'RDP - Disable Unsolicited Remote Assistance' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'fAllowUnsolicited'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry 'RDP - Allow Full Control' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'fAllowFullControl'
            ValueType = 'String'
            ValueData = ' '
            Force     = $true
        }

        Registry 'RDP - Disable Remote Assistance Requests' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'fAllowToGetHelp'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry 'RDP - Allow a Single Session Per User' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'fSingleSessionPerUser'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'RDP - Disable LPT Printing' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'fDisableLPT'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'RDP - Disable PnP Redir' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'fDisablePNPRedir'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'RDP - Redirect Only Default Client Printer' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'RedirectOnlyDefaultClientPrinter'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Disable Using Current Working Dir for Dll Search' {
            Ensure    = 'Present'
            Key       = 'HKLM:\System\CurrentControlSet\Control\SessionManager'
            ValueName = 'CWDIllegalInDllSearch'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        #endregion Remote Desktop Settings

        #region Networking

        Registry 'Disable PeerNet' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Peernet'
            ValueName = 'Disabled'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'TCPIP - Keep Alive Time' {
            Ensure    = 'Present'
            Key       = 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters'
            ValueName = 'KeepAliveTime'
            ValueType = 'Dword'
            ValueData = '300000'
            Force     = $true
        }

        #? Windows Server 2016 STIG Finding V-73501
        Registry 'TCPIP - Disable IP Source Routing (V-73501)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters'
            ValueName = 'DisableIPSourceRouting'
            ValueType = 'Dword'
            ValueData = '2'
            Force     = $true
        }

        #? Windows Server 2016 STIG Finding V-73499
        Registry 'TCPIP - Disable IP Source Routing v6 (V-73499)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters'
            ValueName = 'DisableIPSourceRouting'
            ValueType = 'Dword'
            ValueData = '2'
            Force     = $true
        }

        Registry 'TCPIP - Enable Dead Gateway Detect' {
            Ensure    = 'Present'
            Key       = 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters'
            ValueName = 'EnableDeadGWDetect'
            ValueType = 'Dword'
            ValueData = '0'
            Force     = $true
        }

        #? Windows Server 2016 STIG Finding V-73503
        Registry 'TCPIP - Enable ICMP Redirect (V-73503)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters'
            ValueName = 'EnableICMPRedirect'
            ValueType = 'Dword'
            ValueData = '0'
            Force     = $true
        }

        #? Windows Server 2016 STIG Finding V-73505
        Registry 'NetBIOS - No Name Release On Demand (V-73505)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\System\CurrentControlSet\Services\Netbt\Parameters'
            ValueName = 'NoNameReleaseOnDemand'
            ValueType = 'Dword'
            ValueData = '1'
            Force     = $true
        }

        Registry 'TCPIP - Enable IP Autoconfiguration Limits' {
            Ensure    = 'Present'
            Key       = 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters'
            ValueName = 'EnableIPAutoConfigurationLimits'
            ValueType = 'Dword'
            ValueData = '1'
            Force     = $true
        }

        Registry 'TCPIP - Perform Router Discovery' {
            Ensure    = 'Present'
            Key       = 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters'
            ValueName = 'PerformRouterDiscovery'
            ValueType = 'Dword'
            ValueData = '0'
            Force     = $true
        }

        Registry 'TCPIP - Syn Attack Protect' {
            Ensure    = 'Present'
            Key       = 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters'
            ValueName = 'SynAttackProtect'
            ValueType = 'Dword'
            ValueData = '1'
            Force     = $true
        }

        Registry 'TCPIP - Tcp Max Data Retransmissions' {
            Ensure    = 'Present'
            Key       = 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters'
            ValueName = 'TcpMaxDataRetransmissions'
            ValueType = 'Dword'
            ValueData = '3'
            Force     = $true
        }

        NetAdapterAdvancedProperty 'Enable Jumbo Packets' {
            NetworkAdapterName = 'Ethernet'
            RegistryKeyword    = '*JumboPacket'
            RegistryValue      = 9014
        }

        Registry 'Link Layer Topology Discovery - Disable LLTDIO' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\LLTD'
            ValueName = 'EnableLLTDIO'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry 'Link Layer Topology Discovery - Disable Responder' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\LLTD'
            ValueName = 'EnableRspndr'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry 'Disable Network Bridging' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\Network Connections'
            ValueName = 'NC_AllowNetBridge_NLA'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry 'Require domain users to elevate when setting a networks location' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\Network Connections'
            ValueName = 'NC_StdDomainUserSetLocation'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Windows Connect Now - Disable Registrars' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\WCN\Registrars'
            ValueName = 'EnableRegistrars'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry 'Windows Connect Now - Disable WCN UI' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\WCN\UI'
            ValueName = 'DisableWcnUi'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Prevent Device Metadata From Network' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\Device Metadata'
            ValueName = 'PreventDeviceMetadataFromNetwork'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'IPv6 - Enable Forced Tunneling' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\TCPIP\v6Transition'
            ValueName = 'Force_Tunneling'
            ValueType = 'String'
            ValueData = 'Enabled'
            Force     = $true
        }

        Registry 'IPv6 - 6to4 State' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\TCPIP\v6Transition'
            ValueName = '6to4_State'
            ValueType = 'String'
            ValueData = 'Default'
            Force     = $true
        }

        Registry 'WLAN Driver Interface - Disable Scenario Execution' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}'
            ValueName = 'ScenarioExecutionEnabled'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        #endregion Networking

        #region Windows Features and Services

        WindowsFeature 'Install Windows Feature - Dot Net 45' {
            Ensure = 'Present'
            Name   = 'NET-Framework-45-Core'
        }

        WindowsFeature 'Remove Windows Feature - Peer Name Resolution Protocol (V-73291)' {
            Ensure               = 'Absent'
            Name                 = 'PNRP'
            IncludeAllSubFeature = $true
        }

        WindowsFeature 'Remove Windows Feature - Simple TCP/IP Services (V-73293)' {
            Ensure               = 'Absent'
            Name                 = 'Simple-TCPIP'
            IncludeAllSubFeature = $true
        }

        WindowsFeature 'Remove Windows Feature - Telnet Client (V-73295)' {
            Ensure               = 'Absent'
            Name                 = 'Telnet-Client'
            IncludeAllSubFeature = $true
        }

        WindowsFeature 'Remove Windows Feature - Windows PowerShell 2.0 (V-73301)' {
            Ensure               = 'Absent'
            Name                 = 'PowerShell-V2'
            IncludeAllSubFeature = $true
        }

        WindowsFeature 'Remove Windows Feature - Microsoft FTP service (V-73289)' {
            Ensure               = 'Absent'
            Name                 = 'Web-Ftp-Server'
            IncludeAllSubFeature = $true
        }

        WindowsFeature 'Remove Windows Feature - Server Message Block (SMB) v1 (V-73299)' {
            Ensure               = 'Absent'
            Name                 = 'FS-SMB1'
            IncludeAllSubFeature = $true
        }

        WindowsFeature 'Remove Windows Feature - Print and Document Services' {
            Ensure               = 'Absent'
            Name                 = 'Print-Services'
            IncludeAllSubFeature = $true
        }

        WindowsFeature 'Remove Windows Feature - Quality Windows Audio Video Experience' {
            Ensure               = 'Absent'
            Name                 = 'qWave'
            IncludeAllSubFeature = $true
        }

        WindowsFeature 'Remove Windows Feature - Client for NFS' {
            Ensure               = 'Absent'
            Name                 = 'NFS-Client'
            IncludeAllSubFeature = $true
        }

        WindowsFeature 'Remove Windows Feature - Media Foundation' {
            Ensure               = 'Absent'
            Name                 = 'Server-Media-Foundation'
            IncludeAllSubFeature = $true
        }

        Service 'Service - SNMPTRAP' {
            Name        = 'SNMPTRAP'
            Ensure      = 'Present'
            StartupType = 'Automatic'
            State       = 'Running'
        }

        #endregion Windows Features and Services

        #region General Windows Items

        #? 'TimeZone' resource from 'ComputerManagementDsc' module
        TimeZone 'System Time Zone' {
            IsSingleInstance = 'Yes'
            TimeZone         = 'Eastern Standard Time'
        }

        #? Windows Server 2016 STIG Finding V-73557
        WindowsEventLog 'System Event Log Settings (V-73557)' {
            LogName            = 'System'
            IsEnabled          = $true
            LogMode            = 'Circular'
            MaximumSizeInBytes = 128mb
        }

        #? Windows Server 2016 STIG Finding V-73553
        WindowsEventLog 'Application Event Log Settings (V-73553)' {
            LogName            = 'Application'
            IsEnabled          = $true
            LogMode            = 'Circular'
            MaximumSizeInBytes = 128mb
        }

        #? Windows Server 2016 STIG Finding V-73555
        WindowsEventLog 'Security Event Log Settings (V-73555)' {
            LogName            = 'Security'
            IsEnabled          = $true
            LogMode            = 'Circular'
            MaximumSizeInBytes = 256mb
        }

        #? Windows Server 2016 STIG Finding V-73547
        Registry 'Windows Explorer - No Auto Run (V-73547)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueName = 'NoAutoRun'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Windows Explorer - No Disconnect' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueName = 'NoDisconnect'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Windows Explorer - No Web Services' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueName = 'NoWebServices'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Windows Explorer - No Internet Open With' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueName = 'NoInternetOpenWith'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Windows Explorer - No Online Prints Wizard' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueName = 'NoOnlinePrintsWizard'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Windows Explorer - No Publishing Wizard' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueName = 'NoPublishingWizard'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        #? Windows Server 2016 STIG Finding V-73565
        Registry 'Windows Explorer - Pre XP SP2 Shell Protocol Behavior (V-73565)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueName = 'PreXPSP2ShellProtocolBehavior'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        #? Windows Server 2016 STIG Finding V-73549
        Registry 'Windows Explorer - No Drive Type AutoRun (V-73549)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueName = 'NoDriveTypeAutoRun'
            ValueType = 'Dword'
            ValueData = '255'
            Force     = $true
        }

        #? Windows Server 2016 STIG Finding V-73545
        Registry 'Windows Explorer - No Autoplay for non-Volume (V-73545)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'
            ValueName = 'NoAutoplayfornonVolume'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        #? Windows Server 2016 STIG Finding V-73561
        Registry 'Windows Explorer - Enable Data Execution Prevention (V-73561)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'
            ValueName = 'NoDataExecutionPrevention'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        #? Windows Server 2016 STIG Finding V-73563
        Registry 'Windows Explorer - Enable Heap Termination On Corruption (V-73563)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'
            ValueName = 'NoHeapTerminationOnCorruption'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry 'Customer Experience Improvement Program' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Messenger\Client'
            ValueName = 'CEIP'
            ValueType = 'DWord'
            ValueData = '2'
            Force     = $true
        }

        Registry 'Search - Disable Content File Updates' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\SearchCompanion'
            ValueName = 'DisableContentFileUpdates'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Disable Customer Experience Improvement Program' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\SQMClient\Windows'
            ValueName = 'CEIPEnable'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry 'Internet Connection Wizard' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\Internet Connection Wizard'
            ValueName = 'ExitOnMSICW'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        #? Windows Server 2016 STIG Finding V-73529
        Registry 'Disable HTTP Printing (V-73529)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers'
            ValueName = 'DisableHTTPPrinting'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        #? Windows Server 2016 STIG Finding V-73527
        Registry 'Disable Web PnP Download (V-73527)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers'
            ValueName = 'DisableWebPnPDownload'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Windows Error Reporting - Logging Disabled' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting'
            ValueName = 'LoggingDisabled'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry 'Windows Error Reporting - Do not Send Additional Data' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting'
            ValueName = 'DontSendAdditionalData'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        #? Windows Server 2016 STIG Finding V-73587
        Registry 'Windows Installer - Safe For Scripting (V-73587)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\Installer'
            ValueName = 'SafeForScripting'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        #? Windows Server 2016 STIG Finding V-73583
        Registry 'Windows Installer - Enable User Control (V-73583)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\Installer'
            ValueName = 'EnableUserControl'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry 'Windows Mail - Disable Communities' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows Mail'
            ValueName = 'DisableCommunities'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Windows Mail - Manual Launch Allowed' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows Mail'
            ValueName = 'ManualLaunchAllowed'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry 'Windows Messenger - Prevent Run' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Messenger\Client'
            ValueName = 'PreventRun'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Windows Messenger - Prevent AutoRun' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Messenger\Client'
            ValueName = 'PreventAutoRun'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Set Active Power Scheme' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Power\PowerSettings'
            ValueName = 'ActivePowerScheme'
            ValueType = 'String'
            ValueData = '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c'
            Force     = $true
        }

        #? Windows Server 2016 STIG Finding V-73511
        Registry 'ProcessCreationIncludeCmdLine_Enabled (V-73511)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
            ValueName = 'ProcessCreationIncludeCmdLine_Enabled'
            ValueType = 'Dword'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Disable 8dot3 File Name Creation' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem'
            ValueName = 'NtfsDisable8dot3NameCreation'
            ValueType = 'Dword'
            ValueData = '1'
            Force     = $true
        }

        Registry 'SafeDllSearchMode' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
            ValueName = 'SafeDllSearchMode'
            ValueType = 'Dword'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Screen Saver Grace Period' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
            ValueName = 'ScreenSaverGracePeriod'
            ValueType = 'Dword'
            ValueData = '5'
            Force     = $true
        }

        #? Windows Server 2016 STIG Finding V-73537
        Registry 'DC Setting - Prompt for Password on Resume' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
            ValueName = 'DCSettingIndex'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'DC Setting - Idle Timeout' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Power\PowerSettings\3C0BC021-C8A8-4E07-A973-6B14CBCB2B7E'
            ValueName = 'DCSettingIndex'
            ValueType = 'DWord'
            ValueData = '1200'
            Force     = $true
        }

        #? Windows Server 2016 STIG Finding V-73539
        Registry 'AC Setting - Prompt for Password on Resume' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
            ValueName = 'ACSettingIndex'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'AC Setting - Idle Timeout' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Power\PowerSettings\3C0BC021-C8A8-4E07-A973-6B14CBCB2B7E'
            ValueName = 'ACSettingIndex'
            ValueType = 'DWord'
            ValueData = '1200'
            Force     = $true
        }

        Registry 'Do Not Open Server Manager At Logon' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Server\ServerManager'
            ValueName = 'DoNotOpenAtLogon'
            ValueType = 'Dword'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Windows Error Reporting - Disable Send Generic Driver Not Found' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Settings'
            ValueName = 'DisableSendGenericDriverNotFoundToWER'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Windows Error Reporting - Disable Send Request Additional Software' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Settings'
            ValueName = 'DisableSendRequestAdditionalSoftwareToWER'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Windows Device Installation - Do not allow Remote RPC' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Settings'
            ValueName = 'AllowRemoteRPC'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry 'Windows Device Installation - Disable System Restore' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Settings'
            ValueName = 'DisableSystemRestore'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry 'Windows Device Installation - Do not Search Windows Update for drivers' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\DriverSearching'
            ValueName = 'DontSearchWindowsUpdate'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Windows Device Installation - Do not Prompt For Windows Update' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\DriverSearching'
            ValueName = 'DontPromptForWindowsUpdate'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Windows Device Installation - Server Selection' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\DriverSearching'
            ValueName = 'DriverServerSelection'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Windows Update - Do Not Connect To Windows Update Internet Locations' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
            ValueName = 'DoNotConnectToWindowsUpdateInternetLocations'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Windows Update - Do not Elevate Non Admins' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
            ValueName = 'ElevateNonAdmins'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry 'Group Policy - No Background Policy Refresh' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
            ValueName = 'NoBackgroundPolicy'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry 'Group Policy - Enable User Policy Mode' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\System'
            ValueName = 'UserPolicyMode'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        #? Windows Server 2016 STIG Finding V-73525
        Registry 'Group Policy - Always Process Group Policy Objects (V-73525)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
            ValueName = 'NoGPOListChanges'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry 'Tablet Settings - Disable Touch Input' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\TabletPC'
            ValueName = 'TurnOffTouchInput'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        #? Windows Server 2016 STIG Finding V-73585
        Registry 'Windows Installer - Always Install Elevated (V-73585)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\Installer'
            ValueName = 'AlwaysInstallElevated'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry 'Windows Installer - Disable LUA Patching' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\Installer'
            ValueName = 'DisableLUAPatching'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Location and Sensors - Disable Location' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors'
            ValueName = 'DisableLocation'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Disable Registration Wizard' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\Registration Wizard Control'
            ValueName = 'NoRegistration'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Scripted Diagnostics Provider - Enable Query Remote Server' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy'
            ValueName = 'EnableQueryRemoteServer'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry 'Scripted Diagnostics Provider - Disable Query Remote Server' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy'
            ValueName = 'DisableQueryRemoteServer'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        #? Windows Server 2016 STIG Finding V-73531
        Registry 'Lock Screen - Do not Display Network Selection UI (V-73531)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\System'
            ValueName = 'DontDisplayNetworkSelectionUI'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Lock Screen - Disable Lock Screen App Notifications' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\System'
            ValueName = 'DisableLockScreenAppNotifications'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Lock Screen - Disable Camera' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\Personalization'
            ValueName = 'NoLockScreenCamera'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        #? Windows Server 2016 STIG Finding V-73493
        Registry 'Lock Screen - Disable Slideshow (V-73493)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\Personalization'
            ValueName = 'NoLockScreenSlideshow'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Windows Error Reporting - Default Override Behavior' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting\Consent'
            ValueName = 'DefaultOverrideBehavior'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Windows Error Reporting - Disable Archive' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting'
            ValueName = 'DisableArchive'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry 'Windows Error Reporting - Configure Archive' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting'
            ValueName = 'ConfigureArchive'
            ValueType = 'DWord'
            ValueData = '2'
            Force     = $true
        }

        Registry 'Windows Error Reporting - Max Archive Count' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting'
            ValueName = 'MaxArchiveCount'
            ValueType = 'DWord'
            ValueData = '100'
            Force     = $true
        }

        Registry 'Windows Error Reporting - Disable Queue' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting'
            ValueName = 'DisableQueue'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry 'Windows Error Reporting - Force Queue' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting'
            ValueName = 'ForceQueue'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Windows Error Reporting - Max Queue Count' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting'
            ValueName = 'MaxQueueCount'
            ValueType = 'DWord'
            ValueData = '50'
            Force     = $true
        }

        Registry 'Windows Error Reporting - Max Queue Size' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting'
            ValueName = 'MaxQueueSize'
            ValueType = 'DWord'
            ValueData = '1024'
            Force     = $true
        }

        Registry 'Windows Error Reporting - Min Free Disk Space' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting'
            ValueName = 'MinFreeDiskSpace'
            ValueType = 'DWord'
            ValueData = '2800'
            Force     = $true
        }

        Registry 'Windows Error Reporting - Queue Pester Interval' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting'
            ValueName = 'QueuePesterInterval'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Windows Error Reporting - Bypass Data Throttling' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting'
            ValueName = 'BypassDataThrottling'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Windows Error Reporting - Do not Disable' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting'
            ValueName = 'Disabled'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry 'Windows Error Reporting - Do not Show UI' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting'
            ValueName = 'DontShowUI'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Windows Error Reporting - Corporate Wer Server' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting'
            ValueName = 'CorporateWerServer'
            ValueType = 'String'
            ValueData = ' '
            Force     = $true
        }

        Registry 'Windows Error Reporting - Corporate Wer Use SSL' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting'
            ValueName = 'CorporateWerUseSSL'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Windows Error Reporting - Corporate Wer Port Number' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting'
            ValueName = 'CorporateWerPortNumber'
            ValueType = 'DWord'
            ValueData = '1273'
            Force     = $true
        }

        #? Windows Server 2016 STIG Finding V-73581
        Registry 'Windows Search - Do not Allow Indexing Encrypted Stores or Items (V-73581)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\Windows Search'
            ValueName = 'AllowIndexingEncryptedStoresOrItems'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        #? Disables the Windows Help Experience Improvement Program
        Registry 'Windows Remote Assistance - No Implicit Feedback' {
            Ensure    = 'Present'
            Key       = 'HKCU:\Software\Policies\Microsoft\Assistance\Client\1.0'
            ValueName = 'NoImplicitFeedback'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        #? Disables the Windows Help Experience Improvement Program
        Registry 'Windows Remote Assistance - No Explicit Feedback' {
            Ensure    = 'Present'
            Key       = 'HKCU:\Software\Policies\Microsoft\Assistance\Client\1.0'
            ValueName = 'NoExplicitFeedback'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Windows Remote Assistance - No Active Help' {
            Ensure    = 'Present'
            Key       = 'HKCU:\Software\Policies\Microsoft\Assistance\Client\1.0'
            ValueName = 'NoActiveHelp'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        #? Windows Server 2016 STIG - V-73727
        Registry 'File Attachments - Save Zone Information (V-73727)' {
            Ensure    = 'Absent'
            Key       = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments'
            ValueName = 'SaveZoneInformation'
            ValueType = 'DWord'
            Force     = $true
        }

        Registry 'Maps - Do not Auto Download Map Data' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps'
            ValueName = 'AutoDownloadAndUpdateMapData'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        #? Windows Server 2016 STIG Finding V-73551
        Registry 'Windows Telemetry - Set to Basic (V-73551)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
            ValueName = 'AllowTelemetry'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        #? Windows Server 2016 STIG Finding V-73589
        Registry 'Disable Automatic Restart Sign On (V-73589)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName = 'DisableAutomaticRestartSignOn'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        #? Windows Server 2016 STIG Finding V-73591
        Registry 'PowerShell - Enable Script Block Logging (V-73591)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
            ValueName = 'EnableScriptBlockLogging'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'PowerShell - Enable Script Block Invocation Logging' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
            ValueName = 'EnableScriptBlockInvocationLogging'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        #? Windows Server 2016 STIG Finding V-73521
        Registry 'Prevent Boot Drivers Identified as Bad (V-73521)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch'
            ValueName = 'DriverLoadPolicy'
            ValueType = 'DWord'
            ValueData = '3'
            Force     = $true
        }

        #? Windows Server 2016 STIG Finding V-73497
        Registry 'Disable WDigest Authentication (V-73497)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest'
            ValueName = 'UseLogonCredential'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry 'Windows Store - Remove Access to Windows Store' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\WindowsStore'
            ValueName = 'RemoveWindowsStore'
            ValueType = 'Dword'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Windows Store - Disable OS Upgrade via Windows Store' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\WindowsStore'
            ValueName = 'DisableOSUpgrade'
            ValueType = 'Dword'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Windows Store - Disable Windows Store Apps' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\WindowsStore'
            ValueName = 'DisableStoreApps'
            ValueType = 'Dword'
            ValueData = '1'
            Force     = $true
        }

        #endregion General Windows Items

    }
}

Write-Host "##[command] Compiling WindowsBaseOS configuration..."
WindowsBaseOS -OutputPath "$($Destination)" -Verbose
Rename-Item -Path "$($Destination)\localhost.mof" -NewName "WindowsBaseOS.mof" -Verbose
Write-Host "##[command] Creating WindowsBaseOS checksum..."
New-DscChecksum -Path "$($Destination)\WindowsBaseOS.mof" -Force -Verbos