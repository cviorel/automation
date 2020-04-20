####################################################################
# Integration tests for WindowsBaseOS Config
####################################################################

#Requires -Modules @{ ModuleName="Pester";ModuleVersion="4.10.1" }, @{ ModuleName="poshspec";ModuleVersion="2.2.8" }

[cmdletbinding()]
param (
    [parameter()]
    [string]$ComputerName,

    [parameter()]
    [string]$AdminName = $env:LocalAdmin_Name,

    [parameter()]
    [string]$GuestName = $env:LocalGuest_Name
)

Describe "Firewall Rules" {
    Context "RDP Firewall Rules" {
        Firewall "Remote Desktop - User Mode (TCP-In)" Enabled {
            Should -Be $true
        }
        Firewall "Remote Desktop - User Mode (UDP-In)" Enabled {
            Should -Be $true
        }
    }

    Context "Configuration Manager Client Rules" {
        Firewall "Allow-CM-10123-Inbound" Enabled {
            Should -Be $true
        }
        Firewall "Allow-CM-10123-Inbound" Action {
            Should -Be "Allow"
        }
    }

    Context "WinRM & WMI Rules" {
        Firewall "Windows Remote Management (HTTP-In)" Enabled {
            Should -Contain $true
        }
        Firewall "Windows Remote Management (HTTPs-In)" Enabled {
            Should -Be $true
        }
        Firewall "Windows Remote Management (HTTPs-In)" Action {
            Should -Be "Allow"
        }
        Firewall "Windows Defender Firewall Remote Management (RPC)" Enabled {
            Should -Be $true
        }
    }

    Context "File & Printer Sharing" {
        Firewall 'File and Printer Sharing (NB-Datagram-In)' Enabled {
            Should -Be $true
        }
        Firewall 'File and Printer Sharing (NB-Datagram-Out)' Enabled {
            Should -Be $true
        }
        Firewall 'File and Printer Sharing (NB-Name-In)' Enabled {
            Should -Be $true
        }
        Firewall 'File and Printer Sharing (NB-Name-Out)' Enabled {
            Should -Be $true
        }
        Firewall 'File and Printer Sharing (NB-Session-In)' Enabled {
            Should -Be $true
        }
        Firewall 'File and Printer Sharing (NB-Session-Out)' Enabled {
            Should -Be $true
        }
        Firewall 'File and Printer Sharing over SMBDirect (iWARP-In)' Enabled {
            Should -Be $true
        }
        Firewall 'File and Printer Sharing (SMB-In)' Enabled {
            Should -Be $true
        }
        Firewall 'File and Printer Sharing (SMB-Out)' Enabled {
            Should -Be $true
        }
    }

    Context "Remote Event Log Rules" {
        Firewall "Remote Event Log Management (RPC)" Enabled {
            Should -Be $true
        }
        Firewall "Remote Event Log Management (NP-In)" Enabled {
            Should -Be $true
        }
        Firewall "Remote Event Log Management (RPC-EPMAP)" Enabled {
            Should -Be $true
        }
    }
}

Describe "Local Auditing Policies" {
    Context "Audit Policy Options" {
        It "Crash On Audit Fail" {
            (auditpol /get /option:CrashOnAuditFail) -match "Disabled" | Should -Not -Be $null
        }

        It "Full Privilege" {
            (auditpol /get /option:FullPrivilegeAuditing) -match "Disabled" | Should -Not -Be $null
        }

        It "Audit Base Objects" {
            (auditpol /get /option:AuditBaseObjects) -match "Disabled" | Should -Not -Be $null
        }

        It "Audit Base Directories" {
            (auditpol /get /option:AuditBaseDirectories) -match "Disabled" | Should -Not -Be $null
        }
    }

    Context "Audit Policy Subcategories" {
        Write-Host "##[debug] STIG V-73443, V-73445"
        AuditPolicy "Logon/Logoff" "Account Lockout" {
            Should -Be "Success and Failure"
        }

        AuditPolicy "Object Access" "Application Generated" {
            Should -Be "Success and Failure"
        }

        AuditPolicy "Account Management" "Application Group Management" {
            Should -Be "Success and Failure"
        }

        Write-Host "##[debug] STIG V-73461, V-73463"
        AuditPolicy "Policy Change" "Audit Policy Change" {
            Should -Be "Success and Failure"
        }

        Write-Host "##[debug] STIG V-73465"
        AuditPolicy "Policy Change" "Authentication Policy Change" {
            Should -Be "Success and Failure"
        }

        Write-Host "##[debug] STIG V-73467"
        AuditPolicy "Policy Change" "Authorization Policy Change" {
            Should -Be "Success and Failure"
        }

        AuditPolicy "Object Access" "Central Policy Staging" {
            Should -Be "Success and Failure"
        }

        AuditPolicy "Object Access" "Certification Services" {
            Should -Be "Success and Failure"
        }

        Write-Host "##[debug] STIG V-73417"
        AuditPolicy "Account Management" "Computer Account Management" {
            Should -Be "Success and Failure"
        }

        Write-Host "##[debug] STIG V-73413, V-73415"
        AuditPolicy "Account Logon" "Credential Validation" {
            Should -Be "Success and Failure"
        }

        AuditPolicy "DS Access" "Detailed Directory Service Replication" {
            Should -Be "Success and Failure"
        }

        AuditPolicy "Object Access" "Detailed File Share" {
            Should -Be "Success and Failure"
        }

        Write-Host "##[debug] STIG V-73435, V-73437"
        AuditPolicy "DS Access" "Directory Service Access" {
            Should -Be "Success and Failure"
        }

        Write-Host "##[debug] STIG V-73439, V-73441"
        AuditPolicy "DS Access" "Directory Service Changes" {
            Should -Be "Success and Failure"
        }

        AuditPolicy "DS Access" "Directory Service Replication" {
            Should -Be "Success and Failure"
        }

        AuditPolicy "Account Management" "Distribution Group Management" {
            Should -Be "Success and Failure"
        }

        AuditPolicy "Detailed Tracking" "DPAPI Activity" {
            Should -Be "Success and Failure"
        }

        AuditPolicy "Object Access" "File Share" {
            Should -Be "Success and Failure"
        }

        AuditPolicy "Object Access" "File System" {
            Should -Be "Success and Failure"
        }

        AuditPolicy "Object Access" "Filtering Platform Connection" {
            Should -Be "Success and Failure"
        }

        AuditPolicy "Object Access" "Filtering Platform Packet Drop" {
            Should -Be "Success and Failure"
        }

        AuditPolicy "Policy Change" "Filtering Platform Policy Change" {
            Should -Be "Success and Failure"
        }

        Write-Host "##[debug] STIG V-73447"
        AuditPolicy "Logon/Logoff" "Group Membership" {
            Should -Be "Success and Failure"
        }

        AuditPolicy "Object Access" "Handle Manipulation" {
            Should -Be "Success and Failure"
        }

        Write-Host "##[debug] STIG V-73473, V-73475"
        AuditPolicy System "IPsec Driver" {
            Should -Be "Success and Failure"
        }

        AuditPolicy "Logon/Logoff" "IPsec Extended Mode" {
            Should -Be "Success and Failure"
        }

        AuditPolicy "Logon/Logoff" "IPsec Main Mode" {
            Should -Be "Success and Failure"
        }

        AuditPolicy "Logon/Logoff" "IPsec Quick Mode" {
            Should -Be "Success and Failure"
        }

        AuditPolicy "Account Logon" "Kerberos Authentication Service" {
            Should -Be "Success and Failure"
        }

        AuditPolicy "Account Logon" "Kerberos Service Ticket Operations" {
            Should -Be "Success and Failure"
        }

        AuditPolicy "Object Access" "Kernel Object" {
            Should -Be "Success and Failure"
        }

        Write-Host "##[debug] STIG V-73449"
        AuditPolicy "Logon/Logoff" "Logoff" {
            Should -Be "Success and Failure"
        }

        Write-Host "##[debug] STIG V-73451, V-73453"
        AuditPolicy "Logon/Logoff" "Logon" {
            Should -Be "Success and Failure"
        }

        AuditPolicy "Policy Change" "MPSSVC Rule-Level Policy Change" {
            Should -Be "Success and Failure"
        }

        AuditPolicy "Logon/Logoff" "Network Policy Server" {
            Should -Be "Success and Failure"
        }

        AuditPolicy "Privilege Use" "Non Sensitive Privilege Use" {
            Should -Be "Success and Failure"
        }

        AuditPolicy "Account Logon" "Other Account Logon Events" {
            Should -Be "Success and Failure"
        }

        Write-Host "##[debug] STIG V-73419"
        AuditPolicy "Account Management" "Other Account Management Events" {
            Should -Be "Success"
        }

        AuditPolicy "Logon/Logoff" "Other Logon/Logoff Events" {
            Should -Be "Success and Failure"
        }

        AuditPolicy "Object Access" "Other Object Access Events" {
            Should -Be "Success and Failure"
        }

        AuditPolicy "Policy Change" "Other Policy Change Events" {
            Should -Be "Success and Failure"
        }

        AuditPolicy "Privilege Use" "Other Privilege Use Events" {
            Should -Be "Success and Failure"
        }

        Write-Host "##[debug] STIG V-73477, V-73479"
        AuditPolicy System "Other System Events" {
            Should -Be "Success and Failure"
        }

        Write-Host "##[debug] STIG V-73431"
        AuditPolicy "Detailed Tracking" "Plug and Play Events" {
            Should -Be "Success and Failure"
        }

        Write-Host "##[debug] STIG V-73433"
        AuditPolicy "Detailed Tracking" "Process Creation" {
            Should -Be "Success and Failure"
        }

        AuditPolicy "Detailed Tracking" "Process Termination" {
            Should -Be "Success and Failure"
        }

        AuditPolicy "Object Access" "Registry" {
            Should -Be "Success and Failure"
        }

        Write-Host "##[debug] STIG V-73457, V-73459"
        AuditPolicy "Object Access" "Removable Storage" {
            Should -Be "Success and Failure"
        }

        AuditPolicy "Detailed Tracking" "RPC Events" {
            Should -Be "Success and Failure"
        }

        AuditPolicy "Object Access" "SAM" {
            Should -Be "Success and Failure"
        }

        Write-Host "##[debug] STIG V-73423"
        AuditPolicy "Account Management" "Security Group Management" {
            Should -Be "Success and Failure"
        }

        Write-Host "##[debug] STIG V-73481"
        AuditPolicy System "Security State Change" {
            Should -Be "Success and Failure"
        }

        Write-Host "##[debug] STIG V-73483"
        AuditPolicy System "Security System Extension" {
            Should -Be "Success"
        }

        Write-Host "##[debug] STIG V-73469, V-73471"
        AuditPolicy "Privilege Use" "Sensitive Privilege Use" {
            Should -Be "Success and Failure"
        }

        Write-Host "##[debug] STIG V-73455"
        AuditPolicy "Logon/Logoff" "Special Logon" {
            Should -Be "Success and Failure"
        }

        Write-Host "##[debug] STIG V-73489, V-73491"
        AuditPolicy System "System Integrity" {
            Should -Be "Success and Failure"
        }

        AuditPolicy "Detailed Tracking" "Token Right Adjusted Events" {
            Should -Be "Success and Failure"
        }

        AuditPolicy "Logon/Logoff" "User / Device Claims" {
            Should -Be "Success and Failure"
        }

        Write-Host "##[debug] STIG V-73427, V-73429"
        AuditPolicy "Account Management" "User Account Management" {
            Should -Be "Success and Failure"
        }
    }
}

Describe "Local Security Options" {

    Context "Local Account Status" {
        $localUsers = Get-CimInstance -Namespace "ROOT\cimv2" -ClassName "Win32_UserAccount"
        $admin = $localUsers | Where-Object { $_.Name -eq "$($AdminName)" }
        $guest = $localUsers | Where-Object { $_.Name -eq "$($GuestName)" }

        Write-Host "##[debug] STIG V-73623"
        It "Rename Administrator Account" {
            $admin.Name | Should -Be $AdminName
        }

        It "Administrator Account Status" {
            $admin.Disabled | Should -Be $false
        }

        It "Administrator Password Change Allowed" {
            $admin.PasswordChangeable | Should -Be $true
        }

        It "Administrator Password Required" {
            $admin.PasswordRequired | Should -Be $true
        }

        Write-Host "##[debug] STIG V-73625"
        It 'Rename Guest Account' {
            $guest.Name | Should -Be $GuestName
        }

        Write-Host "##[debug] STIG V-73809"
        It "Guest Account Status" {
            $guest.Disabled | Should -Be $true
        }

        It "Guest Password Change Not Allowed" {
            $guest.PasswordChangeable | Should -Be $false
        }
    }

    Context "Security Options" {
        SecurityOption 'Accounts: Block Microsoft accounts' {
            Should -Be 'Users cant add or log on with Microsoft accounts'
        }

        Write-Host "##[debug] STIG V-73621"
        SecurityOption 'Accounts: Limit local account use of blank passwords to console logon only' {
            Should -Be 'Enabled'
        }

        SecurityOption 'Audit: Audit the access of global system objects' {
            Should -Be 'Disabled'
        }

        SecurityOption 'Audit: Audit the use of Backup and Restore privilege' {
            Should -Be 'Disabled'
        }

        Write-Host "##[debug] STIG V-73627"
        SecurityOption 'Audit: Force audit policy subcategory settings Windows Vista or later to override audit policy category settings' {
            Should -Be 'Enabled'
        }

        SecurityOption 'Audit: Shut down system immediately if unable to log security audits' {
            Should -Be 'Disabled'
        }

        SecurityOption 'Devices: Allow undock without having to log on' {
            Should -Be 'Enabled'
        }

        SecurityOption 'Devices: Allowed to format and eject removable media' {
            Should -Be 'Administrators'
        }

        SecurityOption 'Devices: Prevent users from installing printer drivers' {
            Should -Be 'Enabled'
        }

        SecurityOption 'Devices: Restrict CD ROM access to locally logged on user only' {
            Should -Be 'Enabled'
        }

        SecurityOption 'Devices: Restrict floppy access to locally logged on user only' {
            Should -Be 'Enabled'
        }

        Write-Host "##[debug] STIG V-73633"
        SecurityOption 'Domain member: Digitally encrypt or sign secure channel data always' {
            Should -Be 'Enabled'
        }

        Write-Host "##[debug] STIG V-73635"
        SecurityOption 'Domain member: Digitally encrypt secure channel data when possible' {
            Should -Be 'Enabled'
        }

        Write-Host "##[debug] STIG V-73637"
        SecurityOption 'Domain member: Digitally sign secure channel data when possible' {
            Should -Be 'Enabled'
        }

        Write-Host "##[debug] STIG V-73639"
        SecurityOption 'Domain member: Disable machine account password changes' {
            Should -Be 'Disabled'
        }

        Write-Host "##[debug] STIG V-73641"
        SecurityOption 'Domain member: Maximum machine account password age' {
            Should -Be '30'
        }

        Write-Host "##[debug] STIG V-73643"
        SecurityOption 'Domain member: Require strong Windows 2000 or later session key' {
            Should -Be 'Enabled'
        }

        SecurityOption 'Interactive logon: Display user information when the session is locked' {
            Should -Be 'User display name only'
        }

        SecurityOption 'Interactive logon: Do not display last user name' {
            Should -Be 'Enabled'
        }

        SecurityOption 'Interactive logon: Do not require CTRL ALT DEL' {
            Should -Be 'Disabled'
        }

        SecurityOption 'Interactive logon: Machine account lockout threshold' {
            Should -Be '10'
        }

        Write-Host "##[debug] STIG V-73645"
        SecurityOption 'Interactive logon: Machine inactivity limit' {
            Should -Be '900'
        }

        Write-Host "##[debug] STIG V-73651"
        Registry 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' CachedLogonsCount {
            Should -Be '4'
        }

        SecurityOption 'Interactive logon: Prompt user to change password before expiration' {
            Should -Be '14'
        }

        SecurityOption 'Interactive logon: Require Domain Controller authentication to unlock workstation' {
            Should -Be 'Disabled'
        }

        SecurityOption 'Interactive logon: Require smart card' {
            Should -Be 'Disabled'
        }

        Write-Host "##[debug] STIG V-73807"
        SecurityOption 'Interactive logon: Smart card removal behavior' {
            Should -Be 'Lock Workstation'
        }

        Write-Host "##[debug] STIG V-73653"
        SecurityOption 'Microsoft network client: Digitally sign communications always' {
            Should -Be 'Enabled'
        }

        Write-Host "##[debug] STIG V-73655"
        SecurityOption 'Microsoft network client: Digitally sign communications if server agrees' {
            Should -Be 'Enabled'
        }

        Write-Host "##[debug] STIG V-73657"
        SecurityOption 'Microsoft network client: Send unencrypted password to third party SMB servers' {
            Should -Be 'Disabled'
        }

        Write-Host "##[debug] STIG V-73659"
        SecurityOption 'Microsoft network server: Amount of idle time required before suspending session' {
            Should -Be '15'
        }

        Write-Host "##[debug] STIG V-73661"
        SecurityOption 'Microsoft network server: Digitally sign communications always' {
            Should -Be 'Enabled'
        }

        Write-Host "##[debug] STIG V-73663"
        SecurityOption 'Microsoft network server: Digitally sign communications if client agrees' {
            Should -Be 'Enabled'
        }

        SecurityOption 'Microsoft network server: Disconnect clients when logon hours expire' {
            Should -Be 'Enabled'
        }

        SecurityOption 'Microsoft network server: Server SPN target name validation level' {
            Should -Be 'Off'
        }

        Write-Host "##[debug] STIG V-73665"
        SecurityOption 'Network access: Allow anonymous SID Name translation' {
            Should -Be 'Disabled'
        }

        Write-Host "##[debug] STIG V-73667"
        SecurityOption 'Network access: Do not allow anonymous enumeration of SAM accounts' {
            Should -Be 'Enabled'
        }

        Write-Host "##[debug] STIG V-73669"
        SecurityOption 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' {
            Should -Be 'Enabled'
        }

        Write-Host "##[debug] STIG V-73671"
        SecurityOption 'Network access: Do not allow storage of passwords and credentials for network authentication' {
            Should -Be 'Enabled'
        }

        Write-Host "##[debug] STIG V-73673"
        SecurityOption 'Network access: Let Everyone permissions apply to anonymous users' {
            Should -Be 'Disabled'
        }

        Write-Host "##[debug] STIG V-73675"
        SecurityOption 'Network access: Named Pipes that can be accessed anonymously' {
            Should -Be '7'
        }

        Write-Host "##[debug] STIG V-73675"
        SecurityOption 'Network access: Restrict anonymous access to Named Pipes and Shares' {
            Should -Be 'Enabled'
        }

        SecurityOption 'Network access: Sharing and security model for local accounts' {
            Should -Be 'Classic - Local users authenticate as themselves'
        }

        Write-Host "##[debug] STIG V-73679"
        SecurityOption 'Network security: Allow Local System to use computer identity for NTLM' {
            Should -Be 'Enabled'
        }

        Write-Host "##[debug] STIG V-73681"
        SecurityOption 'Network security: Allow LocalSystem NULL session fallback' {
            Should -Be 'Disabled'
        }

        Write-Host "##[debug] STIG V-73683"
        SecurityOption 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' {
            Should -Be 'Disabled'
        }

        Write-Host "##[debug] STIG V-73685"
        Registry 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' SupportedEncryptionTypes {
            Should -Be "2147483640"
        }

        Write-Host "##[debug] STIG V-73687"
        SecurityOption 'Network security: Do not store LAN Manager hash value on next password change' {
            Should -Be 'Enabled'
        }

        Write-Host "##[debug] STIG V-73689"
        SecurityOption 'Network security: Force logoff when logon hours expire' {
            Should -Be 'Enabled'
        }

        Write-Host "##[debug] STIG V-73691"
        SecurityOption 'Network security: LAN Manager authentication level' {
            Should -Be 'Send NTLMv2 responses only. Refuse LM & NTLM'
        }

        Write-Host "##[debug] STIG V-73693"
        SecurityOption 'Network security: LDAP client signing requirements' {
            Should -Be 'Negotiate Signing'
        }

        Write-Host "##[debug] STIG V-73695"
        SecurityOption 'Network security: Minimum session security for NTLM SSP based including secure RPC clients' {
            Should -Be 'Both options checked'
        }

        Write-Host "##[debug] STIG V-73697"
        SecurityOption 'Network security: Minimum session security for NTLM SSP based including secure RPC servers' {
            Should -Be 'Both options checked'
        }

        SecurityOption 'Recovery console: Allow automatic administrative logon' {
            Should -Be 'Disabled'
        }

        SecurityOption 'Recovery console: Allow floppy copy and access to all drives and folders' {
            Should -Be 'Disabled'
        }

        SecurityOption 'Shutdown: Allow system to be shut down without having to log on' {
            Should -Be 'Disabled'
        }

        SecurityOption 'Shutdown: Clear virtual memory pagefile' {
            Should -Be 'Disabled'
        }

        Write-Host "##[debug] STIG V-73699"
        SecurityOption 'System cryptography: Force strong key protection for user keys stored on the computer' {
            Should -Be 'User must enter a password each time they use a key'
        }

        Write-Host "##[debug] STIG V-73701"
        SecurityOption 'System cryptography: Use FIPS compliant algorithms for encryption hashing and signing' {
            Should -Be 'Enabled'
        }

        Write-Host "##[debug] STIG V-73703"
        SecurityOption 'System objects: Require case insensitivity for non Windows subsystems' {
            Should -Be 'Enabled'
        }

        Write-Host "##[debug] STIG V-73705"
        SecurityOption 'System objects: Strengthen default permissions of internal system objects eg Symbolic Links' {
            Should -Be 'Enabled'
        }

        SecurityOption 'System settings: Use Certificate Rules on Windows Executables for Software Restriction Policies' {
            Should -Be 'Disabled'
        }

        Write-Host "##[debug] STIG V-73707"
        SecurityOption 'User Account Control: Admin Approval Mode for the Built in Administrator account' {
            Should -Be 'Enabled'
        }

        Write-Host "##[debug] STIG V-73709"
        SecurityOption 'User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop' {
            Should -Be 'Disabled'
        }

        Write-Host "##[debug] STIG V-73711"
        SecurityOption 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' {
            Should -Be 'Prompt for consent on the secure desktop'
        }

        Write-Host "##[debug] STIG V-73713"
        SecurityOption 'User Account Control: Behavior of the elevation prompt for standard users' {
            Should -Be 'Automatically deny elevation request'
        }

        Write-Host "##[debug] STIG V-73715"
        SecurityOption 'User Account Control: Detect application installations and prompt for elevation' {
            Should -Be 'Enabled'
        }

        SecurityOption 'User Account Control: Only elevate executables that are signed and validated' {
            Should -Be 'Disabled'
        }

        Write-Host "##[debug] STIG V-73717"
        SecurityOption 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' {
            Should -Be 'Enabled'
        }

        Write-Host "##[debug] STIG V-73719"
        SecurityOption 'User Account Control: Run all administrators in Admin Approval Mode' {
            Should -Be 'Enabled'
        }

        SecurityOption 'User Account Control: Switch to the secure desktop when prompting for elevation' {
            Should -Be 'Enabled'
        }

        Write-Host "##[debug] STIG V-73721"
        SecurityOption 'User Account Control: Virtualize file and registry write failures to per user locations' {
            Should -Be 'Enabled'
        }
    }
}

Describe "Local Account Policies" {
    Write-Host "##[command] Exporting security policy for analysis."
    secedit /export /cfg c:\Temp\secpol.cfg
    $pol = Get-Content -Path "c:\Temp\secpol.cfg"

    Write-Host "##[debug] STIG V-73309"
    It "Account lockout duration" {
        $pol | Where-Object { $_ -like "LockoutDuration*" } | Should -Be "LockoutDuration = 15"
    }

    Write-Host "##[debug] STIG V-73311"
    It "Account lockout threshold" {
        $pol | Where-Object { $_ -like "LockoutBadCount*" } | Should -Be "LockoutBadCount = 3"
    }

    Write-Host "##[debug] STIG V-73313"
    It "Reset account lockout counter after" {
        $pol | Where-Object { $_ -like "LockoutDuration*" } | Should -Be "LockoutDuration = 15"
    }

    Write-Host "##[debug] STIG V-73315"
    It "Enforce password history" {
        $pol | Where-Object { $_ -like "PasswordHistorySize*" } | Should -Be "PasswordHistorySize = 24"
    }

    Write-Host "##[debug] STIG V-73317"
    It "Maximum Password Age" {
        $pol | Where-Object { $_ -like "MaximumPasswordAge*" } | Should -Be "MaximumPasswordAge = 60"
    }

    Write-Host "##[debug] STIG V-73319"
    It "Minimum Password Age" {
        $pol | Where-Object { $_ -like "MinimumPasswordAge*" } | Should -Be "MinimumPasswordAge = 1"
    }

    Write-Host "##[debug] STIG V-73321"
    It "Minimum Password Length" {
        $pol | Where-Object { $_ -like "MinimumPasswordLength*" } | Should -Be "MinimumPasswordLength = 14"
    }

    Write-Host "##[debug] STIG V-73323"
    It "Password must meet complexity requirements" {
        $pol | Where-Object { $_ -like "PasswordComplexity*" } | Should -Be "PasswordComplexity = 1"
    }

    Write-Host "##[debug] STIG V-73325"
    It "Store passwords using reversible encryption" {
        $pol | Where-Object { $_ -like "ClearTextPassword*" } | Should -Be "ClearTextPassword = 0"
    }

    Remove-Item -Path "c:\Temp\secpol.cfg" -Force
}

Describe "User Rights Assignment" {

    Write-Host "##[debug] STIG V-73729"
    UserRightsAssignment ByRight 'SeTrustedCredManAccessPrivilege' {
        Should -BeNullOrEmpty
    }

    Write-Host "##[debug] STIG V-73731, V-73733"
    UserRightsAssignment ByRight 'SeNetworkLogonRight' {
        Should -Be @('NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS', 'BUILTIN\Administrators', 'NT AUTHORITY\Authenticated Users')
    }

    Write-Host "##[debug] STIG V-73735"
    UserRightsAssignment ByRight 'SeTcbPrivilege' {
        Should -BeNullOrEmpty
    }

    Write-Host "##[debug] STIG V-73737"
    UserRightsAssignment ByRight 'SeMachineAccountPrivilege' {
        Should -Be 'BUILTIN\Administrators'
    }

    UserRightsAssignment ByRight 'SeIncreaseQuotaPrivilege' {
        Should -Be @('BUILTIN\Administrators', 'NT AUTHORITY\NETWORK SERVICE', 'NT AUTHORITY\LOCAL SERVICE')
    }

    Write-Host "##[debug] STIG V-73739"
    UserRightsAssignment ByRight 'SeInteractiveLogonRight' {
        Should -Be 'BUILTIN\Administrators'
    }

    Write-Host "##[debug] STIG V-73741"
    UserRightsAssignment ByRight 'SeRemoteInteractiveLogonRight' {
        Should -Be 'BUILTIN\Administrators'
    }

    Write-Host "##[debug] STIG V-73743"
    UserRightsAssignment ByRight 'SeBackupPrivilege' {
        Should -Be 'BUILTIN\Administrators'
    }

    UserRightsAssignment ByRight 'SeChangeNotifyPrivilege' {
        Should -Be @('BUILTIN\Administrators', 'NT AUTHORITY\NETWORK SERVICE', 'NT AUTHORITY\LOCAL SERVICE', 'NT AUTHORITY\Authenticated Users')
    }

    UserRightsAssignment ByRight 'SeSystemtimePrivilege' {
        Should -Be @('BUILTIN\Administrators', 'NT AUTHORITY\LOCAL SERVICE')
    }

    Write-Host "##[debug] STIG V-73745"
    UserRightsAssignment ByRight 'SeCreatePagefilePrivilege' {
        Should -Be 'BUILTIN\Administrators'
    }

    Write-Host "##[debug] STIG V-73747"
    UserRightsAssignment ByRight 'SeCreateTokenPrivilege' {
        Should -BeNullOrEmpty
    }

    Write-Host "##[debug] STIG V-73749"
    UserRightsAssignment ByRight 'SeCreateGlobalPrivilege' {
        Should -Be @('NT AUTHORITY\SERVICE', 'BUILTIN\Administrators', 'NT AUTHORITY\NETWORK SERVICE', 'NT AUTHORITY\LOCAL SERVICE')
    }

    Write-Host "##[debug] STIG V-73751"
    UserRightsAssignment ByRight 'SeCreatePermanentPrivilege' {
        Should -BeNullOrEmpty
    }

    Write-Host "##[debug] STIG V-73753"
    UserRightsAssignment ByRight 'SeCreateSymbolicLinkPrivilege' {
        Should -Be 'BUILTIN\Administrators'
    }

    Write-Host "##[debug] STIG V-73755"
    UserRightsAssignment ByRight 'SeDebugPrivilege' {
        Should -Be 'BUILTIN\Administrators'
    }

    UserRightsAssignment ByRight 'SeDenyNetworkLogonRight' {
        Should -Be 'BUILTIN\Guests'
    }

    UserRightsAssignment ByRight 'SeDenyBatchLogonRight' {
        Should -Be 'BUILTIN\Guests'
    }

    UserRightsAssignment ByRight 'SeDenyServiceLogonRight' {
        Should -Be 'BUILTIN\Guests'
    }

    UserRightsAssignment ByRight 'SeDenyInteractiveLogonRight' {
        Should -Be 'BUILTIN\Guests'
    }

    UserRightsAssignment ByRight 'SeDenyRemoteInteractiveLogonRight' {
        Should -Be 'BUILTIN\Guests'
    }

    Write-Host "##[debug] STIG V-73779"
    UserRightsAssignment ByRight 'SeEnableDelegationPrivilege' {
        Should -BeNullOrEmpty
    }

    Write-Host "##[debug] STIG V-73781"
    UserRightsAssignment ByRight 'SeRemoteShutdownPrivilege' {
        Should -Be 'BUILTIN\Administrators'
    }

    Write-Host "##[debug] STIG V-73783"
    UserRightsAssignment ByRight 'SeAuditPrivilege' {
        Should -Be @('NT AUTHORITY\NETWORK SERVICE', 'NT AUTHORITY\LOCAL SERVICE')
    }

    Write-Host "##[debug] STIG V-73785"
    UserRightsAssignment ByRight 'SeImpersonatePrivilege' {
        Should -Be @('NT AUTHORITY\SERVICE', 'BUILTIN\Administrators', 'NT AUTHORITY\NETWORK SERVICE', 'NT AUTHORITY\LOCAL SERVICE')
    }

    UserRightsAssignment ByRight 'SeIncreaseWorkingSetPrivilege' {
        Should -Be 'BUILTIN\Administrators'
    }

    Write-Host "##[debug] STIG V-73787"
    UserRightsAssignment ByRight 'SeIncreaseBasePriorityPrivilege' {
        Should -Be 'BUILTIN\Administrators'
    }

    Write-Host "##[debug] STIG V-73789"
    UserRightsAssignment ByRight 'SeLoadDriverPrivilege' {
        Should -Be 'BUILTIN\Administrators'
    }

    Write-Host "##[debug] STIG V-73791"
    UserRightsAssignment ByRight 'SeLockMemoryPrivilege' {
        Should -BeNullOrEmpty
    }

    UserRightsAssignment ByRight 'SeBatchLogonRight' {
        Should -Be 'BUILTIN\Administrators'
    }

    Write-Host "##[debug] STIG V-73793"
    UserRightsAssignment ByRight 'SeSecurityPrivilege' {
        Should -Be 'BUILTIN\Administrators'
    }

    UserRightsAssignment ByRight 'SeRelabelPrivilege' {
        Should -Be 'BUILTIN\Administrators'
    }

    Write-Host "##[debug] STIG V-73795"
    UserRightsAssignment ByRight 'SeSystemEnvironmentPrivilege' {
        Should -Be 'BUILTIN\Administrators'
    }

    Write-Host "##[debug] STIG V-73797"
    UserRightsAssignment ByRight 'SeManageVolumePrivilege' {
        Should -Be 'BUILTIN\Administrators'
    }

    Write-Host "##[debug] STIG V-73799"
    UserRightsAssignment ByRight 'SeProfileSingleProcessPrivilege' {
        Should -Be 'BUILTIN\Administrators'
    }

    UserRightsAssignment ByRight 'SeUndockPrivilege' {
        Should -Be 'BUILTIN\Administrators'
    }

    Write-Host "##[debug] STIG V-73801"
    UserRightsAssignment ByRight 'SeRestorePrivilege' {
        Should -Be 'BUILTIN\Administrators'
    }

    UserRightsAssignment ByRight 'SeShutdownPrivilege' {
        Should -Be 'BUILTIN\Administrators'
    }

    Write-Host "##[debug] STIG V-73803"
    UserRightsAssignment ByRight 'SeTakeOwnershipPrivilege' {
        Should -Be 'BUILTIN\Administrators'
    }
}

Describe "Other Windows Security Items" {

    Context "Device Guard Settings" {
        Write-Host "##[debug] STIG V-73513"
        It "Device Guard - Enable Virtualization Based Security" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard" -Name "EnableVirtualizationBasedSecurity").EnableVirtualizationBasedSecurity
            $obj | Should -Be "1"
        }

        Write-Host "##[debug] STIG V-73513"
        It "Device Guard - Require Platform Security Features" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard" -Name "RequirePlatformSecurityFeatures").RequirePlatformSecurityFeatures
            $obj | Should -Be "1"
        }

        Write-Host "##[debug] STIG V-73515"
        It "Device Guard - Lsa Cfg Flags" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard" -Name "LsaCfgFlags").LsaCfgFlags
            $obj | Should -Be "2"
        }

        Write-Host "##[debug] STIG V-73517"
        It "Device Guard - Hypervisor Enforced Code Integrity" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard" -Name "HypervisorEnforcedCodeIntegrity").HypervisorEnforcedCodeIntegrity
            $obj | Should -Be "2"
        }
    }

    Context "Windows Explorer Settings" {
        Write-Host "##[debug] STIG V-73547"
        It "Windows Explorer - No Auto Run" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutoRun").NoAutoRun
            $obj | Should -Be "1"
        }

        It "Windows Explorer - No Disconnect" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDisconnect").NoDisconnect
            $obj | Should -Be "1"
        }

        It "Windows Explorer - No Web Services" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoWebServices").NoWebServices
            $obj | Should -Be "1"
        }

        It "Windows Explorer - No Internet Open With" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoInternetOpenWith").NoInternetOpenWith
            $obj | Should -Be "1"
        }

        It "Windows Explorer - No Online Prints Wizard" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoOnlinePrintsWizard").NoOnlinePrintsWizard
            $obj | Should -Be "1"
        }

        It "Windows Explorer - No Publishing Wizard" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoPublishingWizard").NoPublishingWizard
            $obj | Should -Be "1"
        }

        Write-Host "##[debug] STIG V-73565"
        It "Windows Explorer - Pre XP SP2 Shell Protocol Behavior" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "PreXPSP2ShellProtocolBehavior").PreXPSP2ShellProtocolBehavior
            $obj | Should -Be "0"
        }

        Write-Host "##[debug] STIG V-73549"
        It "Windows Explorer - No Drive Type AutoRun" {
            $obj = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun").NoDriveTypeAutoRun
            $obj | Should -Be "255"
        }

        Write-Host "##[debug] STIG V-73545"
        It "Windows Explorer - No Autoplay for non-Volume" {
            $obj = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoAutoplayfornonVolume").NoAutoplayfornonVolume
            $obj | Should -Be "1"
        }

        Write-Host "##[debug] STIG V-73561"
        It "Windows Explorer - Enable Data Execution Prevention" {
            $obj = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoDataExecutionPrevention").NoDataExecutionPrevention
            $obj | Should -Be "0"
        }

        Write-Host "##[debug] STIG V-73563"
        It "Windows Explorer - Enable Heap Termination On Corruption" {
            $obj = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoHeapTerminationOnCorruption").NoHeapTerminationOnCorruption
            $obj | Should -Be "0"
        }
    }

    Context "WinRM & WinRS Settings" {
        It "WinRM - Allow Auto Config" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowAutoConfig").AllowAutoConfig
            $obj | Should -Be "1"
        }

        It "WinRM - IPv4 Filter" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service" -Name "IPv4Filter").IPv4Filter
            $obj | Should -Be "*"
        }

        It "WinRM - IPv6 Filter" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service" -Name "IPv6Filter").IPv6Filter
            $obj | Should -Be "*"
        }

        Write-Host "##[debug] STIG V-73597"
        It "WinRM - Client Do not Allow Digest" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowDigest").AllowDigest
            $obj | Should -Be "0"
        }

        Write-Host "##[debug] STIG V-73595"
        It "WinRM - Client Do not Allow Unencrypted Traffic" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowUnencryptedTraffic").AllowUnencryptedTraffic
            $obj | Should -Be "0"
        }

        Write-Host "##[debug] STIG V-73593"
        It "WinRM - Client Do not Allow Basic Authentication" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowBasic").AllowBasic
            $obj | Should -Be "0"
        }

        Write-Host "##[debug] STIG V-73603"
        It "WinRM - Service Disable Run As" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service" -Name "DisableRunAs").DisableRunAs
            $obj | Should -Be "1"
        }

        Write-Host "##[debug] STIG V-73599"
        It "WinRM - Service Do not Allow Basic Authentication" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowBasic").AllowBasic
            $obj | Should -Be "0"
        }

        Write-Host "##[debug] STIG V-73601"
        It "WinRM - Service Do not Allow Unencrypted Traffic" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowUnencryptedTraffic").AllowUnencryptedTraffic
            $obj | Should -Be "0"
        }

        It "Windows Remote Shell - Idle Timeout" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\WinRS" -Name "IdleTimeout").IdleTimeout
            $obj | Should -Be "900000"
        }

        It "Windows Remote Shell - Allow Remote Shell Access" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\WinRS" -Name "AllowRemoteShellAccess").AllowRemoteShellAccess
            $obj | Should -Be "1"
        }

        Write-Host "##[debug] STIG V-73541"
        It "RPC - Restrict Remote Clients" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Rpc" -Name "RestrictRemoteClients").RestrictRemoteClients
            $obj | Should -Be "1"
        }
    }

    Context "Windows Error Reporting" {
        It "Windows Error Reporting - Default Override Behavior" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting\Consent" -Name "DefaultOverrideBehavior").DefaultOverrideBehavior
            $obj | Should -Be "1"
        }

        It "Windows Error Reporting - Disable Archive" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting" -Name "DisableArchive").DisableArchive
            $obj | Should -Be "0"
        }

        It "Windows Error Reporting - Configure Archive" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting" -Name "ConfigureArchive").ConfigureArchive
            $obj | Should -Be "2"
        }

        It "Windows Error Reporting - Max Archive Count" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting" -Name "MaxArchiveCount").MaxArchiveCount
            $obj | Should -Be "100"
        }

        It "Windows Error Reporting - Disable Queue" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting" -Name "DisableQueue").DisableQueue
            $obj | Should -Be "0"
        }

        It "Windows Error Reporting - Force Queue" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting" -Name "ForceQueue").ForceQueue
            $obj | Should -Be "1"
        }

        It "Windows Error Reporting - Max Queue Count" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting" -Name "MaxQueueCount").MaxQueueCount
            $obj | Should -Be "50"
        }

        It "Windows Error Reporting - Max Queue Size" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting" -Name "MaxQueueSize").MaxQueueSize
            $obj | Should -Be "1024"
        }

        It "Windows Error Reporting - Min Free Disk Space" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting" -Name "MinFreeDiskSpace").MinFreeDiskSpace
            $obj | Should -Be "2800"
        }

        It "Windows Error Reporting - Queue Pester Interval" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting" -Name "QueuePesterInterval").QueuePesterInterval
            $obj | Should -Be "1"
        }

        It "Windows Error Reporting - Bypass Data Throttling" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting" -Name "BypassDataThrottling").BypassDataThrottling
            $obj | Should -Be "1"
        }

        It "Windows Error Reporting - Do not Disable" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting" -Name "Disabled").Disabled
            $obj | Should -Be "0"
        }

        It "Windows Error Reporting - Do not Show UI" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting" -Name "DontShowUI").DontShowUI
            $obj | Should -Be "1"
        }

        It "Windows Error Reporting - Corporate WER Server" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting" -Name "CorporateWerServer").CorporateWerServer
            $obj | Should -Be " "
        }

        It "Windows Error Reporting - Corporate WER Use SSL" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting" -Name "CorporateWerUseSSL").CorporateWerUseSSL
            $obj | Should -Be "1"
        }

        It "Windows Error Reporting - Corporate WER Port Number" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting" -Name "CorporateWerPortNumber").CorporateWerPortNumber
            $obj | Should -Be "1273"
        }

        It "Windows Error Reporting - Logging Disabled" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting" -Name "LoggingDisabled").LoggingDisabled
            $obj | Should -Be "0"
        }

        It "Windows Error Reporting - Do not Send Additional Data" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting" -Name "DontSendAdditionalData").DontSendAdditionalData
            $obj | Should -Be "1"
        }
    }

    Context "General Settings" {
        It "Disable Windows Consumer Features" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures").DisableWindowsConsumerFeatures
            $obj | Should -Be "1"
        }

        It "Customer Experience Improvement Program" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Messenger\Client" -Name "CEIP").CEIP
            $obj | Should -Be "2"
        }

        It "Search - Disable Content File Updates" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\SearchCompanion" -Name "DisableContentFileUpdates").DisableContentFileUpdates
            $obj | Should -Be "1"
        }

        It "Disable Customer Experience Improvement Program" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable").CEIPEnable
            $obj | Should -Be "0"
        }

        Write-Host "##[debug] STIG V-73529"
        It "Disable HTTP Printing" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -Name "DisableHTTPPrinting").DisableHTTPPrinting
            $obj | Should -Be "1"
        }

        Write-Host "##[debug] STIG V-73527"
        It "Disable Web PnP Download" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -Name "DisableWebPnPDownload").DisableWebPnPDownload
            $obj | Should -Be "1"
        }

        Write-Host "##[debug] STIG V-73587"
        It "Windows Installer - Safe For Scripting" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -Name "SafeForScripting").SafeForScripting
            $obj | Should -Be "0"
        }

        Write-Host "##[debug] STIG V-73583"
        It "Windows Installer - Enable User Control" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -Name "EnableUserControl").EnableUserControl
            $obj | Should -Be "0"
        }

        It "Windows Mail - Disable Communities" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Mail" -Name "DisableCommunities").DisableCommunities
            $obj | Should -Be "1"
        }

        It "Windows Mail - Manual Launch Allowed" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Mail" -Name "ManualLaunchAllowed").ManualLaunchAllowed
            $obj | Should -Be "0"
        }

        It "Windows Messenger - Prevent Run" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Messenger\Client" -Name "PreventRun").PreventRun
            $obj | Should -Be "1"
        }

        It "Windows Messenger - Prevent AutoRun" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Messenger\Client" -Name "PreventAutoRun").PreventAutoRun
            $obj | Should -Be "1"
        }

        It "Set Active Power Scheme" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Power\PowerSettings" -Name "ActivePowerScheme").ActivePowerScheme
            $obj | Should -Be "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
        }

        Write-Host "##[debug] STIG V-73511"
        It "ProcessCreationIncludeCmdLine_Enabled" {
            $obj = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled").ProcessCreationIncludeCmdLine_Enabled
            $obj | Should -Be "1"
        }

        It "Disable 8dot3 File Name Creation" {
            $obj = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "NtfsDisable8dot3NameCreation").NtfsDisable8dot3NameCreation
            $obj | Should -Be "1"
        }

        It "SafeDllSearchMode" {
            $obj = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "SafeDllSearchMode").SafeDllSearchMode
            $obj | Should -Be "1"
        }

        It "Screen Saver Grace Period" {
            $obj = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "ScreenSaverGracePeriod").ScreenSaverGracePeriod
            $obj | Should -Be "5"
        }

        It "Windows Store - Remove Access to Windows Store" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsStore" -Name "RemoveWindowsStore").RemoveWindowsStore
            $obj | Should -Be "1"
        }

        It "Windows Store - Disable OS Upgrade via Windows Store" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsStore" -Name "DisableOSUpgrade").DisableOSUpgrade
            $obj | Should -Be "1"
        }

        It "Windows Store - Disable Windows Store Apps" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsStore" -Name "DisableStoreApps").DisableStoreApps
            $obj | Should -Be "1"
        }

        Write-Host "##[debug] STIG V-73537"
        It "DC Setting - Prompt for Password on Resume" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" -Name "DCSettingIndex").DCSettingIndex
            $obj | Should -Be "1"
        }

        It "DC Setting - Idle Timeout" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Power\PowerSettings\3C0BC021-C8A8-4E07-A973-6B14CBCB2B7E" -Name "DCSettingIndex").DCSettingIndex
            $obj | Should -Be "1200"
        }

        Write-Host "##[debug] STIG V-73539"
        It "AC Setting - Prompt for Password on Resume" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" -Name "ACSettingIndex").ACSettingIndex
            $obj | Should -Be "1"
        }

        It "AC Setting - Idle Timeout" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Power\PowerSettings\3C0BC021-C8A8-4E07-A973-6B14CBCB2B7E" -Name "ACSettingIndex").ACSettingIndex
            $obj | Should -Be "1200"
        }

        It "Do Not Open Server Manager At Logon" {
            $obj = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Server\ServerManager" -Name "DoNotOpenAtLogon").DoNotOpenAtLogon
            $obj | Should -Be "1"
        }

        It "System Certificates - Disable Root Auto Update" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\SystemCertificates\AuthRoot" -Name "DisableRootAutoUpdate").DisableRootAutoUpdate
            $obj | Should -Be "1"
        }

        It "App Compatibility - Disable Engine" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\AppCompat" -Name "DisableEngine").DisableEngine
            $obj | Should -Be "1"
        }

        It "App Compatibility - Disable PcaUI" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\AppCompat" -Name "DisablePcaUI").DisablePcaUI
            $obj | Should -Be "0"
        }

        Write-Host "##[debug] STIG V-73543"
        It "App Compatibility - Disable Inventory" {
            $obj = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory").DisableInventory
            $obj | Should -Be "1"
        }

        It "AppX - Allow All Trusted Apps" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Appx" -Name "AllowAllTrustedApps").AllowAllTrustedApps
            $obj | Should -Be "1"
        }

        It "Prevent Device Metadata From Network" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork").PreventDeviceMetadataFromNetwork
            $obj | Should -Be "1"
        }

        It "Windows Error Reporting - Disable Send Generic Driver Not Found" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Settings" -Name "DisableSendGenericDriverNotFoundToWER").DisableSendGenericDriverNotFoundToWER
            $obj | Should -Be "1"
        }

        It "Windows Error Reporting - Disable Send Request Additional Software" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Settings" -Name "DisableSendRequestAdditionalSoftwareToWER").DisableSendRequestAdditionalSoftwareToWER
            $obj | Should -Be "1"
        }

        It "Windows Device Installation - Do not allow Remote RPC" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Settings" -Name "AllowRemoteRPC").AllowRemoteRPC
            $obj | Should -Be "0"
        }

        It "Windows Device Installation - Disable System Restore" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Settings" -Name "DisableSystemRestore").DisableSystemRestore
            $obj | Should -Be "0"
        }

        It "Windows Device Installation - Do not Search Windows Update for drivers" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchWindowsUpdate").DontSearchWindowsUpdate
            $obj | Should -Be "1"
        }

        It "Windows Device Installation - Do not Prompt For Windows Update" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DriverSearching" -Name "DontPromptForWindowsUpdate").DontPromptForWindowsUpdate
            $obj | Should -Be "1"
        }

        It "Windows Device Installation - Server Selection" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DriverSearching" -Name "DriverServerSelection").DriverServerSelection
            $obj | Should -Be "1"
        }

        It "Windows Update - Do Not Connect To Windows Update Internet Locations" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name "DoNotConnectToWindowsUpdateInternetLocations").DoNotConnectToWindowsUpdateInternetLocations
            $obj | Should -Be "1"
        }

        It "Windows Update - Do not Elevate Non Admins" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name "ElevateNonAdmins").ElevateNonAdmins
            $obj | Should -Be "0"
        }

        It "Group Policy - No Background Policy Refresh" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -Name "NoBackgroundPolicy").NoBackgroundPolicy
            $obj | Should -Be "0"
        }

        It "Group Policy - Enable User Policy Mode" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "UserPolicyMode").UserPolicyMode
            $obj | Should -Be "1"
        }

        Write-Host "##[debug] STIG V-73525"
        It "Group Policy - Always Process Group Policy Objects" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -Name "NoGPOListChanges").NoGPOListChanges
            $obj | Should -Be "0"
        }

        It "Tablet Settings - Disable Touch Input" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\TabletPC" -Name "TurnOffTouchInput").TurnOffTouchInput
            $obj | Should -Be "1"
        }

        Write-Host "##[debug] STIG V-73585"
        It "Windows Installer - Always Install Elevated" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated").AlwaysInstallElevated
            $obj | Should -Be "0"
        }

        It "Windows Installer - Disable LUA Patching" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -Name "DisableLUAPatching").DisableLUAPatching
            $obj | Should -Be "1"
        }

        It "Location and Sensors - Disable Location" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation").DisableLocation
            $obj | Should -Be "1"
        }

        It "Disable Registration Wizard" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Registration Wizard Control" -Name "NoRegistration").NoRegistration
            $obj | Should -Be "1"
        }

        It "Scripted Diagnostics Provider - Enable Query Remote Server" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" -Name "EnableQueryRemoteServer").EnableQueryRemoteServer
            $obj | Should -Be "0"
        }

        It "Scripted Diagnostics Provider - Disable Query Remote Server" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" -Name "DisableQueryRemoteServer").DisableQueryRemoteServer
            $obj | Should -Be "0"
        }

        Write-Host "##[debug] STIG V-73531"
        It "Lock Screen - Do not Display Network Selection UI" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI").DontDisplayNetworkSelectionUI
            $obj | Should -Be "1"
        }

        It "Lock Screen - Disable Lock Screen App Notifications" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "DisableLockScreenAppNotifications").DisableLockScreenAppNotifications
            $obj | Should -Be "1"
        }

        It "Lock Screen - Disable Camera" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenCamera").NoLockScreenCamera
            $obj | Should -Be "1"
        }

        Write-Host "##[debug] STIG V-73493"
        It "Lock Screen - Disable Slideshow" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenSlideshow").NoLockScreenSlideshow
            $obj | Should -Be "1"
        }

        Write-Host "##[debug] STIG V-73533"
        It "Do not Enumerate Local Users" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "EnumerateLocalUsers").EnumerateLocalUsers
            $obj | Should -Be "0"
        }

        Write-Host "##[debug] STIG V-73559"
        It "Enable Smart Screen" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen").EnableSmartScreen
            $obj | Should -Be "1"
        }

        Write-Host "##[debug] STIG V-73581"
        It "Windows Search - Do not Allow Indexing Encrypted Stores or Items" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Search" -Name "AllowIndexingEncryptedStoresOrItems").AllowIndexingEncryptedStoresOrItems
            $obj | Should -Be "0"
        }

        Write-Host "##[debug] STIG V-73727"
        It "File Attachments - Save Zone Information" {
            $obj = Test-Path -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments"
            $obj | Should -Be $false
        }

        It "Maps - Do not Auto Download Map Data" {
            $obj = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps" -Name "AutoDownloadAndUpdateMapData").AutoDownloadAndUpdateMapData
            $obj | Should -Be "0"
        }

        Write-Host "##[debug] STIG V-73551"
        It "Windows Telemetry - Set to Basic" {
            $obj = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry").AllowTelemetry
            $obj | Should -Be "1"
        }

        Write-Host "##[debug] STIG V-73589"
        It "Disable Automatic Restart Sign On" {
            $obj = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableAutomaticRestartSignOn").DisableAutomaticRestartSignOn
            $obj | Should -Be "1"
        }

        Write-Host "##[debug] STIG V-73591"
        It "PowerShell - Enable Script Block Logging" {
            $obj = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging").EnableScriptBlockLogging
            $obj | Should -Be "1"
        }

        It "PowerShell - Enable Script Block Invocation Logging" {
            $obj = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockInvocationLogging").EnableScriptBlockInvocationLogging
            $obj | Should -Be "1"
        }

        Write-Host "##[debug] STIG V-73521"
        It "Prevent Boot Drivers Identified as Bad" {
            $obj = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" -Name "DriverLoadPolicy").DriverLoadPolicy
            $obj | Should -Be "3"
        }

        It "Disable Using Current Working Dir for Dll Search" {
            $obj = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SessionManager" -Name "CWDIllegalInDllSearch").CWDIllegalInDllSearch
            $obj | Should -Be "1"
        }
    }
}

Describe "SCHANNEL/Crypto and Authentication" {
    Context "Authentication" {
        It "Microsoft Virtual System Migration Service - Allow Default Credentials" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowDefaultCredentials" -Name "1").1
            $obj | Should -Be "Microsoft Virtual System Migration Service/*"
        }

        It "Microsoft Virtual System Migration Service - Allow Default Credentials When NTLMOnly" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowDefCredentialsWhenNTLMOnly" -Name "2").2
            $obj | Should -Be "Microsoft Virtual System Migration Service/*"
        }

        It "Microsoft Virtual Console Service - Allow Default Credentials" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowDefaultCredentials" -Name "2").2
            $obj | Should -Be "Microsoft Virtual Console Service/*"
        }

        It "Microsoft Virtual Console Service - Allow Default Credentials When NTLMOnly" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowDefCredentialsWhenNTLMOnly" -Name "1").1
            $obj | Should -Be "Microsoft Virtual Console Service/*"
        }

        It "Credentials Delegation - Allow Default Credentials" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation" -Name "AllowDefaultCredentials").AllowDefaultCredentials
            $obj | Should -Be "1"
        }

        It "Credentials Delegation - Concatenate Defaults-Allow Default" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation" -Name "ConcatenateDefaults_AllowDefault").ConcatenateDefaults_AllowDefault
            $obj | Should -Be "1"
        }

        It "Credentials Delegation - Allow Default Credentials When NTLMOnly" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation" -Name "AllowDefCredentialsWhenNTLMOnly").AllowDefCredentialsWhenNTLMOnly
            $obj | Should -Be "1"
        }

        It "Credentials Delegation - Concatenate Defaults-Allow Default NTLM Only" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation" -Name "ConcatenateDefaults_AllowDefNTLMOnly").ConcatenateDefaults_AllowDefNTLMOnly
            $obj | Should -Be "1"
        }

        It "SmartCard - Enable Plug & Play" {
            $obj = (Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\ScPnP -Name "EnableScPnP").EnableScPnP
            $obj | Should -Be "1"
        }

        It "SmartCard - Enable Plug & Play Notifications" {
            $obj = (Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\ScPnP -Name "ScPnPNotification").ScPnPNotification
            $obj | Should -Be "0"
        }

        Write-Host "##[debug] STIG V-73497"
        It "Disable WDigest Authentication" {
            $obj = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest" -Name "UseLogonCredential").UseLogonCredential
            $obj | Should -Be "0"
        }

        Write-Host "##[debug] STIG V-73507"
        It "Windows Authentication - Do not Allow Insecure Guest Authentication" {
            $obj = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" -Name "AllowInsecureGuestAuth").AllowInsecureGuestAuth
            $obj | Should -Be "0"
        }

        Write-Host "##[debug] STIG V-73487"
        It "Credentials UI - Do not Enumerate Administrators" {
            $obj = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" -Name "EnumerateAdministrators").EnumerateAdministrators
            $obj | Should -Be "0"
        }

        Write-Host "##[debug] STIG V-73495"
        It "Local Account Token Filter Policy" {
            $obj = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy").LocalAccountTokenFilterPolicy
            $obj | Should -Be "0"
        }

        It "Auto Admin Logon" {
            $obj = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon").AutoAdminLogon
            $obj | Should -Be "0"
        }

        It "Disable Biometrics" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Biometrics" -Name "Enabled").Enabled
            $obj | Should -Be "0"
        }

        It "Block User Input Methods For SignIn" {
            $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Control Panel\International" -Name "BlockUserInputMethodsForSignIn").BlockUserInputMethodsForSignIn
            $obj | Should -Be "1"
        }
    }
    Context "SCHANNEL & Ciphers" {
        It "SCHANNEL Ciphers - Disable AES 128/128" {
            $obj = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128" -Name "Enabled").Enabled
            $obj | Should -Be  "0"
        }

        It "SCHANNEL Ciphers - Disable DES 168/168" {
            $obj = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 168/168" -Name "Enabled").Enabled
            $obj | Should -Be  "0"
        }

        It "SCHANNEL Ciphers - Disable DES 56/56" {
            $obj = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56" -Name "Enabled").Enabled
            $obj | Should -Be  "0"
        }

        It "SCHANNEL Ciphers - Disable RC2 128/128" {
            $obj = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128" -Name "Enabled").Enabled
            $obj | Should -Be  "0"
        }

        It "SCHANNEL Ciphers - Disable RC2 40/128" {
            $obj = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128" -Name "Enabled").Enabled
            $obj | Should -Be  "0"
        }

        It "SCHANNEL Ciphers - Disable RC2 56/128" {
            $obj = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128" -Name "Enabled").Enabled
            $obj | Should -Be  "0"
        }

        It "SCHANNEL Ciphers - Disable RC4 128/128" {
            $obj = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128" -Name "Enabled").Enabled
            $obj | Should -Be  "0"
        }

        It "SCHANNEL Ciphers - Disable RC4 40/128" {
            $obj = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128" -Name "Enabled").Enabled
            $obj | Should -Be  "0"
        }

        It "SCHANNEL Ciphers - Disable RC4 56/128" {
            $obj = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128" -Name "Enabled").Enabled
            $obj | Should -Be  "0"
        }

        It "SCHANNEL Ciphers - Disable RC4 64/128" {
            $obj = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128" -Name "Enabled").Enabled
            $obj | Should -Be  "0"
        }

        It "SCHANNEL Ciphers - Disable Triple DES 168/168" {
            $obj = Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168/168"
            $obj | Should -Be  $false
        }

        It "SCHANNEL Protocols - Set SSL 2.0 Client-DisabledByDefault On" {
            $obj = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -Name "DisabledByDefault").DisabledByDefault
            $obj | Should -Be  "1"
        }

        It "SCHANNEL Protocols - Set SSL 2.0 Server-DisabledByDefault On" {
            $obj = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Name "DisabledByDefault").DisabledByDefault
            $obj | Should -Be  "1"
        }

        It "SCHANNEL Protocols - Disable SSL 2.0 Client" {
            $obj = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -Name "Enabled").Enabled
            $obj | Should -Be  "0"
        }

        It "SCHANNEL Protocols - Disable SSL 2.0 Server" {
            $obj = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Name "Enabled").Enabled
            $obj | Should -Be  "0"
        }

        It "SCHANNEL Protocols - Set SSL 3.0 Client-DisabledByDefault On" {
            $obj = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -Name "DisabledByDefault").DisabledByDefault
            $obj | Should -Be  "1"
        }

        It "SCHANNEL Protocols - Set SSL 3.0 Server-DisabledByDefault On" {
            $obj = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Name "DisabledByDefault").DisabledByDefault
            $obj | Should -Be  "1"
        }

        It "SCHANNEL Protocols - Disable SSL 3.0 Client" {
            $obj = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -Name "Enabled").Enabled
            $obj | Should -Be  "0"
        }

        It "SCHANNEL Protocols - Disable SSL 3.0 Server" {
            $obj = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Name "Enabled").Enabled
            $obj | Should -Be  "0"
        }

        It "SCHANNEL Protocols - Set TLS 1.0 Client-DisabledByDefault On" {
            $obj = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Name "DisabledByDefault").DisabledByDefault
            $obj | Should -Be  "1"
        }

        It "SCHANNEL Protocols - Set TLS 1.0 Server-DisabledByDefault On" {
            $obj = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "DisabledByDefault").DisabledByDefault
            $obj | Should -Be  "1"
        }

        It "SCHANNEL Protocols - Disable TLS 1.0 Client" {
            $obj = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Name "Enabled").Enabled
            $obj | Should -Be  "0"
        }

        It "SCHANNEL Protocols - Disable TLS 1.0 Server" {
            $obj = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "Enabled").Enabled
            $obj | Should -Be  "0"
        }

        It "SCHANNEL Protocols - Set TLS 1.1 Client-DisabledByDefault Off" {
            $obj = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Name "DisabledByDefault").DisabledByDefault
            $obj | Should -Be  "0"
        }

        It "SCHANNEL Protocols - Set TLS 1.1 Server-DisabledByDefault Off" {
            $obj = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name "DisabledByDefault").DisabledByDefault
            $obj | Should -Be  "0"
        }

        It "SCHANNEL Protocols - Enable TLS 1.1 Client" {
            $obj = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Name "Enabled").Enabled
            $obj | Should -Be  "1"
        }

        It "SCHANNEL Protocols - Enable TLS 1.1 Server" {
            $obj = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name "Enabled").Enabled
            $obj | Should -Be  "1"
        }

        It "SCHANNEL Protocols - Set TLS 1.2 Client-DisabledByDefault Off" {
            $obj = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name "DisabledByDefault").DisabledByDefault
            $obj | Should -Be  "0"
        }

        It "SCHANNEL Protocols - Set TLS 1.2 Server-DisabledByDefault Off" {
            $obj = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "DisabledByDefault").DisabledByDefault
            $obj | Should -Be  "0"
        }

        It "SCHANNEL Protocols - TLS 1.2 Client-Enabled" {
            $obj = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name "Enabled").Enabled
            $obj | Should -Be  "1"
        }

        It "SCHANNEL Protocols - TLS 1.2 Server-Enabled" {
            $obj = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "Enabled").Enabled
            $obj | Should -Be  "1"
        }

        It "SCHANNEL Hashes - Disable MD5" {
            $obj = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5" -Name "Enabled").Enabled
            $obj | Should -Be  "0"
        }

        It "SCHANNEL Hashes - Disable SHA" {
            $obj = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA" -Name "Enabled").Enabled
            $obj | Should -Be  "0"
        }
    }
}

Describe "Remote Desktop (RDP) Settings" {
    It "RDP - Disable Client COM Port Mapping" {
        $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableCcm").fDisableCcm
        $obj | Should -Be "1"
    }

    Write-Host "##[debug] STIG V-73569"
    It "RDP - Disable Client Drive Mapping" {
        $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableCdm").fDisableCdm
        $obj | Should -Be "1"
    }

    It "RDP - Logging Enabled" {
        $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "LoggingEnabled").LoggingEnabled
        $obj | Should -Be "1"
    }

    Write-Host "##[debug] STIG V-73571"
    It "RDP - Always Prompt for Password" {
        $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "fPromptForPassword").fPromptForPassword
        $obj | Should -Be "1"
    }

    Write-Host "##[debug] STIG V-73575"
    It "RDP - Minimum Encryption Level" {
        $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "MinEncryptionLevel").MinEncryptionLevel
        $obj | Should -Be "3"
    }

    It "RDP - Per Session Temp Dir" {
        $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "PerSessionTempDir").PerSessionTempDir
        $obj | Should -Be "1"
    }

    It "RDP - Delete Temp Dirs On Exit" {
        $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "DeleteTempDirsOnExit").DeleteTempDirsOnExit
        $obj | Should -Be "1"
    }

    Write-Host "##[debug] STIG V-73573"
    It "RDP - Encrypt RPC Traffic" {
        $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "fEncryptRPCTraffic").fEncryptRPCTraffic
        $obj | Should -Be "1"
    }

    It "RDP - Enable Smart Cards" {
        $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "fEnableSmartCard").fEnableSmartCard
        $obj | Should -Be "1"
    }

    It "RDP - Max Ticket Expiry Units" {
        $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "MaxTicketExpiryUnits").MaxTicketExpiryUnits
        $obj | Should -Be " "
    }

    It "RDP - Max Ticket Expiry" {
        $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "MaxTicketExpiry").MaxTicketExpiry
        $obj | Should -Be " "
    }

    It "RDP - Licensing Mode" {
        $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "LicensingMode").LicensingMode
        $obj | Should -Be "2"
    }

    It "RDP - Disable Auto Reconnect" {
        $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableAutoReconnect").fDisableAutoReconnect
        $obj | Should -Be "0"
    }

    It "RDP - Enable Keep Alive" {
        $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "KeepAliveEnable").KeepAliveEnable
        $obj | Should -Be "1"
    }

    It "RDP - Keep Alive Interval" {
        $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "KeepAliveInterval").KeepAliveInterval
        $obj | Should -Be "3"
    }

    It "RDP - Disable Select Network Detect" {
        $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "SelectNetworkDetect").SelectNetworkDetect
        $obj | Should -Be "0"
    }

    It "RDP - Max Disconnection Time" {
        $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "MaxDisconnectionTime").MaxDisconnectionTime
        $obj | Should -Be "86400000"
    }

    It "RDP - Max Idle Time" {
        $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "MaxIdleTime").MaxIdleTime
        $obj | Should -Be "86400000"
    }

    It "RDP - Max Connection Time" {
        $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "MaxConnectionTime").MaxConnectionTime
        $obj | Should -Be "172800000"
    }

    It "RDP - Reset Broken Session" {
        $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "fResetBroken").fResetBroken
        $obj | Should -Be "1"
    }

    It "RDP - Security Layer" {
        $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "SecurityLayer").SecurityLayer
        $obj | Should -Be "2"
    }

    It "RDP - Disable Solicited Remote Assistance" {
        $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "fUseMailto").fUseMailto
        $obj | Should -Be " "
    }

    It "RDP - User Authentication" {
        $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "UserAuthentication").UserAuthentication
        $obj | Should -Be "1"
    }

    It "RDP - Do not Deny TS Connections" {
        $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDenyTSConnections").fDenyTSConnections
        $obj | Should -Be "0"
    }

    Write-Host "##[debug] STIG V-73567"
    It "RDP - Disable Password Saving" {
        $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "DisablePasswordSaving").DisablePasswordSaving
        $obj | Should -Be "1"
    }

    It "RDP - Disable Unsolicited Remote Assistance" {
        $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowUnsolicited").fAllowUnsolicited
        $obj | Should -Be "0"
    }

    It "RDP - Allow Full Control" {
        $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowFullControl").fAllowFullControl
        $obj | Should -Be " "
    }

    It "RDP - Disable Remote Assistance Requests" {
        $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowToGetHelp").fAllowToGetHelp
        $obj | Should -Be "0"
    }

    It "RDP - Allow a Single Session Per User" {
        $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "fSingleSessionPerUser").fSingleSessionPerUser
        $obj | Should -Be "1"
    }

    It "RDP - Disable LPT Printing" {
        $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableLPT").fDisableLPT
        $obj | Should -Be "1"
    }

    It "RDP - Disable PnP Redir" {
        $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisablePNPRedir").fDisablePNPRedir
        $obj | Should -Be "1"
    }

    It "RDP - Redirect Only Default Client Printer" {
        $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "RedirectOnlyDefaultClientPrinter").RedirectOnlyDefaultClientPrinter
        $obj | Should -Be "1"
    }
}

Describe "Networking" {

    It "Jumbo Packets should -Be Enabled" {
        $obj = Get-NetAdapterAdvancedProperty -RegistryKeyword "*JumboPacket"
        $obj.RegistryValue | Should -Be "9014"
    }

    It "TCPIP - Keep Alive Time" {
        $obj = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters" -Name "KeepAliveTime").KeepAliveTime
        $obj | Should -Be "300000"
    }

    Write-Host "##[debug] STIG V-73501"
    It "TCPIP - Disable IP Source Routing" {
        $obj = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters" -Name "DisableIPSourceRouting").DisableIPSourceRouting
        $obj | Should -Be "2"
    }

    Write-Host "##[debug] STIG V-73499"
    It "TCPIP - Disable IP Source Routing v6" {
        $obj = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisableIPSourceRouting").DisableIPSourceRouting
        $obj | Should -Be "2"
    }

    It "TCPIP - Enable Dead Gateway Detect" {
        $obj = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnableDeadGWDetect").EnableDeadGWDetect
        $obj | Should -Be "0"
    }

    Write-Host "##[debug] STIG V-73503"
    It "TCPIP - Enable ICMP Redirect" {
        $obj = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnableICMPRedirect").EnableICMPRedirect
        $obj | Should -Be "0"
    }

    Write-Host "##[debug] STIG V-73505"
    It "NetBIOS - No Name Release On Demand" {
        $obj = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netbt\Parameters" -Name "NoNameReleaseOnDemand").NoNameReleaseOnDemand
        $obj | Should -Be "1"
    }

    It "TCPIP - Enable IP Autoconfiguration Limits" {
        $obj = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnableIPAutoConfigurationLimits").EnableIPAutoConfigurationLimits
        $obj | Should -Be "1"
    }

    It "TCPIP - Perform Router Discovery" {
        $obj = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters" -Name "PerformRouterDiscovery").PerformRouterDiscovery
        $obj | Should -Be "0"
    }

    It "TCPIP - Syn Attack Protect" {
        $obj = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters" -Name "SynAttackProtect").SynAttackProtect
        $obj | Should -Be "1"
    }

    It "TCPIP - Tcp Max Data Retransmissions" {
        $obj = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters" -Name "TcpMaxDataRetransmissions").TcpMaxDataRetransmissions
        $obj | Should -Be "3"
    }

    It "Link Layer Topology Discovery - Disable LLTDIO" {
        $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\LLTD" -Name "EnableLLTDIO").EnableLLTDIO
        $obj | Should -Be "0"
    }

    It "Link Layer Topology Discovery - Disable Responder" {
        $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\LLTD" -Name "EnableRspndr").EnableRspndr
        $obj | Should -Be "0"
    }

    It "Disable Network Bridging" {
        $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Network Connections" -Name "NC_AllowNetBridge_NLA").NC_AllowNetBridge_NLA
        $obj | Should -Be "0"
    }

    It "Require domain users to elevate when setting a networks location" {
        $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Network Connections" -Name "NC_StdDomainUserSetLocation").NC_StdDomainUserSetLocation
        $obj | Should -Be "1"
    }

    It "Windows Connect Now - Disable Registrars" {
        $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WCN\Registrars" -Name "EnableRegistrars").EnableRegistrars
        $obj | Should -Be "0"
    }

    It "Windows Connect Now - Disable WCN UI" {
        $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WCN\UI" -Name "DisableWcnUi").DisableWcnUi
        $obj | Should -Be "1"
    }

    It "Internet Connection Wizard" {
        $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Internet Connection Wizard" -Name "ExitOnMSICW").ExitOnMSICW
        $obj | Should -Be "1"
    }

    It "IPv6 - Enable Forced Tunneling" {
        $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\TCPIP\v6Transition" -Name "Force_Tunneling").Force_Tunneling
        $obj | Should -Be "Enabled"
    }

    It "IPv6 - 6to4 State" {
        $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\TCPIP\v6Transition" -Name "6to4_State")."6to4_State"
        $obj | Should -Be "Default"
    }

    It "WLAN Driver Interface - Disable Scenario Execution" {
        $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}" -Name "ScenarioExecutionEnabled").ScenarioExecutionEnabled
        $obj | Should -Be "0"
    }

    It "Disable PeerNet" {
        $obj = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Peernet" -Name "Disabled").Disabled
        $obj | Should -Be "1"
    }
}

Describe "Windows Features and Services" {
    $features = Get-WindowsFeature | Where-Object { $_.InstallState -eq "Installed" }

    Context "Installed Features" {
        It ".NET Framework 4.6 should -Be installed" {
            "NET-Framework-45-Core" | Should BeIn $features.Name
        }
    }

    Context "Removed Features" {
        Write-Host "##[debug] STIG V-73291"
        It "Peer Name Resolution Protocol should not be installed" {
            "PNRP" | Should Not BeIn $features.Name
        }

        Write-Host "##[debug] STIG V-73293"
        It "Simple TCP/IP Services should not be installed" {
            "Simple-TCPIP" | Should Not BeIn $features.Name
        }

        Write-Host "##[debug] STIG V-73295"
        It "Telnet Client should not be installed" {
            "Telnet-Client" | Should Not BeIn $features.Name
        }

        Write-Host "##[debug] STIG V-73301"
        It "Windows PowerShell 2.0 Engine should not be installed" {
            "PowerShell-V2" | Should Not BeIn $features.Name
        }

        Write-Host "##[debug] STIG V-73289"
        It "FTP Server should not be installed" {
            "Web-Ftp-Server" | Should Not BeIn $features.Name
        }

        Write-Host "##[debug] STIG V-73299, V-78123, V-78125"
        It "SMB 1.0/CIFS File Sharing Support should not be installed" {
            "FS-SMB1" | Should Not BeIn $features.Name
        }

        It "Print and Document Services should not be installed" {
            "Print-Services" | Should Not BeIn $features.Name
        }

        It "Quality Windows Audio Video Experience should not be installed" {
            "qWave" | Should Not BeIn $features.Name
        }

        It "Client for NFS should not be installed" {
            "NFS-Client" | Should Not BeIn $features.Name
        }

        It "Media Foundation should not be installed" {
            "Server-Media-Foundation" | Should Not BeIn $features.Name
        }
    }
}

Describe "General Windows Configuration Items" {
    Context "Windows Event Logging" {
        Context "Windows Application Event Log" {
            $log = Get-LogProperties -Name Application
            Write-Host "##[debug] STIG V-73553"
            It "Application Event Log Maximum Size" {
                $log.MaxLogSize | Should BeGreaterOrEqual "134217728"
            }

            It "Application Event Log Retention Mode" {
                $log.Retention | Should -Be $false
            }
        }

        Context "Windows Security Event Log" {
            $log = Get-LogProperties -Name Security
            Write-Host "##[debug] STIG V-73555"
            It "Security Event Log Maximum Size" {
                $log.MaxLogSize | Should BeGreaterOrEqual "268435456"
            }

            It "Security Event Log Retention Mode" {
                $log.Retention | Should -Be $false
            }
        }

        Context "Windows System Event Log" {
            $log = Get-LogProperties -Name System
            Write-Host "##[debug] STIG V-73557"
            It "System Event Log Maximum Size" {
                $log.MaxLogSize | Should BeGreaterOrEqual "134217728"
            }

            It "System Event Log Retention Mode" {
                $log.Retention | Should -Be $false
            }
        }
    }

    Context "Other Items" {
        $tz = Get-TimeZone
        It "System Time Zone" {
            $tz.Id | Should -Be "Eastern Standard Time"
        }
    }
}
