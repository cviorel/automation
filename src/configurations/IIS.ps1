<#
    .SYNOPSIS
        This script will compile a DSC MOF configuration file.

    .DESCRIPTION
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
        PS C:\> IIS -ComputerName 'localhost' -OutputPath "C:\Temp" -Verbose

        This example will compile a MOF file from the 'IIS' DSC onfiguration script.

    .NOTES
        Important: Some parameter values presented in this script may be examples only and should be changed before this script is used in a testing or production scenario. Carefully review all configuration values before deployment.

        Items denoted with a 'V' and a five digit number (Example: 'V-73287') are configuration items from the official DISA STIG reference guides. Each 'V' number corresponds to a STIG finding.

        The following items should be reviewed for relevance to the organization's IIS security requirements. Many items can be covered with OS-level STIG configurations or with procedures and operating policies:

        - V-76815 The IIS 8.5 website document directory must be in a separate partition from the IIS 8.5 websites system files
        - V-76865 The IIS 8.5 website must have a unique application pool.
        - V-76767 - The File System Object component must be disabled on the IIS 8.5 web server
        - V-76717 - Java software installed on a production IIS 8.5 web server must be limited to .class files and the Java Virtual Machine
        - V-76705 - All IIS 8.5 web server sample code, example applications, and tutorials must be removed from a production IIS 8.5 server
        - V-76751 - The IIS 8.5 web server must not be running on a system providing any other role
        - V-76753 - The Internet Printing Protocol (IPP) must be disabled on the IIS 8.5 web server
        - V-76759 - An IIS 8.5 web server must maintain the confidentiality of controlled information during transmission through the use of an approved TLS version
        - V-76761 - A web server must maintain the confidentiality of controlled information during transmission through the use of an approved TLS version
        - V-76763 - The IIS 8.5 web server must install security-relevant software updates within the configured time period directed by an authoritative source (e.g., IAVM, CTOs, DTMs, and STIGs)
        - V-76765 - All accounts installed with the IIS 8.5 web server software and tools must have passwords assigned and default passwords changed
        - V-76719 - IIS 8.5 Web server accounts accessing the directory tree, the shell, or other operating system functions and utilities must only be administrative accounts
        - V-76721 - The IIS 8.5 web server must separate the hosted applications from hosted web server management functionality
        - V-76743 - The IIS 8.5 web server must provide the capability to immediately disconnect or disable remote access to the hosted applications
        - V-76679 - The IIS 8.5 web server remote authors or content providers must only use secure encrypted logons and connections to upload web server content
        - V-76739 - Remote access to the IIS 8.5 web server must follow access policy or work in conjunction with enterprise tools designed to enforce policy requirements
        - V-76749 - Access to web administration tools must be restricted to the web manager and the web managers designees
        - V-76699 - The IIS 8.5 web server must not perform user management for hosted applications
        - V-76701 - The IIS 8.5 web server must only contain functions necessary for operation
        - V-76707 - The accounts created by uninstalled features (i.e., tools, utilities, specific, etc.) must be deleted from the IIS 8.5 server
        - V-76709 - The IIS 8.5 web server must be reviewed on a regular basis to remove any Operating System features, utility programs, plug-ins, and modules not necessary for operation
        - V-76715 - The IIS 8.5 web server must perform RFC 5280-compliant certification path validation
        - V-76729 - The IIS 8.5 web server must augment re-creation to a stable and known baseline
        - V-76697 - The log data and records from the IIS 8.5 web server must be backed up onto a different system or media
        - V-76691 - The IIS 8.5 web server log files must only be accessible by privileged users
        - V-76695 - The log information from the IIS 8.5 web server must be protected from unauthorized deletion
        - V-76693 - The log information from the IIS 8.5 web server must be protected from unauthorized modification
        - V-76703 - The IIS 8.5 web server must not be both a website server and a proxy server

        Author: Mike Nickerson

    .LINK
        https://public.cyber.mil/stigs/

    .LINK
        https://www.stigviewer.com/stig/iis_8.5_server/

    .LINK
        https://www.stigviewer.com/stig/iis_8.5_site/

#>

[cmdletbinding()]
param (
    [parameter(HelpMessage = "Output path for the compiled MOF file.")]
    [string]$Destination
)

Configuration IIS {

    param (
        [parameter(HelpMessage = "The computer name for the target DSC client.")]
        [string]$ComputerName = 'localhost'
    )
    # Import DSC modules
    Import-DscResource -ModuleName 'PSDscResources' -ModuleVersion 2.12.0.0
    Import-DscResource -ModuleName 'xWebAdministration' -ModuleVersion 3.1.1
    Import-DscResource -ModuleName 'xSystemSecurity' -ModuleVersion 1.5.0

    Node $ComputerName {

        WindowsFeature 'Install IIS' {
            Ensure = "Present"
            Name   = "Web-Server"
        }

        WindowsFeatureSet 'Install Extra IIS Features' {
            Ensure               = 'Present'
            Name                 = @(
                'Web-Mgmt-Service',
                'Web-Scripting-Tools',
                'Web-Http-Redirect',
                'Web-Health',
                'Web-Performance',
                'Web-Asp-Net45'
            )
            IncludeAllSubFeature = $true
        }

        # Enable remote mgmt
        Registry 'Enable Remote Management' {
            Key       = 'HKLM:\SOFTWARE\Microsoft\WebManagement\Server'
            ValueName = 'EnableRemoteManagement'
            ValueData = '1'
            ValueType = 'DWord'
            Ensure    = 'Present'
            Force     = $true
        }

        # Ensure the WMSvc service is started
        Service 'Start WMSvc Service' {
            Name        = 'WMSvc'
            Ensure      = 'Present'
            StartupType = 'Automatic'
            State       = 'Running'
        }

        # V-76741 - The IIS 8.5 web server must restrict inbound connections from nonsecure zones (refers to the Web Management Service)
        Registry 'Restrict Remote Mgmt Access (V-76741)' {
            Key       = 'HKLM:\SOFTWARE\Microsoft\WebManagement\Server'
            ValueName = 'RemoteRestrictions'
            ValueData = '/wEZAgAAAAEAAABoAgAAABkBAAAAAAAAABkDAAAAAQAAAC4EAwoDAAMAAwACAAAALgQD/wMAAwADAAMAAABn'
            # Value data above is based on using the New-RemoteRestrictions function: New-RemoteRestrictions -GlobalDeny $true -Addresses "10.0.0.0/255.0.0.0"
            ValueType = 'String'
            Ensure    = 'Present'
            Force     = $true
        }

        # Configure IIS logging options
        # Covers the following STIG findings:
        # V-76681 - The enhanced logging for the IIS 8.5 web server must be enabled and capture all user and web server events.
        # V-76687 - The IIS 8.5 web server must produce log records that contain sufficient information to establish the outcome (success or failure) of IIS 8.5 web server events.
        # V-76689 - The IIS 8.5 web server must produce log records containing sufficient information to establish the identity of any user/subject or process associated with an event.
        # V-76747 - The IIS 8.5 web server must use a logging mechanism that is configured to allocate log record storage capacity large enough to accommodate the logging requirements of the IIS 8.5 web server.
        # V-76685 - An IIS 8.5 web server behind a load balancer or proxy server, must produce log records containing the source client IP and destination information.
        xIisLogging 'Configure Logging for All Sites (V-76681, V-76687, V-76689, V-76747, V-76685)' {
            LogPath              = 'C:\inetpub\logs\LogFiles\'
            LoglocalTimeRollover = $true
            LogPeriod            = 'Daily'
            LogFormat            = 'W3C'
            LogFlags             = @(
                'Date',
                'Time',
                'ClientIP',
                'UserName',
                'Method',
                'ServerIP',
                'UriQuery',
                'HttpStatus',
                'UriStem',
                'ServerPort',
                'UserAgent',
                'HttpSubStatus',
                'Win32Status',
                'TimeTaken',
                'Referer',
                'Cookie'
            )
            LogCustomFields      = @(
                MSFT_xLogCustomField {
                    LogFieldName = 'Connection'
                    SourceName   = 'Connection'
                    SourceType   = 'RequestHeader'
                }

                MSFT_xLogCustomField {
                    LogFieldName = 'Warning'
                    SourceName   = 'Warning'
                    SourceType   = 'RequestHeader'
                }

                MSFT_xLogCustomField {
                    LogFieldName = 'User-Agent'
                    SourceName   = 'User-Agent'
                    SourceType   = 'RequestHeader'
                }

                MSFT_xLogCustomField {
                    LogFieldName = 'Authorization'
                    SourceName   = 'Authorization'
                    SourceType   = 'RequestHeader'
                }

                MSFT_xLogCustomField {
                    LogFieldName = 'Content-Type'
                    SourceName   = 'Content-Type'
                    SourceType   = 'RequestHeader'
                }
            )
        }

        # V-76683 - Both the log file and Event Tracing for Windows (ETW) for the IIS 8.5 web server must be enabled
        xWebConfigProperty 'Enable Event Tracing for Windows (V-76683)' {
            WebsitePath  = 'MACHINE/WEBROOT/APPHOST'
            Filter       = '/system.applicationHost/sites/sitedefaults/logfile'
            PropertyName = 'logTargetW3C'
            Value        = 'File,ETW'
            Ensure       = 'Present'
        }

        # V-76711 - The IIS 8.5 web server must have Multipurpose Internet Mail Extensions (MIME) that invoke OS shell programs disabled
        xIisMimeTypeMapping 'Disable Multipurpose Internet Mail Extensions (EXE) (V-76711)' {
            Ensure            = 'Absent'
            Extension         = '.exe'
            MimeType          = 'application/octet-stream'
            ConfigurationPath = "MACHINE/WEBROOT/APPHOST"
        }

        xIisMimeTypeMapping 'Disable Multipurpose Internet Mail Extensions (DLL) (V-76711)' {
            Ensure            = 'Absent'
            Extension         = '.dll'
            MimeType          = 'application/x-msdownload'
            ConfigurationPath = "MACHINE/WEBROOT/APPHOST"
        }

        xIisMimeTypeMapping 'Disable Multipurpose Internet Mail Extensions (CSH) (V-76711)' {
            Ensure            = 'Absent'
            Extension         = '.csh'
            MimeType          = 'application/x-csh'
            ConfigurationPath = "MACHINE/WEBROOT/APPHOST"
        }

        # V-76713 - The IIS 8.5 web server must have Web Distributed Authoring and Versioning (WebDAV) disabled
        WindowsFeature 'Remove WebDAV Feature (V-76713)' {
            Ensure = 'Absent'
            Name   = 'Web-DAV-Publishing'
        }

        # V-76723 - The IIS 8.5 web server Session State cookie settings must be configured to regenerate expired session IDs
        xWebConfigProperty 'Regenerate Expired Session ID (V-76723)' {
            WebsitePath  = 'MACHINE'
            Filter       = '/system.web/sessionState'
            PropertyName = 'RegenerateExpiredSessionID'
            Value        = $true
            Ensure       = 'Present'
        }

        # V-76725 - The IIS 8.5 web server must use cookies to track session state
        xWebConfigProperty 'Enable Cookies (V-76725)' {
            WebsitePath  = 'MACHINE'
            Filter       = '/system.web/sessionState'
            PropertyName = 'CookieLess'
            Value        = 'UseCookies'
            Ensure       = 'Present'
        }

        # V-76727 - The IIS 8.5 web server must limit the amount of time a cookie persists (00:20:00 is the IIS default)
        xWebConfigProperty 'Set Cookie Persistence (V-76727)' {
            WebsitePath  = 'MACHINE/WEBROOT/APPHOST'
            Filter       = '/system.webServer/asp/session'
            PropertyName = 'Timeout'
            Value        = '00:20:00'
            Ensure       = 'Present'
        }

        # V-76731 - The production IIS 8.5 web server must utilize SHA2 encryption for the Machine Key
        xWebConfigProperty 'Set Machine Key Validation (V-76731)' {
            WebsitePath  = 'MACHINE'
            Filter       = '/system.web/machineKey'
            PropertyName = 'Validation'
            Value        = 'HMACSHA256'
            Ensure       = 'Present'
        }

        xWebConfigProperty 'Set Machine Key Decryption' {
            WebsitePath  = 'MACHINE'
            Filter       = '/system.web/machineKey'
            PropertyName = 'Decryption'
            Value        = 'Auto'
            Ensure       = 'Present'
        }

        # V-76733 - Directory Browsing on the IIS 8.5 web server must be disabled
        xWebConfigProperty 'Disable Directory Browsing (V-76733)' {
            WebsitePath  = 'MACHINE/WEBROOT/APPHOST'
            Filter       = '/system.webServer/directoryBrowse'
            PropertyName = 'Enabled'
            Value        = $false
            Ensure       = 'Present'
        }

        # V-76737 - Warning and error messages displayed to clients must be modified to minimize the identity of the IIS 8.5 web server, patches, loaded modules, and directory paths
        xWebConfigProperty 'Modify Error Messages (V-76737)' {
            WebsitePath  = 'MACHINE/WEBROOT/APPHOST'
            Filter       = '/system.webServer/httpErrors'
            PropertyName = 'ErrorMode'
            Value        = 'DetailedLocalOnly'
            Ensure       = 'Present'
        }

        <# V-76745 - IIS 8.5 web server system files must conform to minimum file permission requirements
        xFileSystemAccessRule 'InetPub File System Permissions - SYSTEM (V-76745)' {
            Path     = "$env:SystemDrive\inetpub"
            Identity = "NT AUTHORITY\SYSTEM"
            Rights   = @("FullControl")
            Ensure   = "Present"
        }

        xFileSystemAccessRule 'InetPub File System Permissions - Administrators (V-76745)' {
            Path     = "$env:SystemDrive\inetpub"
            Identity = "BUILTIN\Administrators"
            Rights   = @("FullControl")
            Ensure   = "Present"
        }

        xFileSystemAccessRule 'InetPub File System Permissions - TrustedInstaller (V-76745)' {
            Path     = "$env:SystemDrive\inetpub"
            Identity = "NT Service\TrustedInstaller"
            Rights   = @("FullControl")
            Ensure   = "Present"
        }

        xFileSystemAccessRule 'InetPub File System Permissions - ALL APPLICATION PACKAGES (V-76745)' {
            Path     = "$env:SystemDrive\inetpub"
            Identity = "APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES"
            Rights   = @("ReadAndExecute")
            Ensure   = "Present"
        }

        xFileSystemAccessRule 'InetPub File System Permissions - Users (V-76745)' {
            Path     = "$env:SystemDrive\inetpub"
            Identity = "BUILTIN\Users"
            Rights   = @("ReadAndExecute","ListDirectory")
            Ensure   = "Present"
        }#>

        # V-76757 - IIS 8.5 web server session IDs must be sent to the client using TLS
        xWebConfigProperty 'Send Session Id using TLS (V-76757)' {
            WebsitePath  = 'MACHINE/WEBROOT/APPHOST'
            Filter       = '/system.webServer/asp/session'
            PropertyName = 'keepSessionIdSecure'
            Value        = $true
            Ensure       = 'Present'
        }

        <# V-76771 - The IIS 8.5 web server must have a global authorization rule configured to restrict access
        xWebConfigProperty 'GlobalAuth-Administrator (V-76771)' {
            WebsitePath  = 'MACHINE'
            Filter       = '/system.web/authorization/allow'
            PropertyName = 'Users'
            Value        = 'Administrators'
            Ensure       = 'Present'
        }#>

        # V-76769 - Unspecified file extensions on a production IIS 8.5 web server must be removed
        xWebConfigProperty 'Remove Unspecified File Extensions (CGI) (V-76769)' {
            WebsitePath  = 'MACHINE/WEBROOT/APPHOST'
            Filter       = '/system.webserver/security/isapiCgiRestriction'
            PropertyName = 'notListedCgisAllowed'
            Value        = $false
            Ensure       = 'Present'
        }

        xWebConfigProperty 'Remove Unspecified File Extensions (ISAPI) (V-76769)' {
            WebsitePath  = 'MACHINE/WEBROOT/APPHOST'
            Filter       = '/system.webserver/security/isapiCgiRestriction'
            PropertyName = 'notListedIsapisAllowed'
            Value        = $false
            Ensure       = 'Present'
        }

        # V-76755 - The IIS 8.5 web server must be tuned to handle the operational requirements of the hosted application
        # See "Tuning IIS 10.0" for more details - https://docs.microsoft.com/en-us/windows-server/administration/performance-tuning/role/web-server/tuning-iis-10
        Registry 'Enable URI Cache (V-76755)' {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters'
            ValueName = 'UriEnableCache'
            ValueData = '1'
            ValueType = 'DWord'
            Ensure    = 'Present'
            Force     = $true
        }

        Registry 'Set Uri Max Bytes (V-76755)' {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters'
            ValueName = 'UriMaxUriBytes'
            ValueData = '262144'
            ValueType = 'DWord'
            Ensure    = 'Present'
            Force     = $true
        }

        Registry 'Set Uri Scavenger Period (V-76755)' {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters'
            ValueName = 'UriScavengerPeriod'
            ValueData = '120'
            ValueType = 'DWord'
            Ensure    = 'Present'
            Force     = $true
        }

        # V-76773 MaxConnections setting must be configured to limit the number of allowed simultaneous session requests
        xWebConfigProperty 'Limit Max Connections (V-76773)' {
            WebsitePath  = 'MACHINE/WEBROOT/APPHOST'
            Filter       = '/system.applicationHost/sites/siteDefaults/limits'
            PropertyName = 'maxConnections'
            Value        = '4294967295'
            Ensure       = 'Present'
        }

        # V-76805 The production website must configure the Global .NET Trust Level
        xWebConfigProperty 'Set Global .NET Trust Level (V-76805)' {
            WebsitePath  = 'MACHINE'
            Filter       = '/system.web/trust'
            PropertyName = 'Level'
            Value        = 'Full'
            Ensure       = 'Present'
        }

        # V-76811 Anonymous IIS 8.5 website access accounts must be restricted
        xWebConfigProperty 'Disable Anonymous Authentication (V-76811)' {
            WebsitePath  = 'MACHINE/WEBROOT/APPHOST'
            Filter       = '/system.webServer/security/authentication/anonymousAuthentication'
            PropertyName = 'Enabled'
            Value        = $true
            Ensure       = 'Present'
        }

        # V-76817 The IIS 8.5 website must be configured to limit the maxURL.
        xWebConfigProperty 'Configure Max Url Limit (V-76817)' {
            WebsitePath  = 'MACHINE/WEBROOT/APPHOST'
            Filter       = '/system.webServer/security/requestFiltering/requestLimits'
            PropertyName = 'maxUrl'
            Value        = '4096'
            Ensure       = 'Present'
        }

        # V-76819 The IIS 8.5 website must be configured to limit the size of web requests.
        xWebConfigProperty 'Configure Max Allowed Content Length (V-76819)' {
            WebsitePath  = 'MACHINE/WEBROOT/APPHOST'
            Filter       = '/system.webServer/security/requestFiltering/requestLimits'
            PropertyName = 'maxAllowedContentLength'
            Value        = '30000000'
            Ensure       = 'Present'
        }

        # V-76821 The IIS 8.5 websites Maximum Query String limit must be configured.
        xWebConfigProperty 'Configure Max Query String (V-76821)' {
            WebsitePath  = 'MACHINE/WEBROOT/APPHOST'
            Filter       = '/system.webServer/security/requestFiltering/requestLimits'
            PropertyName = 'maxQueryString'
            Value        = '2048'
            Ensure       = 'Present'
        }

        # V-76823 Non-ASCII characters in URLs must be prohibited by any IIS 8.5 website.
        xWebConfigProperty 'Do not Allow High Bit Characters (V-76823)' {
            WebsitePath  = 'MACHINE/WEBROOT/APPHOST'
            Filter       = '/system.webServer/security/requestFiltering'
            PropertyName = 'allowHighBitCharacters'
            Value        = $false
            Ensure       = 'Present'
        }

        # V-76825 Double encoded URL requests must be prohibited by any IIS 8.5 website.
        xWebConfigProperty 'Do not Allow Double Escaping (V-76825)' {
            WebsitePath  = 'MACHINE/WEBROOT/APPHOST'
            Filter       = '/system.webServer/security/requestFiltering'
            PropertyName = 'allowDoubleEscaping'
            Value        = $false
            Ensure       = 'Present'
        }

        # V-76827 Unlisted file extensions in URL requests must be filtered by any IIS 8.5 website.
        xWebConfigProperty 'Do not Allow Unlisted File Extensions (V-76827)' {
            WebsitePath  = 'MACHINE/WEBROOT/APPHOST'
            Filter       = '/system.webServer/security/requestFiltering/fileExtensions'
            PropertyName = 'allowUnlisted'
            Value        = $true
            Ensure       = 'Present'
        }

        # V-76877 The application pools pinging monitor for each IIS 8.5 website must be enabled.
        xWebConfigProperty 'Set Application Pool Defaults - Pinging Enabled (V-76877)' {
            WebsitePath  = 'MACHINE/WEBROOT/APPHOST'
            Filter       = '/system.applicationHost/applicationPools/applicationPoolDefaults/processModel'
            PropertyName = 'pingingEnabled'
            Value        = $true
            Ensure       = 'Present'
        }

        # V-76879 The application pools rapid fail protection for each IIS 8.5 website must be enabled.
        xWebConfigProperty 'Set Application Pool Defaults - Enable Rapid Fail Protection (V-76879)' {
            WebsitePath  = 'MACHINE/WEBROOT/APPHOST'
            Filter       = '/system.applicationHost/applicationPools/applicationPoolDefaults/failure'
            PropertyName = 'rapidFailProtection'
            Value        = $true
            Ensure       = 'Present'
        }

        # V-76881 The application pools rapid fail protection settings for each IIS 8.5 website must be managed.
        xWebConfigProperty 'Set Application Pool Defaults - Set Rapid Fail Protection Interval (V-76881)' {
            WebsitePath  = 'MACHINE/WEBROOT/APPHOST'
            Filter       = '/system.applicationHost/applicationPools/applicationPoolDefaults/failure'
            PropertyName = 'rapidFailProtectionInterval'
            Value        = (New-TimeSpan -Minutes 5).ToString()
            Ensure       = 'Present'
        }

        # V-76875 The maximum queue length for HTTP.sys for each IIS 8.5 website must be explicitly configured.
        xWebConfigProperty 'Set Application Pool Defaults - Set Queue Length (V-76875)' {
            WebsitePath  = 'MACHINE/WEBROOT/APPHOST'
            Filter       = '/system.applicationHost/applicationPools/applicationPoolDefaults'
            PropertyName = 'queueLength'
            Value        = '1000'
            Ensure       = 'Present'
        }
    }
}

Write-Host "##[command] Compiling IIS configuration..."
IIS -OutputPath "$($Destination)" -Verbose
Rename-Item -Path "$($Destination)\localhost.mof" -NewName "IIS.mof" -Verbose
Write-Host "##[command] Creating IIS checksum..."
New-DscChecksum -Path "$($Destination)\IIS.mof" -Force -Verbose


Start-IISCommitDelay
$fileExtensions = Get-IISConfigSection -SectionPath 'system.webServer/security/requestFiltering' | Get-IISConfigCollection -CollectionName 'fileExtensions'
New-IISConfigCollectionElement -ConfigCollection $fileExtensions -ConfigAttribute @{ 'fileExtension' = '.svc'; 'allowed' = $true } -AddAt 0
Set-IISConfigAttributeValue -ConfigElement $fileExtensions -AttributeName 'applyToWebDAV' -AttributeValue $false
Stop-IISCommitDelay