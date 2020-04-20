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
        PS C:\> WindowsGUI -ComputerName 'localhost' -OutputPath "C:\Temp" -Verbose

        This example will compile a MOF file from the 'WindowsGUI' DSC onfiguration script.

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
    [parameter(HelpMessage = "Output path for the compiled MOF file.")]
    [string]$Destination
)

Configuration WindowsGUI {

    param (
        [parameter(HelpMessage = "The computer name for the target DSC client.")]
        [string]$ComputerName = 'localhost'
    )

    #* Import DSC modules
    Import-DscResource -ModuleName 'PSDscResources' -ModuleVersion 2.12.0.0
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion 8.0.0
    Import-DscResource -ModuleName 'NetworkingDSC' -ModuleVersion 7.4.0.0

    Node $Computername {

        Firewall 'Firewall - WMI-RPCSS-In-TCP' {
            Name    = 'WMI-RPCSS-In-TCP'
            Ensure  = 'Present'
            Enabled = 'True'
        }

        Firewall 'Firewall - WMI-WINMGMT-In-TCP' {
            Name    = 'WMI-WINMGMT-In-TCP'
            Ensure  = 'Present'
            Enabled = 'True'
        }

        Firewall 'Firewall - WMI-ASYNC-In-TCP' {
            Name    = 'WMI-ASYNC-In-TCP'
            Ensure  = 'Present'
            Enabled = 'True'
        }

        Firewall 'Firewall - WMI-WINMGMT-Out-TCP' {
            Name    = 'WMI-WINMGMT-Out-TCP'
            Ensure  = 'Present'
            Enabled = 'True'
        }

        #* WindowsFeatureSet resource from the PSDscResources module
        WindowsFeatureSet 'Windows GUI - Remove Unneeded Windows Features' {
            Ensure               = 'Absent'
            Name                 = @(
                'Fax', #? V-73287
                'RSAT-Fax', #? V-73287
                'TFTP-Client', #? V-73297
                'Remote-Assistance',
                'Biometric-Framework',
                'Wireless-Networking',
                'MultiPoint-Connector',
                'XPS-Viewer',
                'Internet-Print-Client' #? Originally part of WindowsGUI config - meets requirement for WindowsGUI STIG V-76753
            )
            IncludeAllSubFeature = $true
        }

        #* ServiceSet resource from the PSDscResources module
        #? Based on guidance from https://docs.microsoft.com/en-us/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server
        ServiceSet 'Windows GUI - Disable Unused Services' {
            Name        = @(
                'AJRouter', #? AllJoyn Router Service
                'bthserv', #? Bluetooth Support Service
                'DeviceAssociationService', #? Device Association Service - Enables pairing between the system and wired or wireless devices.
                'dmwappushservice', #? WAP Push Message Routing Service - Service required on client devices for Intune, MDM and similar management technologies, and for Unified Write Filter. Not needed for Server.
                'MapsBroker', #? Downloaded Maps Manager
                'lfsvc', #? Geolocation Service
                'SharedAccess', #? Internet Connection Sharing (ICS)
                'lltdsvc', #? Link-Layer Topology Discovery Mapper
                'wlidsvc', #? Microsoft Account Sign-in Assistant - Microsoft Accounts are N/A on Windows Server
                'PhoneSvc', #? Phone Service - Used by modern VoIP apps
                'QWAVE', #? Quality Windows Audio Video Experience - Client-side QoS service
                'RmSvc', #? Radio Management Service
                'SensorDataService', #? Sensor Data Service - Delivers data from a variety of sensors
                'SensrSvc', #? Sensor Monitoring Service - Monitors various sensors in order to expose data and adapt to system and user state. If this service is stopped or disabled, the display brightness will not adapt to lighting conditions.
                'SensorService', #? Sensor Service - A service for sensors that manages different sensors' functionality.
                'WiaRpc', #? Still Image Acquisition Events - Launches applications associated with still image acquisition events.
                'TapiSrv', #? Telephony -Provides Telephony API (TAPI) support for programs that control telephony devices on the local computer and, through the LAN, on servers that are also running the service.
                'upnphost', #? UPnP Device Host - Allows UPnP devices to be hosted on this computer.
                'WalletService', #? WalletService - Hosts objects used by clients of the wallet
                'Audiosrv', #? Windows Audio - Manages audio for Windows-based programs.
                'AudioEndpointBuilder', #? Windows Audio Endpoint Builder - Manages audio devices for the Windows Audio service.
                'WbioSrvc', #? Windows Biometric Service - The Windows biometric service gives client applications the ability to capture, compare, manipulate, and store biometric data without gaining direct access to any biometric hardware or samples. The service is hosted in a privileged SVCHOST process.
                'FrameServer', #? Windows Camera Frame Server - Enables multiple clients to access video frames from camera devices.
                'stisvc', #? Windows Image Acquisition (WIA) - Provides image acquisition services for scanners and cameras.
                'wisvc', #? Windows Insider Service
                'icssvc', #? Windows Mobile Hotspot Service - Provides the ability to share a cellular data connection with another device.
                'XblAuthManager', #? Xbox Live Auth Manager - Provides authentication and authorization services for interacting with Xbox Live.
                'XblGameSave', #? Xbox Live Game Save - This service syncs save data for Xbox Live save enabled games.
                'TabletInputService', #? Enables Touch Keyboard and Handwriting Panel pen and ink functionality
                'WSearch' #? Windows Search Service (disabled by default on Windows Server 2016)
            )
            StartupType = 'Disabled'
            State       = 'Stopped'
        }

        Registry 'Disable Enclosure Download (V-73577)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds'
            ValueName = 'DisableEnclosureDownload'
            ValueType = 'DWORD'
            ValueData = '1'
            Force     = $true
        }

        #? Windows Server 2012R2 V-36709 & Windows Server 2016 V-73579
        Registry 'Do not Allow Basic Auth In Clear (V-73579)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds'
            ValueName = 'AllowBasicAuthInClear'
            ValueType = 'DWORD'
            ValueData = '0'
            Force     = $true
        }

        Registry 'Script-initiated windows without size or position constraints must be disallowed (Internet zone) (V-46637)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '2102'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }

        Registry 'All network paths (UNCs) for Intranet sites must be disallowed (V-46635)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap'
            ValueName = 'UNCAsIntranet'
            ValueType = 'DWORD'
            ValueData = '0'
            Force     = $true
        }

        Registry 'Checking for signatures on downloaded programs must be enforced (V-46633)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Download'
            ValueName = 'CheckExeSignatures'
            ValueType = 'STRING'
            ValueData = 'yes'
            Force     = $true
        }

        Registry 'The Download unsigned ActiveX controls property must be disallowed (Restricted Sites zone) (V-46575)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '1004'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }


        Registry 'Internet Explorer Processes for Restrict File Download must be enforced (Reserved) (V-46733)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD'
            ValueName = '(Reserved)'
            ValueType = 'STRING'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Script-initiated windows without size or position constraints must be disallowed (Restricted Sites zone) (V-46639)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '2102'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }


        Registry 'Internet Explorer Processes for Zone Elevation must be enforced (iexplore) (V-46731)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION'
            ValueName = 'iexplore.exe'
            ValueType = 'STRING'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Scripting of Internet Explorer WebBrowser control property must be disallowed (Internet zone) (V-46849)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '1206'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }

        Registry 'InPrivate Browsing must be disallowed (V-46847)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Privacy'
            ValueName = 'EnableInPrivateBrowsing'
            ValueType = 'DWORD'
            ValueData = '0'
            Force     = $true
        }

        Registry 'Deleting websites that the user has visited must be disallowed (V-46841)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Privacy'
            ValueName = 'CleanHistory'
            ValueType = 'DWORD'
            ValueData = '0'
            Force     = $true
        }

        Registry 'The Download signed ActiveX controls property must be disallowed (Restricted Sites zone) (V-46573)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '1001'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }

        Registry 'Automatic prompting for file downloads must be disallowed (Internet zone) (V-46643)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '2200'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }

        Registry 'Scriptlets must be disallowed (Internet zone) (V-46641)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '1209'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }

        Registry 'Java permissions must be disallowed (Locked Down Local Machine zone) (V-46647)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\0'
            ValueName = '1C00'
            ValueType = 'DWORD'
            ValueData = '0'
            Force     = $true
        }

        Registry 'Java permissions must be disallowed (Local Machine zone) (V-46645)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0'
            ValueName = '1C00'
            ValueType = 'DWORD'
            ValueData = '0'
            Force     = $true
        }

        Registry 'Java permissions must be disallowed (Locked Down Intranet zone) (V-46649)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\1'
            ValueName = '1C00'
            ValueType = 'DWORD'
            ValueData = '0'
            Force     = $true
        }

        Registry 'Security checking features must be enforced (V-46621)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Security'
            ValueName = 'DisableSecuritySettingsCheck'
            ValueType = 'DWORD'
            ValueData = '0'
            Force     = $true
        }

        Registry 'Checking for server certificate revocation must be enforced (V-46629)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
            ValueName = 'CertificateRevocation'
            ValueType = 'DWORD'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Cross-Site Scripting Filter must be enforced (Internet zone) (V-46879)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '1409'
            ValueType = 'DWORD'
            ValueData = '0'
            Force     = $true
        }

        Registry 'ActiveX controls without prompt property must be used in approved domains only (Internet zone) (V-46865)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '120b'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }

        Registry 'Internet Explorer must be set to disallow users to add/delete sites (V-46615)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
            ValueName = 'Security_zones_map_edit'
            ValueType = 'DWORD'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Internet Explorer must be configured to disallow users to change policies (V-46617)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
            ValueName = 'Security_options_edit'
            ValueType = 'DWORD'
            ValueData = '1'
            Force     = $true
        }


        Registry 'Internet Explorer Processes for Notification Bars must be enforced (Explorer) (V-46861)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND'
            ValueName = 'explorer.exe'
            ValueType = 'STRING'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Internet Explorer must be configured to use machine settings (V-46619)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
            ValueName = 'Security_HKLM_only'
            ValueType = 'DWORD'
            ValueData = '1'
            Force     = $true
        }


        Registry 'Internet Explorer Processes for Notification Bars must be enforced (iexplore) (V-46869)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND'
            ValueName = 'iexplore.exe'
            ValueType = 'STRING'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Accessing data sources across domains must be disallowed (Restricted Sites zone) (V-46589)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '1406'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }

        Registry 'Font downloads must be disallowed (Restricted Sites zone) (V-46585)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '1604'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }

        Registry 'Java permissions must be disallowed (Restricted Sites zone) (V-46587)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '1C00'
            ValueType = 'DWORD'
            ValueData = '0'
            Force     = $true
        }

        Registry 'ActiveX controls marked safe for scripting must be disallowed (Restricted Sites zone) (V-46581)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '1405'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }

        Registry 'File downloads must be disallowed (Restricted Sites zone) (V-46583)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '1803'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }

        Registry 'Font downloads must be disallowed (Internet zone) (V-46505)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '1604'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }


        Registry 'Internet Explorer Processes for Zone Elevation must be enforced (Explorer) (V-46729)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION'
            ValueName = 'explorer.exe'
            ValueType = 'STRING'
            ValueData = '1'
            Force     = $true
        }

        Registry 'The Java permissions must be disallowed (Internet zone) (V-46507)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '1C00'
            ValueType = 'DWORD'
            ValueData = '0'
            Force     = $true
        }

        Registry 'The Initialize and script ActiveX controls not marked as safe property must be disallowed (Internet zone) (V-46501)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '1201'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }

        Registry 'Accessing data sources across domains must be disallowed (Internet zone) (V-46509)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '1406'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }

        Registry 'Crash Detection management must be enforced (V-46811)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Restrictions'
            ValueName = 'NoCrashDetection'
            ValueType = 'DWORD'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Configuring History setting must be set to 40 days (V-46609)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Url History'
            ValueName = 'DaysToKeep'
            ValueType = 'DWORD'
            ValueData = '40'
            Force     = $true
        }

        Registry 'Logon options must be configured and enforced (Restricted Sites zone) (V-46607)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '1A00'
            ValueType = 'DWORD'
            ValueData = '196608'
            Force     = $true
        }

        Registry 'Clipboard operations via script must be disallowed (Restricted Sites zone) (V-46605)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '1407'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }

        Registry 'Active scripting must be disallowed (Restricted Sites Zone) (V-46603)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '1400'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }

        Registry 'Userdata persistence must be disallowed (Restricted Sites zone) (V-46601)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '1606'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }

        Registry 'Navigating windows and frames across different domains must be disallowed (Restricted Sites zone) (V-46599)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '1607'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }

        Registry 'ActiveX controls without prompt property must be used in approved domains only (Restricted Sites zone) (V-46893)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '120b'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }

        Registry 'Functionality to drag and drop or copy and paste files must be disallowed (Restricted Sites zone) (V-46593)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '1802'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }

        Registry 'The Allow META REFRESH property must be disallowed (Restricted Sites zone) (V-46591)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '1608'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }


        Registry 'Internet Explorer Processes Restrict ActiveX Install must be enforced (Reserved) (V-46897)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL'
            ValueName = '(Reserved)'
            ValueType = 'STRING'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Launching programs and files in IFRAME must be disallowed (Restricted Sites zone) (V-46597)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '1804'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }

        Registry 'Cross-Site Scripting Filter property must be enforced (Restricted Sites zone) (V-46895)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '1409'
            ValueType = 'DWORD'
            ValueData = '0'
            Force     = $true
        }

        Registry 'Launching programs and files in IFRAME must be disallowed (Internet zone) (V-46513)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '1804'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }

        Registry 'Functionality to drag and drop or copy and paste files must be disallowed (Internet zone) (V-46511)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '1802'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }

        Registry 'Userdata persistence must be disallowed (Internet zone) (V-46517)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '1606'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }

        Registry 'Navigating windows and frames across different domains must be disallowed (Internet zone) (V-46515)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '1607'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }

        Registry 'Pop-up Blocker must be enforced (Restricted Sites zone) (V-46691)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '1809'
            ValueType = 'DWORD'
            ValueData = '0'
            Force     = $true
        }

        Registry 'Websites in less privileged web content zones must be prevented from navigating into the Internet zone (V-46693)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '2101'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }

        Registry 'Websites in less privileged web content zones must be prevented from navigating into the Restricted Sites zone (V-46695)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '2101'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }

        Registry 'Scripting of Java applets must be disallowed (Restricted Sites zone) (V-46801)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '1402'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }

        Registry 'The Initialize and script ActiveX controls not marked as safe property must be disallowed (Restricted Sites zone) (V-46577)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '1201'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }

        Registry 'AutoComplete feature for forms must be disallowed (V-46807)' {
            Ensure    = 'Present'
            Key       = 'HKCU:\Software\Policies\Microsoft\Internet Explorer\Main'
            ValueName = 'Use FormSuggest'
            ValueType = 'STRING'
            ValueData = 'no'
            Force     = $true
        }

        Registry 'ActiveX controls and plug-ins must be disallowed (Restricted Sites zone) (V-46579)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '1200'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }


        Registry 'Internet Explorer Processes for MIME sniffing must be enforced (Explorer) (V-46717)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING'
            ValueName = 'explorer.exe'
            ValueType = 'STRING'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Scriptlets must be disallowed (Restricted Sites zone) (V-46927)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '1209'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }

        Registry '.NET Framework-reliant components signed with Authenticode must be disallowed to run (Internet zone) (V-46921)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '2001'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }

        Registry 'Security Warning for unsafe files must be disallowed (Restricted Sites zone) (V-46889)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '1806'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }

        Registry 'Protected Mode must be enforced (Restricted Sites zone) (V-46685)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '2500'
            ValueType = 'DWORD'
            ValueData = '0'
            Force     = $true
        }

        Registry 'Protected Mode must be enforced (Internet zone) (V-46681)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '2500'
            ValueType = 'DWORD'
            ValueData = '0'
            Force     = $true
        }

        Registry 'Scripting of Internet Explorer WebBrowser Control must be disallowed (Restricted Sites zone) (V-46883)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '1206'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }

        Registry 'When uploading files to a server, the local directory path must be excluded (Restricted Sites zone) (V-46885)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '160A'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }

        Registry 'Pop-up Blocker must be enforced (Internet zone) (V-46689)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '1809'
            ValueType = 'DWORD'
            ValueData = '0'
            Force     = $true
        }

        Registry 'XAML files must be disallowed (Restricted Sites zone) (V-46669)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '2402'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }

        Registry 'Java permissions must be configured with High Safety (Trusted Sites zone) (V-46543)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2'
            ValueName = '1C00'
            ValueType = 'DWORD'
            ValueData = '65536'
            Force     = $true
        }

        Registry 'Dragging of content from different domains within a window must be disallowed (Internet zone) (V-46545)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '2708'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }

        Registry 'Allow binary and script behaviors must be disallowed (Restricted Sites zone) (V-46701)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '2000'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }


        Registry 'Internet Explorer Processes Restrict ActiveX Install must be enforced (Explorer) (V-46549)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL'
            ValueName = 'explorer.exe'
            ValueType = 'STRING'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Java permissions must be disallowed (Locked Down Restricted Sites zone) (V-46663)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4'
            ValueName = '1C00'
            ValueType = 'DWORD'
            ValueData = '0'
            Force     = $true
        }

        Registry 'XAML files must be disallowed (Internet zone) (V-46665)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '2402'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }


        Registry 'Internet Explorer Processes for MIME handling must be enforced. (Reserved) (V-46709)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING'
            ValueName = '(Reserved)'
            ValueType = 'STRING'
            ValueData = '1'
            Force     = $true
        }


        Registry 'Internet Explorer Processes Restrict ActiveX Install must be enforced (iexplore) (V-46553)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL'
            ValueName = 'iexplore.exe'
            ValueType = 'STRING'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Status bar updates via script must be disallowed (Restricted Sites zone) (V-46939)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '2103'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }

        Registry 'Anti-Malware programs against ActiveX controls must be run for the Local Machine zone (V-47003)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0'
            ValueName = '270C'
            ValueType = 'DWORD'
            ValueData = '0'
            Force     = $true
        }

        Registry 'Anti-Malware programs against ActiveX controls must be run for the Restricted Sites zone (V-47005)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '270C'
            ValueType = 'DWORD'
            ValueData = '0'
            Force     = $true
        }

        Registry 'The Internet Explorer warning about certificate address mismatch must be enforced (V-46475)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
            ValueName = 'WarnOnBadCertRecving'
            ValueType = 'DWORD'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Anti-Malware programs against ActiveX controls must be run for the Trusted Sites zone (V-47009)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2'
            ValueName = '270C'
            ValueType = 'DWORD'
            ValueData = '0'
            Force     = $true
        }

        Registry 'Automatic prompting for file downloads must be disallowed (Restricted Sites zone) (V-46705)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '2200'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }


        Registry 'Internet Explorer Processes for Restrict File Download must be enforced (Explorer) (V-46779)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD'
            ValueName = 'explorer.exe'
            ValueType = 'STRING'
            ValueData = '1'
            Force     = $true
        }


        Registry 'Internet Explorer Processes for MIME sniffing must be enforced (Reserved) (V-46715)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING'
            ValueName = '(Reserved)'
            ValueType = 'STRING'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Browser must retain history on exit (V-46829)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Privacy'
            ValueName = 'ClearBrowsingHistoryOnExit'
            ValueType = 'DWORD'
            ValueData = '0'
            Force     = $true
        }

        Registry 'Internet Explorer Processes for MIME handling must be enforced (Explorer) (V-46711)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING'
            ValueName = 'explorer.exe'
            ValueType = 'STRING'
            ValueData = '1'
            Force     = $true
        }


        Registry 'Internet Explorer Processes for MIME handling must be enforced (iexplore) (V-46713)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING'
            ValueName = 'iexplore.exe'
            ValueType = 'STRING'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Dragging of content from different domains within a window must be disallowed (Restricted Sites zone) (V-46555)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '2708'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }


        Registry 'Internet Explorer Processes for MIME sniffing must be enforced (iexplore) (V-46719)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING'
            ValueName = 'iexplore.exe'
            ValueType = 'STRING'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Status bar updates via script must be disallowed (Internet zone) (V-46903)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '2103'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }

        Registry '.NET Framework-reliant components not signed with Authenticode must be disallowed to run (Internet zone) (V-46907)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '2004'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }

        Registry 'When Enhanced Protected Mode is enabled, ActiveX controls must be disallowed to run in Protected Mode (V-46975)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main'
            ValueName = 'DisableEPMCompat'
            ValueType = 'DWORD'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Dragging of content from different domains across windows must be disallowed (Internet zone) (V-46981)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '2709'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }

        Registry 'Dragging of content from different domains across windows must be disallowed (Restricted Sites zone) (V-46547)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '2709'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }

        Registry 'Enhanced Protected Mode functionality must be enforced (V-46987)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main'
            ValueName = 'Isolation'
            ValueType = 'STRING'
            ValueData = 'PMEM'
            Force     = $true
        }


        Registry 'Internet Explorer Processes for restricting pop-up windows must be enforced (Explorer) (V-46789)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS'
            ValueName = 'explorer.exe'
            ValueType = 'STRING'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Internet Explorer Processes for restricting pop-up windows must be enforced (Reserved) (V-46787)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS'
            ValueName = '(Reserved)'
            ValueType = 'STRING'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Internet Explorer Processes for Restrict File Download must be enforced (iexplore) (V-46781)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD'
            ValueName = 'iexplore.exe'
            ValueType = 'STRING'
            ValueData = '1'
            Force     = $true
        }

        Registry '.NET Framework-reliant components signed with Authenticode must be disallowed to run (Restricted Sites Zone) (V-46799)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '2001'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }

        Registry 'Internet Explorer Processes for MK protocol must be enforced (Reserved) (V-46721)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL'
            ValueName = '(Reserved)'
            ValueType = 'STRING'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Internet Explorer Processes for MK protocol must be enforced (Explorer) (V-46723)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL'
            ValueName = 'explorer.exe'
            ValueType = 'STRING'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Internet Explorer Processes for MK protocol must be enforced (iexplore) (V-46725)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL'
            ValueName = 'iexplore.exe'
            ValueType = 'STRING'
            ValueData = '1'
            Force     = $true
        }

        Registry 'The Download signed ActiveX controls property must be disallowed (Internet zone) (V-46481)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '1001'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }

        Registry 'Internet Explorer Processes for Zone Elevation must be enforced (Reserved) (V-46727)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION'
            ValueName = '(Reserved)'
            ValueType = 'STRING'
            ValueData = '1'
            Force     = $true
        }

        Registry 'The Download unsigned ActiveX controls property must be disallowed (Internet zone) (V-46483)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '1004'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }

        Registry 'Logon options must be configured to prompt (Internet zone) (V-46523)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '1A00'
            ValueType = 'DWORD'
            ValueData = '65536'
            Force     = $true
        }

        Registry 'Clipboard operations via script must be disallowed (Internet zone) (V-46521)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '1407'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }

        Registry 'Java permissions must be configured with High Safety (Intranet zone) (V-46525)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1'
            ValueName = '1C00'
            ValueType = 'DWORD'
            ValueData = '65536'
            Force     = $true
        }

        Registry 'Security Warning for unsafe files must be set to prompt (Internet zone) (V-46859)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '1806'
            ValueType = 'DWORD'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Internet Explorer Processes for Notification Bars must be enforced (Reserved) (V-46857)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND'
            ValueName = '(Reserved)'
            ValueType = 'STRING'
            ValueData = '1'
            Force     = $true
        }

        Registry 'When uploading files to a server, the local directory path must be excluded (Internet zone) (V-46853)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '160A'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }

        Registry '.NET Framework-reliant components not signed with Authenticode must be disallowed to run (Restricted Sites Zone) (V-46797)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '2004'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }

        Registry 'Anti-Malware programs against ActiveX controls must be run for the Intranet zone (V-46999)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1'
            ValueName = '270C'
            ValueType = 'DWORD'
            ValueData = '0'
            Force     = $true
        }

        Registry 'Anti-Malware programs against ActiveX controls must be run for the Internet zone (V-46997)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '270C'
            ValueType = 'DWORD'
            ValueData = '0'
            Force     = $true
        }

        Registry 'The 64-bit tab processes, when running in Enhanced Protected Mode on 64-bit versions of Windows, must be turned on (V-46995)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main'
            ValueName = 'Isolation64Bit'
            ValueType = 'DWORD'
            ValueData = '1'
            Force     = $true
        }


        Registry 'Internet Explorer Processes for restricting pop-up windows must be enforced (iexplore) (V-46791)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS'
            ValueName = 'iexplore.exe'
            ValueType = 'STRING'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Java permissions must be disallowed (Locked Down Trusted Sites zone) (V-46653)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\2'
            ValueName = '1C00'
            ValueType = 'DWORD'
            ValueData = '0'
            Force     = $true
        }

        Registry 'Hide Zone Info On Properties (V-14269)' {
            Ensure    = 'Present'
            Key       = 'HKUS:\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments'
            ValueName = 'HideZoneInfoOnProperties'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Scan Attachments With Anti Virus (V-14270)' {
            Ensure    = 'Present'
            Key       = 'HKUS:\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments'
            ValueName = 'ScanWithAntiVirus'
            ValueType = 'DWord'
            ValueData = '3'
            Force     = $true
        }

        Registry 'PreventCodecDownload (V-3481)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\WindowsMediaPlayer'
            ValueName = 'PreventCodecDownload'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Turn off Encryption Support must be enabled (V-46473)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
            ValueName = 'SecureProtocols'
            ValueType = 'DWORD'
            ValueData = '2560'
            Force     = $true
        }

        Registry 'Check for publishers certificate revocation must be enforced (V-46477)' {
            Ensure    = 'Present'
            Key       = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing'
            ValueName = 'State'
            ValueType = 'DWORD'
            ValueData = '23C00'
            Hex       = $true
        }

        Registry 'Software must be disallowed to run or install with invalid signatures (V-46625)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Download'
            ValueName = 'RunInvalidSignatures'
            ValueType = 'DWORD'
            ValueData = '0'
            Force     = $true
        }

        Registry 'Turn on the auto-complete feature for user names and passwords on forms must be disabled (V-46815)' {
            Ensure    = 'Present'
            Key       = 'HKCU:\Software\Policies\Microsoft\Internet Explorer\Main'
            ValueName = 'FormSuggest PW Ask'
            ValueType = 'STRING'
            ValueData = 'no'
            Force     = $true
        }

        Registry 'Managing SmartScreen Filter use must be enforced (V-46819)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter'
            ValueName = 'EnabledV9'
            ValueType = 'DWORD'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Prevent bypassing SmartScreen Filter warnings must be enabled (V-64711)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter'
            ValueName = 'PreventOverride'
            ValueType = 'DWORD'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Prevent bypassing SmartScreen Filter warnings must be enabled (V-64713)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter'
            ValueName = 'PreventOverrideAppRepUnknown'
            ValueType = 'DWORD'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Prevent ignoring certificate errors option must be enabled (V-64717)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
            ValueName = 'PreventIgnoreCertErrors'
            ValueType = 'DWORD'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Turn on SmartScreen Filter scan option for the Internet Zone must be enabled (V-64719)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '2301'
            ValueType = 'DWORD'
            ValueData = '0'
            Force     = $true
        }

        Registry 'Turn on SmartScreen Filter scan option for the Restricted Sites Zone must be enabled (V-64721)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '2301'
            ValueType = 'DWORD'
            ValueData = '0'
            Force     = $true
        }

        Registry 'The Initialize and script ActiveX controls not marked as safe must be disallowed (Intranet Zone) (V-64723)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1'
            ValueName = '1201'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }

        Registry 'The Initialize and script ActiveX controls not marked as safe must be disallowed (Trusted Sites Zone) (V-64725)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2'
            ValueName = '1201'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }

        Registry 'Allow Fallback to SSL 3.0 (Internet Explorer) must be disabled (V-64729)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
            ValueName = 'EnableSSL3Fallback'
            ValueType = 'DWORD'
            ValueData = '0'
            Force     = $true
        }

        Registry 'Run once selection for running outdated ActiveX controls must be disabled (V-72757)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Ext'
            ValueName = 'RunThisTimeEnabled'
            ValueType = 'DWORD'
            ValueData = '0'
            Force     = $true
        }

        Registry 'Enabling outdated ActiveX controls for Internet Explorer must be blocked (V-72759)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Ext'
            ValueName = 'VersionCheckEnabled'
            ValueType = 'DWORD'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Use of the Tabular Data Control (TDC) ActiveX control must be disabled for the Internet Zone (V-72761)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '120c'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }

        Registry 'Use of the Tabular Data Control (TDC) ActiveX control must be disabled for the Restricted Sites Zone (V-72763)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '120c'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }

        Registry 'VBScript must not be allowed to run in Internet Explorer (Internet zone) (V-75169)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueName = '140C'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }

        Registry 'VBScript must not be allowed to run in Internet Explorer (Restricted Sites zone) (V-75171)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueName = '140C'
            ValueType = 'DWORD'
            ValueData = '3'
            Force     = $true
        }

        Registry 'Prevent per-user installation of ActiveX controls must be enabled (V-64715)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Security\ActiveX'
            ValueName = 'BlockNonAdminActiveXInstall'
            ValueType = 'DWORD'
            ValueData = '1'
            Force     = $true
        }

        Registry 'Windows Explorer - Do not Use Windows Store for OpenWith' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Policies\Microsoft\Windows\Explorer'
            ValueName = 'NoUseStoreOpenWith'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }
    }
}

Write-Host "##[command] Compiling WindowsGUI configuration..."
WindowsGUI -OutputPath "$($Destination)" -Verbose
Rename-Item -Path "$($Destination)\localhost.mof" -NewName "WindowsGUI.mof" -Verbose
Write-Host "##[command] Creating WindowsGUI checksum..."
New-DscChecksum -Path "$($Destination)\WindowsGUI.mof" -Force -Verbos