####################################################################
# Integration tests for IIS Config
####################################################################

#Requires -Modules @{ ModuleName="Pester";ModuleVersion="4.10.1" }

Describe "Web Server and Other Windows Features" {
    $features = Get-WindowsFeature | Where-Object { $_.Name -like "web*" -and $_.InstallState -eq "Installed" }

    Context "Installed Features" {

        It "IIS is Installed" {
            "Web-Server" | Should -BeIn $features.Name
        }

        It "ASP.Net 4.5 Feature is Installed" {
            "Web-Asp-Net45" | Should -BeIn $features.Name
        }

        It "Web Management Service is Installed" {
            "Web-Mgmt-Service" | Should -BeIn $features.Name
        }

        It "Web HTTP Redirect Feature is Installed" {
            "Web-Http-Redirect" | Should -BeIn $features.Name
        }

        It "Web Health Service is Installed" {
            "Web-Health" | Should -BeIn $features.Name
        }

        It "Web Performance Feature is Installed" {
            "Web-Performance" | Should -BeIn $features.Name
        }
    }

    Context "Absent Features" {

        It "WebDAV Feature is not Installed (V-76713)" {
            "Web-DAV-Publishing" | Should -Not -BeIn $features.Name
        }
    }
}

Describe "IIS Remote Management Settings" {

    It "Remote Management Is Enabled" {
        $obj = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\WebManagement | Get-ItemProperty | Select-Object -ExpandProperty EnableRemoteManagement
        $obj | Should -Be "1"
    }

    It "Includes Remote Restrictions (V-76741)" {
        $obj = (Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\WebManagement | Get-ItemProperty -Name RemoteRestrictions).RemoteRestrictions
        $obj | Should -Be '/wEZAgAAAAEAAABoAgAAABkBAAAAAAAAABkDAAAAAQAAAC4EAwoDAAMAAwACAAAALgQD/wMAAwADAAMAAABn'
    }

    It "WMSVC Service is Started" {
        $obj = Get-Service -Name WMSVC
        $obj.Status | Should -Be "Running"
    }
}

Describe "IIS Logging Settings" {

    $settings = Get-WebConfiguration -Filter "/system.applicationHost/sites/siteDefaults/Logfile"

    It "Logging Is Enabled" {
        $settings.Enabled | Should -Be $true
    }

    It "Log Format Is W3C (V-76681)" {
        $settings.LogFormat | Should -Be "W3C"
    }

    It "Log Period Is Daily (V-76747)" {
        $settings.period | Should -Be "Daily"
    }

    It "Use Local Time for Log Rollover (V-76747)" {
        $settings.localTimeRollover | Should -Be $true
    }

    It "Log Target Destination (V-76683)" {
        $settings.logTargetW3C | Should -Be "File,ETW"
    }

    It "Logging Path is Set Correctly" {
        $settings.directory | Should -Be "F:\LogFiles"
    }

    It "Add Required Log Flags (V-76681)" {
        $currentFields = (Get-WebConfiguration -Filter System.Applicationhost/Sites/SiteDefaults/logfile).LogExtFileFlags.Split(",")
        $fieldNames = @(
            'Date',
            'Time',
            'ClientIP',
            'UserName',
            'ServerIP',
            'UriQuery',
            'HttpStatus',
            'Method',
            'UriStem',
            'ServerPort',
            'UserAgent',
            'HttpSubStatus',
            'Win32Status',
            'TimeTaken',
            'Cookie'
        )
        $fieldNames | Should -BeIn $currentFields
    }

    It "Add Required Custom Logging Flags (V-76687)" {
        $currentFields = (Get-WebConfiguration -Filter System.Applicationhost/Sites/SiteDefaults/logfile).customFields.Collection
        $fieldNames = @(
            "Connection",
            "Warning",
            "User-Agent",
            "Content-Type"
        )
        $fieldNames | Should -BeIn $currentFields.logFieldName
    }
}

Describe "General IIS Security Settings" {

    Context "Disable Specified MIME Extensions (V-76711)" {
        $mimeConfig = (Get-WebConfiguration //staticcontent).Collection
        It "EXE MIME Extension is Disabled" {
            $mimeConfig | Where-Object { $_.fileExtension -eq ".exe" } | Should -Be $null
        }

        It "DLL MIME Extension is Disabled" {
            $mimeConfig | Where-Object { $_.fileExtension -eq ".dll" } | Should -Be $null
        }

        It "CSH MIME Extension is Disabled" {
            $mimeConfig | Where-Object { $_.fileExtension -eq ".csh" } | Should -Be $null
        }
    }

    Context "Session State & Cookies Configuration" {
        $sessionStateSettings = Get-WebConfiguration -Filter "/system.web/sessionState"
        $sessionSettings = Get-WebConfiguration -Filter "/system.webServer/asp/session"
        It "RegenerateExpiredSessionID is Enabled (V-76723)" {
            $sessionStateSettings.RegenerateExpiredSessionID | Should -Be $true
        }

        It "CookieLess is set to UseCookies (V-76725)" {
            $sessionStateSettings.CookieLess | Should -Be "UseCookies"
        }

        It "Cookie Persistence Timeout is 20 Minutes (V-76727)" {
            $sessionSettings.Timeout.ToString() | Should -Be "00:20:00"
        }

        It "Session IDs Sent via TLS (V-76757)" {
            $sessionSettings.keepSessionIdSecure | Should -Be $true
        }

        It "MaxConnections Must Limit Simultaneous Sessions (V-76773)" {
            $obj = Get-WebConfiguration -Filter "/system.applicationHost/sites/siteDefaults/limits"
            $obj.MaxConnections | Should -Be "4294967295"
        }
    }

    Context "Machine Key Validation & Decryption (V-76731)" {
        $machineKeySettings = Get-WebConfiguration -Filter "/system.web/machineKey"
        It "Machine key Validation" {
            $machineKeySettings.Validation | Should -Be "HMACSHA256"
        }

        It "Machine key Decryption" {
            $machineKeySettings.Decryption | Should -Be "Auto"
        }
    }

    Context "File Extensions" {
        $isapiSettings = Get-WebConfiguration -Filter "/system.webserver/security/isapiCgiRestriction"
        It "Remove Unspecified CGI File Extensions (V-76769)" {
            $isapiSettings.notListedCgisAllowed | Should -Be $false
        }

        It "Remove Unspecified ISAPI File Extensions (V-76769)" {
            $isapiSettings.notListedIsapisAllowed | Should -Be $false
        }

        It "Prohibit Unlisted File Extensions (V-76827)" {
            $obj = Get-WebConfiguration -Filter "/system.webServer/security/requestFiltering/fileExtensions"
            $obj.allowUnlisted | Should -Be $false
        }
    }

    Context "Web Server Tuning (V-76755)" {
        It "Configure URIEnableCache" {
            $obj = Get-Item -Path HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters | Get-ItemProperty | Select-Object -ExpandProperty UriEnableCache
            $obj | Should -Be "1"
        }

        It "Configure UriMaxUriBytes" {
            $obj = Get-Item -Path HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters | Get-ItemProperty | Select-Object -ExpandProperty UriMaxUriBytes
            $obj | Should -Be "262144"
        }

        It "Configure UriScavengerPeriod" {
            $obj = Get-Item -Path HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters | Get-ItemProperty | Select-Object -ExpandProperty UriScavengerPeriod
            $obj | Should -Be "120"
        }
    }

    Context "Request Limits" {
        $reqLimits = Get-WebConfiguration -Filter "/system.webServer/security/requestFiltering/requestLimits"
        $reqFilteringLimits = Get-WebConfiguration -Filter "/system.webServer/security/requestFiltering"
        It "MaxURL Limit must be set to 4096 or less (V-76817)" {
            $reqLimits.maxURl | Should -BeLessOrEqual "4096"
        }

        It "MaxAllowedContentLength Limit must be set to 30000000 or less (V-76819)" {
            $reqLimits.maxAllowedContentLength | Should -BeLessOrEqual "30000000"
        }

        It "MaxQueryString Limit must be set to 2048 or less (V-76821)" {
            $reqLimits.maxQueryString | Should -BeLessOrEqual "2048"
        }

        It "Prohibit Non-ASCII Characters in URLs (V-76823)" {
            $reqFilteringLimits.allowHighBitCharacters | Should -Be $false
        }

        It "Prohibit Double Encoded URL Requests (V-76825)" {
            $reqFilteringLimits.allowDoubleEscaping | Should -Be $false
        }
    }

    Context "Application Pool Configuration" {
        $appPoolFailureSettings = Get-WebConfiguration -Filter "/system.applicationHost/applicationPools/applicationPoolDefaults/failure"
        It "Enable Application Pool Rapid Fail Protection (V-76879)" {
            $appPoolFailureSettings.rapidFailProtection | Should -Be $true
        }

        It "Manage Application Pool Rapid Fail Protection (V-76881)" {
            $appPoolFailureSettings.rapidFailProtectionInterval.ToString() | Should -Be "00:05:00"
        }

        It "Enable Application Pools Pinging Monitor (V-76877)" {
            $obj = Get-WebConfiguration -Filter "/system.applicationHost/applicationPools/applicationPoolDefaults/processModel"
            $obj.pingingEnabled | Should -Be $true
        }

        It "Configure Maximum Queue Length (V-76875)" {
            $obj = Get-WebConfiguration -Filter "/system.applicationHost/applicationPools/applicationPoolDefaults"
            $obj.queueLength | Should -Be "1000"
        }
    }

    It "Directory Browsing is Disabled (V-76733)" {
        $obj = Get-WebConfiguration -Filter "/system.webServer/directorybrowse"
        $obj.Enabled | Should -Be $false
    }

    It "Error Messages Should -Be Modified (V-76737)" {
        $obj = Get-WebConfiguration -Filter "/system.webServer/httpErrors"
        $obj.ErrorMode | Should -Be "DetailedLocalOnly"
    }

    It "The Global .Net Trust Level Must be Set to Full or Less (V-76805)" {
        $obj = Get-WebConfiguration -Filter "/system.web/trust"
        $obj.Level | Should -BeIn @("Full", "High", "Medium", "Low", "Minimal")
    }

    It "Anonymous Authentication must be Disabled (V-76811)" {
        $obj = Get-WebConfiguration -Filter "/system.webServer/security/authentication/anonymousAuthentication"
        $obj.Enabled | Should -Be $false
    }
}

Describe "File System Permissions (V-76745)" {

    Context "C:\Inetpub Permissions" {
        $permissions = Get-Acl -Path "C:\inetpub" -ErrorAction SilentlyContinue
        It "Allow - SYSTEM - FullControl" {
            $permissions.AccessToString | Should -BeLike "*NT AUTHORITY\SYSTEM*Allow*FullControl*"
        }

        It "Allow - Administrators - FullControl" {
            $permissions.AccessToString | Should -BeLike "*BUILTIN\Administrators*Allow*FullControl*"
        }

        It "Allow - TrustedInstaller - FullControl" {
            $permissions.AccessToString | Should -BeLike "*NT SERVICE\TrustedInstaller*Allow*FullControl*"
        }

        It "Allow - ALL APPLICATION PACKAGES - ReadAndExecute" {
            $permissions.AccessToString | Should -BeLike "*ALL APPLICATION PACKAGES*Allow*ReadAndExecute*"
        }

        It "Allow - Users - ReadAndExecute/ListDirectory" {
            $permissions.AccessToString | Should -BeLike "*BUILTIN\Users*Allow*ReadAndExecute,*Synchronize*"
        }
    }

    Context "C:\Inetpub\ Subdirectory Permissions" {

        It "C:\Inetpub\history - Allow - SYSTEM - FullControl" {
            $permissions = Get-Acl -Path "C:\inetpub\history" -ErrorAction SilentlyContinue
            $permissions.AccessToString | Should -BeLike "*NT AUTHORITY\SYSTEM*Allow*FullControl*"
        }

        It "C:\Inetpub\history - Allow - Users - FullControl" {
            $permissions = Get-Acl -Path "C:\inetpub\history" -ErrorAction SilentlyContinue
            $permissions.AccessToString | Should -BeLike "*BUILTIN\Users*Allow*FullControl*"
        }

        It "C:\inetpub\logs - Allow - WMSvc - ListDirectory" {
            $permissions = Get-Acl -Path "C:\inetpub\logs" -ErrorAction SilentlyContinue
            $permissions.AccessToString | Should -BeLike "*NT SERVICE\WMSVC*Allow*ReadAndExecute,*Synchronize*"
        }

        It "C:\inetpub\logs\FailedReqLogFiles - Allow - SYSTEM - FullControl" {
            $permissions = Get-Acl -Path "C:\inetpub\logs\FailedReqLogFiles" -ErrorAction SilentlyContinue
            $permissions.AccessToString | Should -BeLike "*NT AUTHORITY\SYSTEM*Allow*FullControl*"
        }

        It "C:\inetpub\logs\FailedReqLogFiles - Allow - Administrators - FullControl" {
            $permissions = Get-Acl -Path "C:\inetpub\logs\FailedReqLogFiles" -ErrorAction SilentlyContinue
            $permissions.AccessToString | Should -BeLike "*BUILTIN\Administrators*Allow*FullControl*"
        }

        It "C:\inetpub\logs\FailedReqLogFiles - Allow - IIS_IUSRS - Various" {
            $permissions = Get-Acl -Path "C:\inetpub\logs\FailedReqLogFiles" -ErrorAction SilentlyContinue
            $permissions.AccessToString | Should -BeLike "*BUILTIN\IIS_IUSRS*Allow*ReadData,*DeleteSubdirectoriesAndFiles,*Write,*Delete,*Synchronize*"
        }

        It "C:\inetpub\logs\wmsvc - Allow - WMSvc - Various" {
            $permissions = Get-Acl -Path "C:\inetpub\logs\wmsvc" -ErrorAction SilentlyContinue
            $permissions.AccessToString | Should -BeLike "*NT SERVICE\WMSVC*Allow*Modify,*Synchronize*"
        }

        It "C:\Inetpub\custerr - Allow - Users - ReadAndExecute/ListDirectory" {
            $permissions = Get-Acl -Path "C:\inetpub\custerr" -ErrorAction SilentlyContinue
            $permissions.AccessToString | Should -BeLike "*BUILTIN\Users*Allow*"
        }

        It "C:\inetpub\temp\IIS Temporary Compressed Files - Allow - SYSTEM - FullControl" {
            $permissions = Get-Acl -Path "C:\inetpub\temp\IIS Temporary Compressed Files" -ErrorAction SilentlyContinue
            $permissions.AccessToString | Should -BeLike "*NT AUTHORITY\SYSTEM*Allow*FullControl*"
        }

        It "C:\inetpub\temp\IIS Temporary Compressed Files - Allow - Administrators - FullControl" {
            $permissions = Get-Acl -Path "C:\inetpub\temp\IIS Temporary Compressed Files" -ErrorAction SilentlyContinue
            $permissions.AccessToString | Should -BeLike "*BUILTIN\Administrators*Allow*FullControl*"
        }

        It "C:\inetpub\temp\IIS Temporary Compressed Files - Allow - IIS_IUSRS - FullControl" {
            $permissions = Get-Acl -Path "C:\inetpub\temp\IIS Temporary Compressed Files" -ErrorAction SilentlyContinue
            $permissions.AccessToString | Should -BeLike "*BUILTIN\IIS_IUSRS*Allow*FullControl*"
        }

        It "C:\inetpub\temp\appPools - Allow - SYSTEM - FullControl" {
            $permissions = Get-Acl -Path "C:\inetpub\temp\appPools" -ErrorAction SilentlyContinue
            $permissions.AccessToString | Should -BeLike "*NT AUTHORITY\SYSTEM*Allow*FullControl*"
        }

        It "C:\inetpub\temp\appPools - Allow - Administrators - FullControl" {
            $permissions = Get-Acl -Path "C:\inetpub\temp\appPools" -ErrorAction SilentlyContinue
            $permissions.AccessToString | Should -BeLike "*BUILTIN\Administrators*Allow*FullControl*"
        }

        It "C:\inetpub\wwwroot - Allow - IIS_IUSRS - ReadAndExecute" {
            $permissions = Get-Acl -Path "C:\inetpub\wwwroot" -ErrorAction SilentlyContinue
            $permissions.AccessToString | Should -BeLike "*BUILTIN\IIS_IUSRS*Allow*ReadAndExecute,*Synchronize*"
        }
    }

    Context "E:\Inetpub Permissions" {
        $permissions = Get-Acl -Path "e:\inetpub" -ErrorAction SilentlyContinue
        It "Allow - SYSTEM - FullControl" {
            $permissions.AccessToString | Should -BeLike "*NT AUTHORITY\SYSTEM*Allow*FullControl*"
        }

        It "Allow - Administrators - FullControl" {
            $permissions.AccessToString | Should -BeLike "*BUILTIN\Administrators*Allow*FullControl*"
        }

        It "Allow - TrustedInstaller - FullControl" {
            $permissions.AccessToString | Should -BeLike "*NT SERVICE\TrustedInstaller*Allow*FullControl*"
        }

        It "Allow - ALL APPLICATION PACKAGES - ReadAndExecute" {
            $permissions.AccessToString | Should -BeLike "*ALL APPLICATION PACKAGES*Allow*ReadAndExecute*"
        }

        It "Allow - Users - ReadAndExecute/ListDirectory" {
            $permissions.AccessToString | Should -BeLike "*BUILTIN\Users*Allow*ReadAndExecute,*Synchronize*"
        }
    }
}