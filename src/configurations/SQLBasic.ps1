<#
    .SYNOPSIS
        This script will compile a DSC MOF configuration file for a basic SQL Server 2016 installation.

    .DESCRIPTION
        Run this script to create a Desired State Configuration MOF file. The MOF file can then be placed on the pull server and distributed. The default feature for this configuration is the SQL DB Engine but other supported features can be added as needed.

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

    .PARAMETER SqlServiceCred
        PSCredential object for the SQL service account.
        Required: False
        Type: String
        Parameter Sets: All
        Position: Named
        Default Value: none
        Accept pipeline input: False
        Accept wildcard characters: False

    .PARAMETER AgtServiceCred
        PSCredential object for the SQL Agent service account.
        Required: False
        Type: String
        Parameter Sets: All
        Position: Named
        Default Value: none
        Accept pipeline input: False
        Accept wildcard characters: False

    .PARAMETER SysAdmins
        String array of sysadmin user names or group names to add to the SQL server permissions.
        Required: False
        Type: String
        Parameter Sets: All
        Position: Named
        Default Value: none
        Accept pipeline input: False
        Accept wildcard characters: False

    .EXAMPLE
        PS C:\> SQLBasic -ComputerName 'localhost' -OutputPath "C:\Temp" -Verbose

        This example will compile a MOF file from the 'SQLBasic' DSC onfiguration script.

    .NOTES
        Important: Some parameter values presented in this script may be examples only and should be changed before this script is used in a testing or production scenario. Carefully review all configuration values before deployment.

        Items denoted with a 'V' and a five digit number (Example: 'V-73287') are configuration items from the official DISA STIG reference guides. Each 'V' number corresponds to a STIG finding.

        Important: This DSC configuration script also makes use of a PSD data file for full configuration flexibility. The accompanying SQLBasic.psd1 file contains default/example values for some items and should be updated before using this configuration.

        Example values for DB mail parameters:
        - DBMailAccountName  = 'Database Mail'
        - DBMailOperatorName = 'DBA Team'
        - DBMailEmailAddress = 'dbateam@corp.com'
        - DBMailServerName   = 'smtp.corp.com'

        The values in this script use the following example disk layout for a SQL installation:
        - C: - OS - 96-128 GB
        - B: - Backups - 50 GB
        - E: - Data - 50 GB
        - L: - Logs - 20 GB
        - S: - Program Files - 30 GB
        - T: - Temp DB - 20 GB

        Author: Mike Nickerson

    .LINK
        https://public.cyber.mil/stigs/

    .LINK
        https://stigviewer.com/stig/ms_sql_server_2016_database/

    .LINK
        https://stigviewer.com/stig/ms_sql_server_2016_instance/
#>

[cmdletbinding()]
param (
    [parameter(HelpMessage = "Output path for the compiled MOF file.")]
    [string]$Destination,

    [parameter(Mandatory = $true)]
    [System.Management.Automation.PSCredential]$SqlServiceCred,

    [parameter(Mandatory = $true)]
    [System.Management.Automation.PSCredential]$AgtServiceCred,

    [parameter()]
    [string[]]$SysAdmins
)

Configuration SQLBasic {

    param (
        [parameter()]
        [string] $ComputerName = $AllNodes.NodeName,

        [parameter()]
        [string]$Features = "SQLENGINE"
    )

    #? Import DSC Modules
    Import-DscResource -ModuleName 'SqlServerDsc' -ModuleVersion 13.3.0
    Import-DscResource -ModuleName 'NetworkingDSC' -ModuleVersion 7.4.0.0
    Import-DscResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion 2.10.0.0
    Import-DscResource -ModuleName 'PSDscResources' -ModuleVersion 2.12.0.0

    Node $AllNodes.NodeName  {

        Firewall 'Allow SQL 1433 Inbound' {
            Name        = 'Allow SQL 1433 Inbound'
            DisplayName = 'Allow SQL 1433 Inbound'
            Ensure      = 'Present'
            Enabled     = $true
            Profile     = ('Domain', 'Private')
            Direction   = 'Inbound'
            LocalPort   = '1433'
            Protocol    = 'TCP'
        }

        #* Allow the service accounts to log on as a service
        UserRightsAssignment Log_on_as_a_service {
            Policy   = 'Log_on_as_a_service'
            Identity = "$($script:SqlServiceCred.UserName)"
            Ensure   = 'Present'
        }

        #* Grant Replace a process level token right
        UserRightsAssignment Replace_a_process_level_token {
            Policy   = 'Replace_a_process_level_token'
            Identity = "$($script:SqlServiceCred.UserName)"
            Ensure   = 'Present'
        }

        File 'Create SystemDB Backup Folder' {
            Ensure          = 'Present'
            DestinationPath = 'B:\SQLBackup\SystemDB'
            Type            = 'Directory'
        }

        File 'Create UserDB Backup Folder' {
            Ensure          = 'Present'
            DestinationPath = 'B:\SQLBackup\UserDB'
            Type            = 'Directory'
        }

        SqlSetup 'Install SQL Server 2016 Default Instance' {
            #* General parameters
            SourcePath             = 'C:\Temp\SQL_Server_2016'
            UpdateEnabled          = 'False'
            ForceReboot            = $true
            SQMReporting           = 0
            ErrorReporting         = 0
            SqlSvcStartupType      = 'Automatic'
            AgtSvcStartupType      = 'Automatic'

            #* Default instance basic parameters
            InstanceName           = $Node.InstanceName
            Features               = $Features
            SQLCollation           = 'SQL_Latin1_General_CP1_CI_AS'
            InstallSharedDir       = 'S:\Program Files\Microsoft SQL Server'
            InstallSharedWOWDir    = 'S:\Program Files (x86)\Microsoft SQL Server'
            InstanceDir            = 'S:\Program Files\Microsoft SQL Server'
            InstallSQLDataDir      = 'S:\Program Files\Microsoft SQL Server'
            SQLUserDBDir           = 'E:\Program Files\Microsoft SQL Server\MSSQL13.MSSQLSERVER\MSSQL\Data'
            SQLUserDBLogDir        = 'L:\Program Files\Microsoft SQL Server\MSSQL13.MSSQLSERVER\MSSQL\Data'
            SQLTempDBDir           = 'T:\Program Files\Microsoft SQL Server\MSSQL13.MSSQLSERVER\MSSQL\Data'
            SQLTempDBLogDir        = 'T:\Program Files\Microsoft SQL Server\MSSQL13.MSSQLSERVER\MSSQL\Data'
            SQLBackupDir           = 'B:\SQLBackup'

            #* Security & Accounts
            SQLSysAdminAccounts    = $script:SysAdmins
            SQLSvcAccount          = $script:SqlServiceCred
            AgtSvcAccount          = $script:AgtServiceCred

            #* Split Temp DB Files
            SqlTempdbFileCount     = 4
            SqlTempdbFileSize      = 1024
            SqlTempdbFileGrowth    = 512
            SqlTempdbLogFileSize   = 512
            SqlTempdbLogFileGrowth = 128
        }

        SqlServiceAccount 'Configure SQL DB Engine Service Account' {
            ServerName     = $Node.ServerName
            InstanceName   = $Node.InstanceName
            ServiceType    = 'DatabaseEngine'
            RestartService = $true
            ServiceAccount = $script:SqlServiceCred
        }

        SqlServiceAccount 'Configure SQL Agent Service Account' {
            ServerName     = $Node.ServerName
            InstanceName   = $Node.InstanceName
            ServiceType    = 'SQLServerAgent'
            RestartService = $true
            ServiceAccount = $script:AgtServiceCred
        }

        SqlServerRole 'Configure SysAdmin Role Members' {
            ServerName       = $Node.ServerName
            InstanceName     = $Node.InstanceName
            Ensure           = 'Present'
            ServerRoleName   = 'sysadmin'
            MembersToInclude = $script:SysAdmins
        }

        SqlServerNetwork 'Set TCP Port Number' {
            ServerName     = $Node.ServerName
            InstanceName   = $Node.InstanceName
            ProtocolName   = 'Tcp'
            IsEnabled      = $true
            TcpDynamicPort = $false
            TcpPort        = 1433
            RestartService = $true
        }

        SqlAgentOperator 'Add DBA Team Operator' {
            Name         = $ConfigurationData.NonNodeData.DBMailOperatorName
            Ensure       = 'Present'
            ServerName   = $Node.ServerName
            InstanceName = $Node.InstanceName
            EmailAddress = $ConfigurationData.NonNodeData.DBMailEmailAddress
        }

        SqlServerDatabaseMail 'Setup DB Mail' {
            ServerName     = $Node.ServerName
            InstanceName   = $Node.InstanceName
            Ensure         = 'Present'
            AccountName    = $ConfigurationData.NonNodeData.DBMailAccountName
            ProfileName    = $ConfigurationData.NonNodeData.DBMailOperatorName
            EmailAddress   = $ConfigurationData.NonNodeData.DBMailEmailAddress
            ReplyToAddress = $ConfigurationData.NonNodeData.DBMailEmailAddress
            DisplayName    = $ConfigurationData.NonNodeData.DBMailEmailAddress
            MailServerName = $ConfigurationData.NonNodeData.DBMailServerName
            Description    = $ConfigurationData.NonNodeData.DBMailAccountName
            TcpPort        = 25
        }

        SqlDatabaseRecoveryModel 'Set Model DB Full Recovery' {
            Name          = 'Model'
            RecoveryModel = 'Full'
            ServerName    = $Node.ServerName
            InstanceName  = $Node.InstanceName
        }

        $ConfigurationData.NonNodeData.ConfigurationOptions.foreach{
            SqlServerConfiguration ("SetConfiguration{0} " -f $_.Name) {
                ServerName   = $Node.NodeName
                InstanceName = $Node.InstanceName
                OptionName   = $_.Name
                OptionValue  = $_.Setting
            }
        }

        #* Set memory parameters - 27 GB maximum based on 32 GB total system memory
        SqlServerMemory 'Configure Max Memory Setting' {
            ServerName   = $Node.ServerName
            InstanceName = $Node.InstanceName
            Ensure       = 'Present'
            MaxMemory    = 27648
        }

        SqlDatabaseDefaultLocation 'Default User Data Directory' {
            ServerName              = $Node.ServerName
            InstanceName            = $Node.InstanceName
            ProcessOnlyOnActiveNode = $true
            Type                    = 'Data'
            Path                    = 'E:\Program Files\Microsoft SQL Server\MSSQL13.MSSQLSERVER\MSSQL\Data'
        }

        SqlDatabaseDefaultLocation 'Default User Log Directory' {
            ServerName              = $Node.ServerName
            InstanceName            = $Node.InstanceName
            ProcessOnlyOnActiveNode = $true
            Type                    = 'Log'
            Path                    = 'L:\Program Files\Microsoft SQL Server\MSSQL13.MSSQLSERVER\MSSQL\Data'
        }

        SqlDatabaseDefaultLocation 'Default Backup Directory' {
            ServerName              = $Node.ServerName
            InstanceName            = $Node.InstanceName
            ProcessOnlyOnActiveNode = $true
            Type                    = 'Backup'
            Path                    = 'B:\SQLBackup'
        }

        #* Make sure Telemetry (CEIP) services remain disabled
        Service 'Disable SQL Telemetry CEIP - Service' {
            Name        = 'SQLTELEMETRY'
            StartupType = 'Disabled'
            State       = 'Stopped'
        }

        Registry 'Disable SQL Telemetry - CustomerFeedback' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Microsoft\Microsoft SQL Server\130'
            ValueName = 'CustomerFeedback'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry 'Disable SQL Telemetry - EnableErrorReporting' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Microsoft\Microsoft SQL Server\130'
            ValueName = 'EnableErrorReporting'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry 'Disable SQL Telemetry - CustomerFeedback (WOW6432)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\WOW6432Node\Microsoft\Microsoft SQL Server\130'
            ValueName = 'CustomerFeedback'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry 'Disable SQL Telemetry - EnableErrorReporting (WOW6432)' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\WOW6432Node\Microsoft\Microsoft SQL Server\130'
            ValueName = 'EnableErrorReporting'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry 'Increase Error Log Count' {
            Ensure    = 'Present'
            Key       = 'HKLM:\Software\Microsoft\MSSQLServer\MSSQLServer'
            ValueName = 'NumErrorLogs'
            ValueType = 'DWord'
            ValueData = '30'
            Force     = $true
        }

        #* Ensure the DBA Team operator schedule is set - using a script because this setting is not currently supported with the SqlServerDsc module
        SqlScript 'SQL Basic - DBA Team Operator Schedule' {
            ServerInstance = $Node.Nodename
            GetFilePath    = "$($ConfigurationData.NonNodeData.ScriptPath)\DBATeamSchedGetScript.sql"
            TestFilePath   = "$($ConfigurationData.NonNodeData.ScriptPath)\DBATeamSchedTestScript.sql"
            SetFilePath    = "$($ConfigurationData.NonNodeData.ScriptPath)\DBATeamSchedSetScript.sql"
            QueryTimeout   = 30
        }

        #* Email SQL Agent Job History job
        SqlScript 'SQL Basic - Configure SQL Agent Job History' {
            ServerInstance = $Node.Nodename
            GetFilePath    = "$($ConfigurationData.NonNodeData.ScriptPath)\SQLAgentJobHistoryGetScript.sql"
            TestFilePath   = "$($ConfigurationData.NonNodeData.ScriptPath)\SQLAgentJobHistoryTestScript.sql"
            SetFilePath    = "$($ConfigurationData.NonNodeData.ScriptPath)\SQLAgentJobHistorySetScript.sql"
            QueryTimeout   = 30
        }

        #* TDE Databases job
        SqlScript 'SQL Basic - Configure TDE Databases' {
            ServerInstance = $Node.Nodename
            GetFilePath    = "$($ConfigurationData.NonNodeData.ScriptPath)\TDEDatabasesGetScript.sql"
            TestFilePath   = "$($ConfigurationData.NonNodeData.ScriptPath)\TDEDatabasesTestScript.sql"
            SetFilePath    = "$($ConfigurationData.NonNodeData.ScriptPath)\TDEDatabasesSetScript.sql"
            QueryTimeout   = 30
        }

        #* Set 'remote query timeout'
        SqlScript 'SQL Basic - Configure Remote Query Timeout' {
            ServerInstance = $Node.Nodename
            GetFilePath    = "$($ConfigurationData.NonNodeData.ScriptPath)\RemoteQueryTimeoutGetScript.sql"
            TestFilePath   = "$($ConfigurationData.NonNodeData.ScriptPath)\RemoteQueryTimeoutTestScript.sql"
            SetFilePath    = "$($ConfigurationData.NonNodeData.ScriptPath)\RemoteQueryTimeoutSetScript.sql"
            QueryTimeout   = 30
        }

        #* Set 'remote access' (from 1.PostInstallSQLConfigScript.sql)
        SqlScript 'SQL Basic - Configure Remote Access' {
            ServerInstance = $Node.Nodename
            GetFilePath    = "$($ConfigurationData.NonNodeData.ScriptPath)\RemoteAccessGetScript.sql"
            TestFilePath   = "$($ConfigurationData.NonNodeData.ScriptPath)\RemoteAccessTestScript.sql"
            SetFilePath    = "$($ConfigurationData.NonNodeData.ScriptPath)\RemoteAccessSetScript.sql"
            QueryTimeout   = 30
        }

        #* Configure Get/Set/Test Queries: Create Server Roles
        SqlScript 'SQL Basic - Check if dbconnectrole exists' {
            ServerInstance = $Node.Nodename
            GetFilePath    = "$($ConfigurationData.NonNodeData.ScriptPath)\dbconnectroleExistGetScript.sql"
            TestFilePath   = "$($ConfigurationData.NonNodeData.ScriptPath)\dbconnectroleExistTestGetScript.sql"
            SetFilePath    = "$($ConfigurationData.NonNodeData.ScriptPath)\dbconnectroleExistSetScript.sql"
            QueryTimeout   = 30
        }

        #* Configure Get/Set/Test Queries:Server Role permissions
        SqlScript 'SQL Basic - Grant required permissions to dbconnectrole' {
            ServerInstance = $Node.Nodename
            GetFilePath    = "$($ConfigurationData.NonNodeData.ScriptPath)\dbconnectrolePermissionsGetScript.sql"
            TestFilePath   = "$($ConfigurationData.NonNodeData.ScriptPath)\dbconnectrolePermissionsTestScript.sql"
            SetFilePath    = "$($ConfigurationData.NonNodeData.ScriptPath)\dbconnectrolePermissionsSetScript.sql"
            QueryTimeout   = 30
        }

        #* Configure Get/Set/Test Queries: Create Server Roles
        SqlScript 'SQL Basic - Check if publicrole exists' {
            ServerInstance = $Node.Nodename
            GetFilePath    = "$($ConfigurationData.NonNodeData.ScriptPath)\publicroleExistGetScript.sql"
            TestFilePath   = "$($ConfigurationData.NonNodeData.ScriptPath)\publicroleExistTestScript.sql"
            SetFilePath    = "$($ConfigurationData.NonNodeData.ScriptPath)\publicroleExistSetScript.sql"
            QueryTimeout   = 30
        }

        #* Configure Get/Set/Test Queries:Server Role permissions
        SqlScript 'SQL Basic - Grant required permissions to publicrole' {
            ServerInstance = $Node.Nodename
            GetFilePath    = "$($ConfigurationData.NonNodeData.ScriptPath)\publicrolePermissionsGetScript.sql"
            TestFilePath   = "$($ConfigurationData.NonNodeData.ScriptPath)\publicrolePermissionsTestScript.sql"
            SetFilePath    = "$($ConfigurationData.NonNodeData.ScriptPath)\publicrolePermissionsSetScript.sql"
            QueryTimeout   = 30
        }
    }
}

Write-Host "##[command] Compiling SQLBasic configuration..."
SQLBasic -ConfigurationData "$($Destination)\..\SQLBasic.psd1" -OutputPath "$($Destination)" -Verbose
Rename-Item -Path "$($Destination)\localhost.mof" -NewName "SQLBasic.mof" -Verbose
Write-Host "##[command] Creating SQLBasic checksum..."
New-DscChecksum -Path "$($Destination)\SQLBasic.mof" -Force -Verbos