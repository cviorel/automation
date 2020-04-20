<#
    .SYNOPSIS
        This script provides configuration data required to execute a DSC configuration (MOF creation) script.

    .DESCRIPTION
        DSC configuration data is specified in a special ".psd1" file like this one in order to provide information that applies to multiple (or all) DSC clients that will be configured with the MOF file compiled from the normal DSC configuration script.

    .NOTES
        Important: Some parameter values presented in this script may be examples only and should be changed before this script is used in a testing or production scenario. Carefully review all configuration values before deployment.

        Author: Mike Nickerson

    .LINKS
        https://docs.microsoft.com/en-us/powershell/scripting/dsc/configurations/configdata?view=powershell-5.1
#>

@{

    AllNodes    = @(

        @{
            NodeName                    = 'localhost'
            ServerName                  = 'localhost'
            InstanceName                = 'MSSQLSERVER'
            PSDscAllowDomainUser        = $true
            PSDscAllowPlainTextPassword = $true
        }
    )

    NonNodeData = @{
        DBMailAccountName    = 'Database Mail'
        DBMailOperatorName   = 'DBA Team'
        DBMailEmailAddress   = 'dbateam@corp.com'
        DBMailServerName     = 'smtp.corp.com'

        ScriptPath           = "C:\Temp\SQLQueries"

        ConfigurationOptions = @(
            @{
                #* Configure backup compression (From PostInstallSQLConfigScript)
                Name    = 'backup compression default'
                Setting = '1'
            }
            @{
                #* Configure max user connections (From PostInstallSQLConfigScript)
                Name    = 'user connections'
                Setting = '5000'
            }
            @{
                #* Emable Database Mail XPs
                Name    = 'Database Mail XPs'
                Setting = '1'
            }
        )
    }
}