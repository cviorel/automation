<#
    .SYNOPSIS
        This script stages required PowerShell DSC modules on a pull server.

    .DESCRIPTION
        After deploying and configuring a web-based pull server, the script will attempt to download and stage the required DSC modules for client configurations. Any needed modules will be downloaded and installed from the Microsoft PowerShell Gallery or other configured repository.

    .PARAMETER ModuleList
        A string array of module names to be staged. The default value is '<SystemDrive>\Temp\ModuleDepot'.
        Example: $ModuleList += ([PSCustomObject]@{Name = "PSDscResources"; Version = "2.12.0.0" },[PSCustomObject]@{Name = "xWebAdministration"; Version = "3.1.1" })
        Required: False
        Type: String[]
        Parameter Sets: All
        Position: Named
        Default Value: none
        Accept pipeline input: False
        Accept wildcard characters: False

    .PARAMETER ModuleDepot
        The file path where downloaded modules will be staged for processing.
        Example: "$env:SystemDrive\Temp\ModuleDepot"
        Required: False
        Type: String
        Parameter Sets: All
        Position: Named
        Default Value: "$env:SystemDrive\Temp\ModuleDepot"
        Accept pipeline input: False
        Accept wildcard characters: False


    .EXAMPLE
        PS C:\> Publish-ModulePackages -ModuleList @("AuditPolicyDSC", "SecurityPolicyDSC")

        This example will download and stage the specified PowerShell modules for use on a DSC pull server.

    .INPUTS

    .OUTPUTS

    .NOTES
        Author: Mike Nickerson
    #>

Get-PackageProvider -Name Nuget -ForceBootstrap | Out-Null

$ModuleDepot = "$env:SystemDrive\Temp\ModuleDepot"
$modulesToInstall = [System.Collections.ArrayList]::new()
$modulesToInstall += (
    [PSCustomObject]@{ModuleName = "PSDscResources"; ModuleVersion = "2.12.0.0" },
    [PSCustomObject]@{ModuleName = "xWebAdministration"; ModuleVersion = "3.1.1" },
    [PSCustomObject]@{ModuleName = "xSystemSecurity"; ModuleVersion = "1.5.0" },
    [PSCustomObject]@{ModuleName = "SqlServerDsc"; ModuleVersion = "13.3.0" },
    [PSCustomObject]@{ModuleName = "NetworkingDSC"; ModuleVersion = "7.4.0.0" },
    [PSCustomObject]@{ModuleName = "SecurityPolicyDSC"; ModuleVersion = "2.10.0.0" },
    [PSCustomObject]@{ModuleName = "ComputerManagementDsc"; ModuleVersion = "8.0.0" },
    [PSCustomObject]@{ModuleName = "AuditPolicyDSC"; ModuleVersion = "1.4.0.0" },
    [PSCustomObject]@{ModuleName = "xPSDesiredStateConfiguration"; ModuleVersion = "9.1.0" }
)

Set-ExecutionPolicy Bypass -Scope Process -Force -Verbose

if (!(Test-Path -Path $ModuleDepot)) {
    New-Item -Path $ModuleDepot -ItemType Directory
}

foreach ($module in $modulesToInstall) {
    $installSplat = @{
        Name            = $module.ModuleName
        RequiredVersion = $module.ModuleVersion
        Force           = $true
        ErrorAction     = 'Stop'
        Path            = $ModuleDepot
    }
    try {
        Save-Module @installSplat -Verbose
    }
    catch {
        $_.Exception.Message
    }
}

Publish-DscModuleAndMof -Source $ModuleDepot -ModuleNameList $modulesToInstall.ModuleName -Force -Verbose