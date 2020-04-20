<#
    .SYNOPSIS
        Installs required PowerShell DSC modules on a pull server.

    .DESCRIPTION
        Installs required PowerShell DSC modules on a pull server as a pre-requisite for deploying a new pull server or updating the DSC modules on a currently deployed server.

    .EXAMPLE
        PS C:\> DSCPullServerPreReqs.ps1

        When run on the pull server itself, this script will download and install the specified modules with the specified versions. You must ensure the correct module names and versions are listed. The script will attempt to install the modules from the Microsoft PowerShell Gallery (PSGallery) and then will attempt to use any other configured repositories if the PSGallery is inaccessible or does not host the required modules.

    .INPUTS

    .OUTPUTS

    .NOTES
        Author: Mike Nickerson
#>


Get-PackageProvider -Name Nuget -ForceBootstrap | Out-Null

# List of PowerShell Modules required for the build
$modulesToInstall = [System.Collections.ArrayList]::new()
$modulesToInstall = @(
    @{ModuleName = "PSDscResources"; ModuleVersion = "2.12.0.0" },
    @{ModuleName = "xWebAdministration"; ModuleVersion = "3.1.1" },
    @{ModuleName = "xSystemSecurity"; ModuleVersion = "1.5.0" },
    @{ModuleName = "SqlServerDsc"; ModuleVersion = "13.3.0" },
    @{ModuleName = "NetworkingDSC"; ModuleVersion = "7.4.0.0" },
    @{ModuleName = "SecurityPolicyDSC"; ModuleVersion = "2.10.0.0" },
    @{ModuleName = "ComputerManagementDsc"; ModuleVersion = "8.0.0" },
    @{ModuleName = "AuditPolicyDSC"; ModuleVersion = "1.4.0.0" },
    @{ModuleName = "xPSDesiredStateConfiguration"; ModuleVersion = "9.1.0" }
)

foreach ($module in $modulesToInstall) {
    $installSplat = @{
        Name            = $module.ModuleName
        RequiredVersion = $module.ModuleVersion
        Force           = $true
        ErrorAction     = 'Stop'
    }
    if (!(Get-Module -Name $module.ModuleName -ListAvailable)) {
        try {
            Install-Module @installSplat -Verbose
            Import-Module -Name $module.ModuleName -ErrorAction Stop
        }
        catch {
            $_.Exception.Message
        }
    }
    else {
        Write-Output "$($module.ModuleName) version $($module.ModuleVersion) is already installed. Continuing..."
    }
}

Write-Output "Checking for Microsoft OLE DB Driver for SQL Server..."
$driver = Get-CimInstance -Namespace "ROOT\cimv2" -ClassName "Win32_Product" -Filter "name = 'Microsoft OLE DB Driver for SQL Server'"
if (!($driver)) {
    # Provide a valid path to the installer MSI file
    & 'msiexec /i "msoledbsql_18.3.0.0_x64.msi" /q IACCEPTMSOLEDBSQLLICENSETERMS=YES'
}
else {
    Write-Output "$($driver.Name), version $($driver.Version) is installed."
}