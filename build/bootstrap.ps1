

Write-Host "##[debug]PowerShell Version Information:"
$PSVersionTable
# https://docs.microsoft.com/powershell/module/packagemanagement/get-packageprovider
Get-PackageProvider -Name Nuget -ForceBootstrap | Out-Null

# List of PowerShell Modules required for the build
$modulesToInstall = [System.Collections.ArrayList]::new()
$modulesToInstall += (
    [PSCustomObject]@{ModuleName = "poshspec"; ModuleVersion = "2.2.8" },
    [PSCustomObject]@{ModuleName = "Pester"; ModuleVersion = "4.10.1" },
    [PSCustomObject]@{ModuleName = "PSScriptAnalyzer"; ModuleVersion = "1.18.3" },
    [PSCustomObject]@{ModuleName = "platyPS"; ModuleVersion = "0.14.0" },
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

Write-Host "`n##[debug]Checking PowerShell Modules...`n"
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
            Write-Host "##vso[task.logissue type=error]$($_.Exception.Message)"
            exit 1
        }
    }
    else {
        Write-Host "##[debug]$($module.ModuleName) version $($module.ModuleVersion) is already installed. Continuing..."
    }
}
