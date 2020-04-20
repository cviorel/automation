<#
    .SYNOPSIS
        Chocolatey Installer Script

    .DESCRIPTION
        This script can be used to install various types of packages with the Chocolatey utility. Packages can be installed from EXE/MSI/MSU files or unzipped from ZIP files.

        Package Installation Arguments used by the Chocolatey when installing a compiled installer (MSI/EXE/MSU).

        Required args:
        PackageName -> Name of the package being installed by Chocolatey, equivalent to the '<id />' field in the nuspec. Can be obtained from the environment var 'env:ChocolateyPackageName'
        FileType -> Installer/package type used to determine installation options. Valid values: 'MSI', 'EXE', 'MSU', 'PS'. Chocolatey uses each of the valid types except 'PS' which is only used by this script when determining which package installer method to use.
        File -> Full path to the installer file (.msi, .exe, etc.).

        Optional args:
        Checksum -> A SHA256 checksum value for the installer or packaged zip file. Obtain this value by using the 'checksum.exe' utility or the PowerShell cmdlet 'Get-FileHash'.
        ChecksumType -> Use 'SHA256' as the default hashing type.
        ValidExitCodes -> Array of exit codes indicating success. Defaults to @(0).
        SilentArgs -> These are the parameters to pass to the native installer, including any arguments to make the installer silent/unattended.
        SoftwareName -> The name of the software that will be displayed in Add/Remove Programs and/or the Windows registry. Will be used for detection of the software.

    .PARAMETER PackageName
        Name of the package being installed by Chocolatey, equivalent to the '<id />' field in the nuspec. Can be obtained from the environment var 'env:ChocolateyPackageName'.

    .PARAMETER PackageVersion
        Version of the package being installed by Chocolatey, equivalent to the '<version />' field in the nuspec. Can be obtained from the environment var 'env:ChocolateyPackageVersion'.

    .PARAMETER FileLocation
        Full path to the installer/zip file (.msi, .exe, .zip, etc.).

    .PARAMETER ToolsDir
        The path to the 'Tools' folder in the NuGet package. This folder should contain the Chocolatey installation scripts. Defaults to '$PSScriptRoot'.

    .PARAMETER FileType
        Installer/package type used to determine installation options. Valid values: 'MSI', 'EXE', 'MSU', 'ZIP'.

    .EXAMPLE
        PS C:\> chocolateyinstall.ps1 -PackageName 'myapp' -PackageVersion $env:ChocolateyPackageVersion -FileLocation (Join-Path $ToolsDir -ChildPath "$($PackageName)-v$($PackageVersion).exe") -ToolsDir $PSScriptRoot -FileType 'EXE'
        This command will attempt to install a package named 'myapp' with the version info provided by the $env:ChocolateyPackageVersion environment variable. The location of the installer EXE is determined using the specified expression.

    .INPUTS
        Inputs (if any)

    .OUTPUTS
        Output (if any)

    .NOTES
        Author: Mike Nickerson
#>

param (

    [parameter(HelpMessage = "Name of the package being installed by Chocolatey, equivalent to the '<id />' field in the nuspec. Can be obtained from the environment var 'env:ChocolateyPackageName'.")]
    [string]$PackageName = $env:ChocolateyPackageName,

    [parameter(HelpMessage = "Version of the package being installed by Chocolatey, equivalent to the '<version />' field in the nuspec. Can be obtained from the environment var 'env:ChocolateyPackageVersion'.")]
    [string]$PackageVersion = $env:ChocolateyPackageVersion,

    [parameter(HelpMessage = "Full path to the installer/zip file (.msi, .exe, .zip, etc.).")]
    [string]$FileLocation,

    [parameter(HelpMessage = "The path to the 'Tools' folder in the NuGet package. This folder should contain the Chocolatey installation scripts. Defaults to 'PSScriptRoot'.")]
    [string]$ToolsDir = $PSScriptRoot,

    [parameter(HelpMessage = "Installer/package type used to determine installation options. Valid values: 'MSI', 'EXE', 'MSU', 'ZIP'.")]
    [ValidateSet("MSI", "EXE", "MSU", "ZIP")]
    [string]$FileType
)

$ErrorActionPreference = 'Stop'

#$PackageName = ""
#$PackageVersion = ""
$FileLocation = Join-Path $ToolsDir -ChildPath "$($PackageName)-v$($PackageVersion).zip"
$ToolsDir = $PSScriptRoot
$FileType = "ZIP"

if ($FileType -eq "ZIP") {
    $minPowerShellVersion = 5
    if ($PSVersionTable.PSVersion.Major -lt $minPowerShellVersion) {
        throw "The $($PackageName) module requires a minimum of PowerShell v$($minPowerShellVersion)."
    }
    else {
        try {
            $destinationPath = Join-Path -Path $env:ProgramFiles -ChildPath "WindowsPowerShell\Modules\$($PackageName)\$($PackageVersion)"
            Get-ChocolateyUnzip -FileFullPath $FileLocation -Destination $destinationPath -PackageName $PackageName
        }
        catch {
            Throw $_.Exception.Message
        }
    }
}

else {
    # Uncomment and provide values for the options below if needed for the package installation.
    $packageArgs = @{
        PackageName = $PackageName
        # Checksum = ""
        # ChecksumType = "SHA256"
        FileType    = $FileType
        File        = $FileLocation
        # SoftwareName = $PackageName*
        # SilentArgs = ""
        # ValidExitCodes = @(0)
    }
    try {
        Install-ChocolateyInstallPackage @packageArgs
    }
    catch {
        Throw $_.Exception.Message
    }
}
