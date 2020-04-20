
param (

    [parameter(HelpMessage = "Name of the package being installed by Chocolatey, equivalent to the '<id />' field in the nuspec. Can be obtained from the environment var 'env:ChocolateyPackageName'.")]
    [string]$PackageName = $env:ChocolateyPackageName,

    [parameter(HelpMessage = "Version of the package being installed by Chocolatey, equivalent to the '<version />' field in the nuspec. Can be obtained from the environment var 'env:ChocolateyPackageVersion'.")]
    [string]$PackageVersion = $env:ChocolateyPackageVersion
)

$ErrorActionPreference = "Stop"

$path = Join-Path -Path $env:ProgramFiles -ChildPath "WindowsPowerShell\Modules\$PackageName\$PackageVersion"
Write-Output "Removing $($PackageName) from $($path)."
Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue