<#
    .SYNOPSIS
        Compiles DSC configuration documents (MOF files).

    .DESCRIPTION
        This script will compile DSC configuration MOF files and place them in the appropriate folder on the DSC pull server. This sript is designed to be run from an Azure DevOps Pipeline task.

    .PARAMETER SourcePath
        The path to one or more DSC configuration scripts.
        Example: 'D:\configs'
        Required: False
        Type: String
        Parameter Sets: All
        Position: Named
        Default Value: none
        Accept pipeline input: False
        Accept wildcard characters: False

    .PARAMETER Destination
        The output path for the compiled MOF files.
        Example: 'D:\configs'
        Required: False
        Type: String
        Parameter Sets: All
        Position: Named
        Default Value: none
        Accept pipeline input: False
        Accept wildcard characters: False

    .EXAMPLE
        PS C:\> CompileMOFs.ps1 -SourcePath "C:\Temp\DSC" -Destination "C:\Temp\MOFs"

        This example will process any DSC configuration scripts found in the specified source path and output the compiled MOF files and checksums to the output path.

    .INPUTS

    .OUTPUTS

    .NOTES
        Author: Mike Nickerson

    .LINK
        https://docs.microsoft.com/en-us/powershell/scripting/dsc/configurations/write-compile-apply-configuration?view=powershell-7
#>

[cmdletbinding()]
param (
    [parameter(HelpMessage = "The path to one or more DSC configuration scripts.")]
    [string]$SourcePath,

    [parameter(HelpMessage = "The output path for the compiled MOF files.")]
    [string]$Destination,

    [parameter()]
    [string]$AdminName,

    [parameter()]
    [string]$GuestName
)

$scripts = Get-ChildItem -Path $SourcePath -Filter "*.ps1" -Recurse

foreach ($obj in $scripts) {
    if ($obj.Name -like "*SQL*") {
        $configName = $obj.Name -replace (".ps1","")
        try {
            Remove-Item "$($Destination)\$($configName).mof" -Force -Recurse -Verbose -ErrorAction SilentlyContinue
            $sqlServicePwd = ConvertTo-SecureString -String $env:SQL_SERVICE_PWD -AsPlainText -Force
            $creds = New-Object System.Management.Automation.PSCredential($env:SQLServiceAccountName, $sqlServicePwd)
            . $obj.FullName -SqlServiceCred $creds -AgtServiceCred $creds -SysAdmins "Domain Admins" -Destination $Destination
        }
        catch {
            $_.Exception.Message
            Write-Host "##vso[task.logissue type=error;] Unable to compile the MOF file for the $($configName) config."
            exit 1
        }
    }
    elseif ($obj.Name -like "*BaseOS*") {
        $configName = "WindowsBaseOS"
        try {
            Remove-Item "$($Destination)\$($configName).mof" -Force -Recurse -Verbose -ErrorAction SilentlyContinue
            . $obj.FullName -AdminName $AdminName -GuestName $GuestName -Destination $Destination
        }
        catch {
            $_.Exception.Message
            Write-Host "##vso[task.logissue type=error;] Unable to compile the MOF file for the $($configName) config."
            exit 1
        }
    }
    else {
        $configName = $obj.Name -replace (".ps1","")
        try {
            Remove-Item "$($Destination)\$($configName).mof" -Force -Recurse -Verbose -ErrorAction SilentlyContinue
            . $obj.FullName -Destination $Destination
        }
        catch {
            $_.Exception.Message
            Write-Host "##vso[task.logissue type=error;] Unable to compile the MOF file for the $($configName) config."
            exit 1
        }
    }
}
