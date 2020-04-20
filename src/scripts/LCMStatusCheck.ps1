<#
    .SYNOPSIS
        Build pipeline utility script for checking DSC node status.

    .DESCRIPTION
        Build pipeline utility script for checking DSC node status.

    .PARAMETER ComputerName
        Computer name to test.
        Example: 'DSC-Client01'
        Required: True
        Type: String
        Parameter Sets: All
        Position: Named
        Default Value: none
        Accept pipeline input: False
        Accept wildcard characters: False

    .EXAMPLE
        PS C:\> LCMStatusCheck.ps1 -ComputerName "MyNode"

        Runs the script and checks the specified DSC node for the LCM configuration status.

    .INPUTS

    .OUTPUTS

    .NOTES
        Author: Mike Nickerson

    .LINK
        https://docs.microsoft.com/en-us/powershell/scripting/dsc/pull-server/update-nodes-manually?view=powershell-7

    .LINK
        https://docs.microsoft.com/en-us/powershell/scripting/dsc/managing-nodes/metaconfig?view=powershell-7
#>

[cmdletbinding()]
param (
    [parameter(Mandatory = $true)]
    [string]$ComputerName = $env:COMPUTERNAME
)

$scriptBlock = {
    $currentStatus = Get-DscLocalConfigurationManager

    if (!($currentStatus)) {
        Write-Output "##vso[task.logissue type=error;] Unable to determine the DSC LCM status."
        exit 1
    }
    else {
        if (!($currentStatus.ConfigurationDownloadManagers) -or !($currentStatus.ReportManagers)) {
            Write-Output "The LCM on the client node is not currently configured. "
            Write-Output "Running the LCM configuration script. "
            . "C:\Temp\LCMConfiguration.ps1" -PullServerName $env:PullServer -RegKey $env:DSCRegKey -Verbose
        }
        else {
            try {
                Write-Output "The client node LCM is currently configured."
                Write-Output "Attempting to update the currently applied DSC configurations."
                do {
                    Start-Sleep -Seconds 30
                }
                while (
                    (Get-DscLocalConfigurationManager).LCMState -ne "Idle"
                )
                Update-DscConfiguration -Wait -Verbose
            }
            catch {
                $_.Exception.Message
            }
        }
    }
}

Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock
