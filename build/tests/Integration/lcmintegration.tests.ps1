####################################################################
# Integration tests for DSC Configurations
####################################################################

#Requires -Modules @{ ModuleName="Pester";ModuleVersion="4.10.1" }, @{ ModuleName="poshspec";ModuleVersion="2.2.8" }

[cmdletbinding()]
param (
    [parameter()]
    [string]$ComputerName,

    [parameter()]
    [string]$AdminName = $env:LocalAdmin_Name,

    [parameter()]
    [string]$GuestName = $env:LocalGuest_Name,

    [parameter()]
    [string]$DSCPullServer = $env:DSCPullServerTest
)

$psSession = New-PSSession -ComputerName $vm
$cimSession = New-CimSession -ComputerName $vm
$LCM = Get-DscLocalConfigurationManager -CimSession $cimSession

Context -Name "Local Configuration Manager Settings" {

    It -Name "Refresh Mode is Pull" {
        $LCM.RefreshMode | Should -Be "Pull"
    }

    It -Name "Configuration Mode is ApplyAndAutoCorrect" {
        $LCM.ConfigurationMode | Should -Be "ApplyAndAutoCorrect"
    }

    It -Name "Reboot Node If Needed is Enabled" {
        $LCM.RebootNodeIfNeeded | Should -Be $true
    }

    It -Name "Pull Server URL is $($DSCPullServer)" {
        $LCM.ConfigurationDownloadManagers.ServerURL | Should -Be "https://$($DSCPullServer):8080/PSDSCPullserver.svc"
    }
}

$configs = @()
foreach ($config in $LCM.ConfigurationDownloadManagers.ConfigurationNames) {
    $configs += $config
}

Write-Host "##vso[task.setvariable variable=configs]$configs"

Get-CimSession -Name $cimSession.Name | Remove-CimSession -Confirm:$false
Get-PSSession -Name $psSession.Name | Remove-PSSession -Confirm:$false