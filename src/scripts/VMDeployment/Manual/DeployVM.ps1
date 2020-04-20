<#
    .SYNOPSIS
        Provisions a new VM in Microsoft System Center Virtual Machine Manager.

    .DESCRIPTION
        The various user-provided parameters enable the script to construct a computer name that is then checked against Active Directory and the current VM inventory in System Center Virtual Machine Manager for uniqueness. A new VM is then provisioned based on the user's choices for OS, server type, audience and operating environment.

    .PARAMETER ServerType
        The intended purpose for the new VM.
        Example: 'Web Server (IIS)'
        Required: False
        Type: String
        Parameter Sets: All
        Position: Named
        Default Value: none
        Accept pipeline input: False
        Accept wildcard characters: False

    .PARAMETER GuestOS
        The Windows edition/version for the new VM.
        Example: 'Windows Server 2016 Datacenter'
        Required: False
        Type: String
        Parameter Sets: All
        Position: Named
        Default Value: none
        Accept pipeline input: False
        Accept wildcard characters: False

    .PARAMETER UI
        The Windows user interface experience for the new VM. (GUI or CORE)
        Example: 'CORE'
        Required: False
        Type: String
        Parameter Sets: All
        Position: Named
        Default Value: none
        Accept pipeline input: False
        Accept wildcard characters: False

    .PARAMETER HardwareProfile
        The hardware profile that VMM will use to provision the required number of virtual CPUs and RAM, etc.
        Example: '4 vCPU - 16 GB RAM'
        Required: False
        Type: String
        Parameter Sets: All
        Position: Named
        Default Value: none
        Accept pipeline input: False
        Accept wildcard characters: False

    .PARAMETER VMMServerName
        The name of the System Center Virtual Machine Manager server.
        Example: 'vmmserver01.domain.corp'
        Required: False
        Type: String
        Parameter Sets: All
        Position: Named
        Default Value: none
        Accept pipeline input: False
        Accept wildcard characters: False

    .PARAMETER DSCPullServer
        FQDN for the DSC pull server.
        Example: 'dscpullserver.corp.local'
        Required: False
        Type: String
        Parameter Sets: All
        Position: Named
        Default Value: none
        Accept pipeline input: False
        Accept wildcard characters: False

    .PARAMETER isoGUID
        The VMM-assgined GUID for the SQL ISO stored in the VMM library.
        Example: 'bf168358-5feb-44cb-b89d-50ba96c423b5'
        Required: False
        Type: String
        Parameter Sets: All
        Position: Named
        Default Value: none
        Accept pipeline input: False
        Accept wildcard characters: False

    .PARAMETER LocalAdminPwd
        The password for the local administrator account.
        Required: False
        Type: SecureString
        Parameter Sets: All
        Position: Named
        Default Value: none
        Accept pipeline input: False
        Accept wildcard characters: False

    .PARAMETER LocalGuestPwd
        The password for the local guest account.
        Required: False
        Type: SecureString
        Parameter Sets: All
        Position: Named
        Default Value: none
        Accept pipeline input: False
        Accept wildcard characters: False

    .PARAMETER VMName
        A name for the new VM.
        Example: 'Server01'
        Required: False
        Type: String
        Parameter Sets: All
        Position: Named
        Default Value: none
        Accept pipeline input: False
        Accept wildcard characters: False

    .PARAMETER RepoURL
        The URL for the NuGet or Azure DevOps Artifacts repository containing packages to be installed on the new VM.
        Required: False
        Type: String
        Parameter Sets: All
        Position: Named
        Default Value: none
        Accept pipeline input: False
        Accept wildcard characters: False

    .EXAMPLE
        PS C:\> VM_Deployment.ps1
        Values for the required parameters can be passed in from the "Initiate_Deployment.ps1" script or manually on the command line.

        The new VM name will be created based on the following model:

        $ServerType+$Audience+$Environment+2-DigitNumber

        The deployment script will check Active Directory and VMM to see if the new name based on that combination is available. The result would be similar to "WEBEPROD01" for a production web server in the public-facing corporate DMZ, for example. Combining the different elements in this fashion, with values that meet the company's needs and standards, ensures the name is both descriptive and unique.

    .INPUTS
        None

    .OUTPUTS
        None

    .NOTES
        Important: Some parameter values presented in this script may be examples only and should be changed before this script is used in a testing or production scenario. Carefully review all configuration values before deployment.

        The VM deployment process initiated by this script requires the use of Microsoft System Center Virtual Machine Manager for VM provisioning.

        The ActiveDirectory and VirtualMachineManager PowerShell modules are required to use this script.

        Author: Mike Nickerson
#>

#Requires -Module 'ActiveDirectory','virtualmachinemanager'

[cmdletbinding()]
param (

    [parameter(HelpMessage = "The intended purpose for the new VM.")]
    [string]$ServerType,

    [parameter(HelpMessage = "The Windows edition/version for the new VM.")]
    [string]$GuestOS,

    [parameter(HelpMessage = "The Windows user interface experience for the new VM. (GUI or CORE)")]
    [string]$UI,

    [parameter(HelpMessage = "The hardware profile that VMM will use to provision the required number of virtual CPUs and RAM, etc.")]
    [string]$HardwareProfile,

    [parameter(HelpMessage = "The name of the System Center Virtual Machine Manager server.")]
    [string]$VMMServerName,

    [parameter(HelpMessage = "The VMM-assgined GUID for the SQL ISO stored in the VMM library.")]
    [string]$isoGUID = "bf168358-5feb-44cb-b89d-50ba96c423b5",

    [parameter(HelpMessage = "The password for the local administrator account.")]
    [securestring]$LocalAdminPwd,

    [parameter(HelpMessage = "The password for the local guest account.")]
    [securestring]$LocalGuestPwd,

    [parameter(HelpMessage = "A name for the new VM.")]
    [string]$VMName,

    [parameter(HelpMessage = "The FQDN for the DSC pull server.")]
    [string]$DSCPullServer,

    [parameter(HelpMessage = "The URL for the NuGet or Azure DevOps Artifacts repository containing packages to be installed on the new VM.")]
    [string]$RepoURL
)

#* Generate new VM name and define required variables
#? Server Type
switch ($ServerType) {
    "Web Server (IIS)" { $type = "WEB" }
    "Database Server" { $type = "SQL" }
    "File Server" { $type = "FIL" }
    "Email Server" { $type = "EML" }
    "Application Server" { $type = "APP" }
    "Test Server" { $type = "TST" }
    "DSC" { $type = "DSC" }
    default { $type = 'TST' }
}

#? GuestOS
switch ($GuestOS) {
    'Windows Server 2016 Standard' {
        $OS = "2016-STD"
        $OSID = "b808453f-f2b5-451f-894f-001c49db255a"
        $osProfile = "Windows Server 2016 Standard"
    }
    'Windows Server 2016 Datacenter' {
        $OS = "2016-DC"
        $OSID = "0a393d1e-9050-4142-8e55-a86e4a555013"
        $osProfile = "Windows Server 2016 Datacenter"
    }
    'Windows Server 2019 Standard' {
        $OS = "2019-STD"
        $OSID = "dffb90ce-abb0-4082-8764-fb08db195c05"
        $osProfile = "Windows Server 2019 Standard"
    }
    'Windows Server 2019 Datacenter' {
        $OS = "2019-DC"
        $OSID = "71e6f97d-724e-4943-9113-fd69a04e6eaa"
        $osProfile = "Windows Server 2019 Datacenter"
    }
    default {
        $OS = "2019-STD"
        $OSID = "dffb90ce-abb0-4082-8764-fb08db195c05"
        $osProfile = "Windows Server 2019 Standard"
    }
}

#? AD Computer properties splat
$adcompData = @{
    Filter     =
    "Name -like '$($VMName)*'"
    Properties =
    "Name"
}

$comps = Get-ADComputer @adcompData
$vmmServer = Get-SCVMMServer -ComputerName $VMMServerName -ForOnBehalfOf
$existingVMs = Get-SCVirtualMachine -VMMServer $vmmServer | Where-Object { $_.Name -like "*$($VMName)*" } | Select-Object Name -ExpandProperty Name

if (!($comps)) {
    Write-Output "No existing Active Directory computer objects found with the name $($VMName). Checking VMM..."
    if (!($existingVMs)) {
        Write-Output "No existing VM with the name $($VMName) was found in VMM. Continuing with deployment..."
    }
    else {
        Write-Warning "An existing VM with the name $($VMName) was found in VMM. Aborting deployment."
        exit 1
    }
}
else {
    Write-Warning "An existing computer object with the name $($VMName) was found in Active Directory. Aborting deployment."
    exit 1
}

#? Get the correct VHDX for the selected OS
$vhdx0 = Get-SCVirtualHardDisk -VMMServer $vmmServer -Name ("$($OS)-$($UI).vhdx")

$vmNet = Get-SCVMNetwork

#? Get the required unattend/answer file
if ($ServerType -eq "DSC") {
    # Places the computer object in a special AD OU that prevents application of existing GPOs
    $answerFile = Get-SCScript -Name "dsc_unattend.xml"
}
else {
    $answerFile = Get-SCScript -Name "gen_unattend.xml"
}

#? Get the VMM Guest OS Template for the requested OS
$guestOSProfile = Get-SCGuestOSProfile -Name $osProfile
#? Get the requested hardware profile
$hwProfile = Get-SCHardwareProfile | Where-Object { $_.Name -eq $HardwareProfile }
#? Get the Hyper-V capability profile
$capabilityProfile = Get-SCCapabilityProfile -Name "Hyper-V"
#? Set the virtual CPU specifications
$CPUType = Get-SCCPUType | Where-Object { $_.Name -eq "3.60 GHz Xeon (2 MB L2 cache)" }
#? Set the VM's operating system parameter
$operatingSystem = Get-SCOperatingSystem -ID $OSID
#? Set the destination cloud (customize for environments with multiple clouds)
$vmmCloud = Get-SCCloud -VMMServer $vmmServer

#? Create GUIDs and names for temporary templates and profiles
$jobGroup1GUID = [GUID]::NewGuid().ToString()
$tempProfileName = "Profile" + ([GUID]::NewGuid().ToString())
$tempTemplateName = "Temporary Template" + ([GUID]::NewGuid().ToString())
$buildJobGUID = [GUID]::NewGuid().ToString()

#? Create the virtual NIC profile
New-SCVirtualNetworkAdapter -JobGroup $jobGroup1GUID -MACAddress "00:00:00:00:00:00" -MACAddressType Static -Synthetic -EnableVMNetworkOptimization $false -EnableMACAddressSpoofing $false -EnableGuestIPNetworkVirtualizationUpdates $false -IPv4AddressType Dynamic -IPv6AddressType Dynamic -VMNetwork $vmNet
#? Create the temporary hardware profile
New-SCHardwareProfile -CPUType $CPUType -Name $tempProfileName -HardwareProfile $hwProfile -Description "Temporary Profile used to create a VM/Template" -SecureBootEnabled $true -SecureBootTemplate "MicrosoftWindows" -CapabilityProfile $capabilityProfile -Generation 2 -JobGroup $jobGroup1GUID
$tempHardware = Get-SCHardwareProfile | Where-Object { $_.Name -eq "$tempProfileName" }
#? Create the temporary VM template
New-SCVMTemplate -Name $tempTemplateName -VirtualHardDisk $vhdx0 -HardwareProfile $tempHardware -GuestOSProfile $guestOSProfile -JobGroup $buildJobGUID -ComputerName $VMName -TimeZone 35 -AnswerFile $answerFile -MergeAnswerFile $false -OperatingSystem $operatingSystem
$newTemplate = Get-SCVMTemplate -All | Where-Object { $_.Name -eq "$tempTemplateName" }
if ($type -eq "SQL") {
    $vhdx1 = Get-SCVirtualHardDisk -VMMServer $vmmServer -Name "SQL_1_B.vhdx" #? SQL Backup Drive
    $vhdx2 = Get-SCVirtualHardDisk -VMMServer $vmmServer -Name "SQL_2_E.vhdx" #? SQL DB Drive
    $vhdx3 = Get-SCVirtualHardDisk -VMMServer $vmmServer -Name "SQL_3_L.vhdx" #? SQL Logfile Drive
    $vhdx4 = Get-SCVirtualHardDisk -VMMServer $vmmServer -Name "SQL_4_S.vhdx" #? SQL Shared Drive
    $vhdx5 = Get-SCVirtualHardDisk -VMMServer $vmmServer -Name "SQL_5_T.vhdx" #? SQL TempDB Drive
    $iso = Get-SCISO -ID $isoGUID
    New-SCVirtualDiskDrive -VMTemplate $newTemplate -SCSI -Bus 0 -LUN 1 -VirtualHardDisk $vhdx1
    New-SCVirtualDiskDrive -VMTemplate $newTemplate -SCSI -Bus 0 -LUN 2 -VirtualHardDisk $vhdx2
    New-SCVirtualDiskDrive -VMTemplate $newTemplate -SCSI -Bus 0 -LUN 3 -VirtualHardDisk $vhdx3
    New-SCVirtualDiskDrive -VMTemplate $newTemplate -SCSI -Bus 0 -LUN 4 -VirtualHardDisk $vhdx4
    New-SCVirtualDiskDrive -VMTemplate $newTemplate -SCSI -Bus 0 -LUN 5 -VirtualHardDisk $vhdx5
    New-SCVirtualDVDDrive -VMTemplate $newTemplate -Bus 0 -LUN 6 -ISO $iso
}
$virtualMachineConfiguration = New-SCVMConfiguration -VMTemplate $newTemplate -Name $VMName

#* Create the new virtual machine
New-SCVirtualMachine -Name $VMName -ComputerName $VMName -VMConfiguration $virtualMachineConfiguration -Cloud $vmmCloud -JobGroup $buildJobGUID -StartAction "TurnOnVMIfRunningWhenVSStopped" -StopAction "SaveVM" -StartVM -Verbose

#* Cleanup
Get-SCHardwareProfile -VMMServer $vmmServer | Where-Object { $_.Description -eq "Temporary Profile used to create a VM/Template" } | Remove-SCHardwareProfile -Confirm:$false

#* Get the properties of the new VM
$newVM = Get-SCVirtualMachine -Name $VMName

$vmProps = @(
    [PSCustomObject]@{Name = "Server Type"; Value = $ServerType }
    [PSCustomObject]@{Name = "Operating System"; Value = $GuestOS }
    [PSCustomObject]@{Name = "UI Type"; Value = $UI }
    [PSCustomObject]@{Name = "Hardware Profile"; Value = $HardwareProfile }
)

#* Set the custom property values for the new VM in VMM
try {
    foreach ($obj in $vmProps) {
        Set-SCCustomPropertyValue -InputObject $newVM -CustomProperty (Get-SCCustomProperty -Name $obj.Name) -Value $obj.Value -RunAsynchronously
    }
}
catch {
    $_.Exception.Message
}

$parameters = @{
    ServerType      = $ServerType
    GuestOS         = $GuestOS
    UI              = $UI
    HardwareProfile = $HardwareProfile
    LocalAdminPwd   = $LocalAdminPwd
    LocalGuestPwd   = $LocalGuestPwd
    VMName          = $VMName
    DSCPullServer   = $DSCPullServer
}

& $PSScriptRoot\ConfigVM.ps1 @parameters
