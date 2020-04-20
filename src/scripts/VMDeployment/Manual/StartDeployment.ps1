<#
    .SYNOPSIS
        Starts a VM deployment process.

    .DESCRIPTION
        This script will gather user input using a multiple choice GUI form, allowing the user to choose the parameters required for VM creation.  Additionally, the user is able to choose the domain, audience, general usage environment and hardware profile for the new VM.

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
        PS C:\> Initiate_Deployment.ps1
        This example will start the script from a PowerShell command line and will present a GUI Windows form with several combo boxes and text boxes. The new VM will be named and created based on the choices made in this form.

    .INPUTS
        None

    .OUTPUTS
        None

    .NOTES
        Important: Some parameter values presented in this script may be examples only and should be changed before this script is used in a testing or production scenario. Carefully review all configuration values before deployment.

        The VM deployment process initiated by this script requires the use of Microsoft System Center Virtual Machine Manager for VM provisioning.

        The PSMenus PowerShell module is required to use this script.

        Author: Mike Nickerson
#>

#Requires -Module 'PSMenus'

[cmdletbinding()]
param (

    [parameter(HelpMessage = "The name of the System Center Virtual Machine Manager server.")]
    [string]$VMMServerName,

    [parameter(HelpMessage = "The intended purpose for the new VM.")]
    [string]$ServerType,

    [parameter(HelpMessage = "The Windows edition/version for the new VM.")]
    [string]$GuestOS,

    [parameter(HelpMessage = "The hardware profile that VMM will use to provision the required number of virtual CPUs and RAM, etc.")]
    [string]$HardwareProfile,

    [parameter(HelpMessage = "A name for the new VM.")]
    [string]$VMName,

    [parameter(HelpMessage = "FQDN for the DSC pull server.")]
    [string]$DSCPullServer,

    [parameter(HelpMessage = "The URL for the NuGet or Azure DevOps Artifacts repository containing packages to be installed on the new VM.")]
    [string]$RepoURL
)

# Create lists for combo boxes
$servTypeList = @(
    "Web Server (IIS)",
    "Database Server",
    "File Server",
    "Email Server",
    "Application Server",
    "Test Server",
    "DSC"
)

$guestOSList = @(
    "Windows Server 2016 Standard",
    "Windows Server 2016 Datacenter",
    "Windows Server 2019 Standard",
    "Windows Server 2019 Datacenter"
)

$UIlist = @(
    "CORE",
    "GUI"
)

$hardwareProfileList = @(
    "Hardware_Profile_2vCPU_8GB",
    "Hardware_Profile_4vCPU_8GB",
    "Hardware_Profile_4vCPU_16GB"
)

# Create the new form
$buttons = Set-OkCancelButtonPanel
$okButtonObj = $Buttons.Controls | Where-Object { $_.Name -eq "OkButton" }
$cancelButtonObj = $Buttons.Controls | Where-Object { $_.Name -eq "CancelButton" }

# Create the combo boxes for user input of params
# comboBox1
$comboBoxLabel1 = Set-TextLabel -Message "Application Type" -Name "comboBoxLabel1" -LocX 10 -LocY 40
$comboBox1 = Set-ComboBox -Name "comboBox1" -ListItems $servTypeList -LocX 130 -LocY 40 -SizeX 250

# comboBox2
$comboBoxLabel2 = Set-TextLabel -Message "Operating System" -Name "comboBoxLabel2" -LocX 10 -LocY 70
$comboBox2 = Set-ComboBox -Name "comboBox2" -ListItems $guestOSList -LocX 130 -LocY 70 -SizeX 250

# comboBox3
$comboBoxLabel3 = Set-TextLabel -Message "Hardware Profile" -Name "comboBoxLabel3" -LocX 10 -LocY 100
$comboBox3 = Set-ComboBox -Name "comboBox3" -ListItems $hardwareProfileList -LocX 130 -LocY 100 -SizeX 250

# comboBox4
$comboBoxLabel4 = Set-TextLabel -Message "UI Type" -Name "comboBoxLabel4" -LocX 10 -LocY 130
$comboBox4 = Set-ComboBox -Name "comboBox4" -ListItems $uiList -LocX 130 -LocY 130 -SizeX 250

# TextBox1
$textBoxLabel1 = Set-TextLabel -Message "VM Name" -Name "TextBoxLabel1" -LocX 10 -LocY 200
$textBox1 = Set-TextBox -Name "TextBox1" -LocX 130 -LocY 200 -SizeX 250

# TextBox2
$textBoxLabel2 = Set-TextLabel -Message "Local Admin Password" -Name "TextBoxLabel2" -LocX 10 -LocY 230
$textBox2 = Set-TextBox -Name "TextBox2" -LocX 130 -LocY 230 -SizeX 250

# TextBox3
$textBoxLabel3 = Set-TextLabel -Message "Local Guest Password" -Name "TextBoxLabel3" -LocX 10 -LocY 260
$textBox3 = Set-TextBox -Name "TextBox3" -LocX 130 -LocY 260 -SizeX 250

# TextBox4
$textBoxLabel4 = Set-TextLabel -Message "VMM Server Name" -Name "TextBoxLabel4" -LocX 10 -LocY 290
$textBox4 = Set-TextBox -Name "TextBox4" -LocX 130 -LocY 290 -SizeX 250

# TextBox5
$textBoxLabel5 = Set-TextLabel -Message "DSC Pull Server" -Name "TextBoxLabel5" -LocX 10 -LocY 320
$textBox5 = Set-TextBox -Name "TextBox5" -LocX 130 -LocY 320 -SizeX 250

# TextBox6
$textBoxLabel6 = Set-TextLabel -Message "Repository URL" -Name "TextBoxLabel6" -LocX 10 -LocY 350
$textBox6 = Set-TextBox -Name "TextBox6" -LocX 130 -LocY 350 -SizeX 250

# Form
$formLabel = Set-TextLabel -Message "Please make your selections below" -Name "FormLabel" -LocX 10 -LocY 10
$form = Set-WindowsForm -Message $formLabel -WindowTitle "VM Deployment" -Buttons $Buttons -SizeX 450 -SizeY 500

$form.Controls.Add($comboBoxLabel1)
$form.Controls.Add($comboBox1)
$form.Controls.Add($comboBoxLabel2)
$form.Controls.Add($comboBox2)
$form.Controls.Add($comboBoxLabel3)
$form.Controls.Add($comboBox3)
$form.Controls.Add($comboBoxLabel4)
$form.Controls.Add($comboBox4)
$form.Controls.Add($textBoxLabel1)
$form.Controls.Add($textBox1)
$form.Controls.Add($textBoxLabel2)
$form.Controls.Add($textBox2)
$form.Controls.Add($textBoxLabel3)
$form.Controls.Add($textBox3)
$form.Controls.Add($textBoxLabel4)
$form.Controls.Add($textBox4)
$form.Controls.Add($textBoxLabel5)
$form.Controls.Add($textBox5)
$form.Controls.Add($textBoxLabel6)
$form.Controls.Add($textBox6)
$form.Controls.Add($buttons)
$form.AcceptButton = $okButtonObj
$form.CancelButton = $cancelButtonObj

$result = $form.ShowDialog()

if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
    $ServerType = $comboBox1.SelectedItem
    $GuestOS = $comboBox2.SelectedItem
    $HardwareProfile = $comboBox3.SelectedItem
    $UI = $comboBox4.SelectedItem
    $VMName = $textBox1.Text
    $LocalAdminPwd = $textBox2.Text
    #TODO Change to using secure pipeline variable
    #$LocalAdminPwd = ConvertTo-SecureString $LocalAdminPwd -AsPlainText -Force
    $LocalGuestPwd = $textBox3.Text
    #TODO Change to using secure pipeline variable
    #$LocalGuestPwd = ConvertTo-SecureString $LocalGuestPwd -AsPlainText -Force
    $VMMServerName = $textBox4.Text
    $DSCPullServer = $textBox5.Text
    $RepoURL = $textBox6.Text

    $parameters = @{
        ServerType      = $ServerType
        GuestOS         = $GuestOS
        UI              = $UI
        HardwareProfile = $HardwareProfile
        VMName          = $VMName
        LocalAdminPwd   = $LocalAdminPwd
        LocalGuestPwd   = $LocalGuestPwd
        VMMServerName   = $VMMServerName
        DSCPullServer   = $DSCPullServer
        RepoURL         = $RepoURL
    }

    & $PSScriptRoot\DeployVM.ps1 @parameters
}
else {
    Write-Output "User Cancelled..."
}
