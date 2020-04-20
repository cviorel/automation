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

    .PARAMETER UI
        The user interface type for the new VM.
        Example: 'GUI'
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

    .PARAMETER AdminName
        The name that will be used to rename the built-in Administrator account on domain memeber servers.
        Required: False
        Type: String
        Parameter Sets: All
        Position: Named
        Default Value: none
        Accept pipeline input: False
        Accept wildcard characters: False

    .PARAMETER GuestName
        The name that will be used to rename the built-in Guest account on domain memeber servers.
        Required: False
        Type: String
        Parameter Sets: All
        Position: Named
        Default Value: none
        Accept pipeline input: False
        Accept wildcard characters: False

    .PARAMETER AdminPwd
        The password for the local administrator account.
        Required: False
        Type: SecureString
        Parameter Sets: All
        Position: Named
        Default Value: none
        Accept pipeline input: False
        Accept wildcard characters: False

    .PARAMETER GuestPwd
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

    .PARAMETER DSCRegKey
        The GUID key for registering clients with the DSC pull server.
        Example: 'dscpullserver.corp.local'
        Required: False
        Type: String
        Parameter Sets: All
        Position: Named
        Default Value: none
        Accept pipeline input: False
        Accept wildcard characters: False

    .PARAMETER RepoURL1
        The URL for the NuGet or Azure DevOps Artifacts repository containing packages to be installed on the new VM.
        Required: False
        Type: String
        Parameter Sets: All
        Position: Named
        Default Value: none
        Accept pipeline input: False
        Accept wildcard characters: False

    .PARAMETER RepoName1
        The name of the NuGet or Azure DevOps Artifacts repository containing packages to be installed on the new VM.
        Required: False
        Type: String
        Parameter Sets: All
        Position: Named
        Default Value: none
        Accept pipeline input: False
        Accept wildcard characters: False

    .PARAMETER RepoURL2
        The URL for the NuGet or Azure DevOps Artifacts repository containing packages to be installed on the new VM.
        Required: False
        Type: String
        Parameter Sets: All
        Position: Named
        Default Value: none
        Accept pipeline input: False
        Accept wildcard characters: False

    .PARAMETER RepoName2
        The name of the NuGet or Azure DevOps Artifacts repository containing packages to be installed on the new VM.
        Required: False
        Type: String
        Parameter Sets: All
        Position: Named
        Default Value: none
        Accept pipeline input: False
        Accept wildcard characters: False

    .PARAMETER RepoPAT
        Personal Access Token for authenticating with the specified repos.
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

#Requires -Module 'virtualmachinemanager'

[cmdletbinding()]
param (

    [parameter(HelpMessage = "The intended purpose for the new VM.")]
    [string]$ServerType,

    [parameter(HelpMessage = "The Windows edition/version for the new VM.")]
    [string]$GuestOS,

    [parameter(HelpMessage = "The user interface type for the new VM.")]
    [string]$UI,

    [parameter(HelpMessage = "The hardware profile that VMM will use to provision the required number of virtual CPUs and RAM, etc.")]
    [string]$HardwareProfile,

    [parameter(HelpMessage = "The name that will be used to rename the built-in Administrator account on domain memeber servers.")]
    [string]$AdminName,

    [parameter(HelpMessage = "The name that will be used to rename the built-in Guest account on domain memeber servers.")]
    [string]$GuestName,

    [parameter(HelpMessage = "A name for the new VM.")]
    [string]$VMName,

    [parameter(HelpMessage = "FQDN for the DSC pull server.")]
    [string]$DSCPullServer,

    [parameter(HelpMessage = "The GUID key for registering clients with the DSC pull server.")]
    [string]$DSCRegKey,

    [parameter(HelpMessage = "The URL for the NuGet or Azure DevOps Artifacts repository containing packages to be installed on the new VM.")]
    [string]$RepoURL1,

    [parameter(HelpMessage = "The name of the NuGet or Azure DevOps Artifacts repository containing packages to be installed on the new VM.")]
    [string]$RepoName1,

    [parameter(HelpMessage = "The URL for the NuGet or Azure DevOps Artifacts repository containing packages to be installed on the new VM.")]
    [string]$RepoURL2,

    [parameter(HelpMessage = "The name of the NuGet or Azure DevOps Artifacts repository containing packages to be installed on the new VM.")]
    [string]$RepoName2
)

#region VM Configuration

do {
    Write-Output "Starting sleep..."
    Start-Sleep -Seconds 10
}
until (
    Test-WSMan -ComputerName $VMName -ErrorAction SilentlyContinue
)

$scriptBlock = {
    Set-ExecutionPolicy Bypass -Scope Process -Force -Verbose
    function Start-Logging {

        [cmdletbinding()]
        param (
            [parameter()]
            [string]$Destination = "$($env:SystemDrive)\Temp\Logs",

            [parameter()]
            [string]$TaskName
        )

        begin {
            $TimeStamp = Get-Date -Format "yyyy-MM-dd-HHmmss"
        }
        process {
            try {
                Start-Transcript -Path "$($Destination)\$($env:COMPUTERNAME)-$($TaskName)-$($TimeStamp).log" -Force
            }
            catch {
                $_.Exception.Message
            }
        }
        end {

        }
    }

    #region Set Variables and Other Parameters

    $ServerType = $using:ServerType
    $GuestOS = $using:GuestOS
    $UI = $using:UI
    $HardwareProfile = $using:HardwareProfile
    $GuestName = $using:GuestName
    $GuestPWD = $env:LOCALGUEST_PWD
    $AdminName = $using:AdminName
    $AdminPwd = $env:LOCALADMIN_PWD
    $RepoName1 = $using:RepoName1
    $RepoURL1 = $using:RepoURL1
    $RepoName2 = $using:RepoName2
    $RepoURL2 = $using:RepoURL2
    $DSCPullServer = $using:DSCPullServer
    $DSCRegKey = $using:DSCRegKey

    $newKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\VMProps"
    $vmProps = @(
        [PSCustomObject]@{Name = "Server Type"; Value = $ServerType }
        [PSCustomObject]@{Name = "Operating System"; Value = $GuestOS }
        [PSCustomObject]@{Name = "UI Type"; Value = $UI }
        [PSCustomObject]@{Name = "Hardware Profile"; Value = $HardwareProfile }
    )

    $protocols = [System.Net.SecurityProtocolType]'TLS,TLS11,TLS12'
    [System.Net.ServicePointManager]::SecurityProtocol = $protocols

    if (!(Test-Path -Path "$($env:SystemDrive)\Temp")) {
        New-Item -Path "$($env:SystemDrive)\Temp" -ItemType Directory -Force -Verbose
    }
    else {
        if (!(Test-Path -Path "$($env:SystemDrive)\Temp\Logs")) {
            New-Item -Path "$($env:SystemDrive)\Temp\Logs" -ItemType Directory -Force -Verbose
        }
    }

    #endregion Set Variables and Other Parameters

    #region Set Registry Keys

    Start-Logging -TaskName "SetRegistryKeys"

    try {
        New-Item -Path $newKeyPath -ItemType Key -Force -Verbose
        foreach ($obj in $vmProps) {
            New-ItemProperty -Path $newKeyPath -Name $obj.Name -Value $obj.Value -Type String -Verbose
        }
    }
    catch {
        Write-Output "Unable to create the registry keys."
        $_.Exception.Message
    }

    Stop-Transcript

    #endregion Set Registry Keys

    #region Setup Local Accounts

    Start-Logging -TaskName "SetupLocalAccounts"

    $locAccts = Get-LocalUser
    $localGuest = $locAccts | Where-Object { $_.SID.Value -like "*-501" }
    $localAdmin = $locAccts | Where-Object { $_.SID.Value -like "*-500" }

    if ($localGuest.Name -ne $GuestName) {
        try {
            Rename-LocalUser -SID $localGuest.SID.Value -NewName $GuestName -Confirm:$false -Verbose
        }
        catch {
            $_.Exception.Message
        }
        finally {
            Set-LocalUser -SID $localGuest.SID.Value -FullName $GuestName -Description "" -Password $GuestPWD -PasswordNeverExpires $true -UserMayChangePassword $false -Confirm:$false -Verbose
            Disable-LocalUser -SID $localGuest.SID.Value -Confirm:$false -Verbose
        }
    }
    elseif ($localGuest.Name -eq $GuestName) {
        try {
            Set-LocalUser -SID $localGuest.SID.Value -FullName $GuestName -Description "" -Password $GuestPWD -PasswordNeverExpires $true -UserMayChangePassword $false -Confirm:$false -Verbose
            Disable-LocalUser -SID $localGuest.SID.Value -Confirm:$false -Verbose
        }
        catch {
            $_.Exception.Message
        }
    }

    if ($localAdmin.Name -ne $AdminName) {
        try {
            Rename-LocalUser -SID $localAdmin.SID.Value -NewName $AdminName -Confirm:$false -Verbose
        }
        catch {
            $_.Exception.Message
        }
        finally {
            Set-LocalUser -SID $localAdmin.SID.Value -FullName $AdminName -Description "" -Password $AdminPwd  -PasswordNeverExpires $true -UserMayChangePassword $true -Confirm:$false -Verbose
            Disable-LocalUser -SID $localAdmin.SID.Value -Confirm:$false -Verbose
        }
    }
    elseif ($localAdmin.Name -eq $AdminName) {
        try {
            Set-LocalUser -SID $localAdmin.SID.Value -FullName $AdminName -Description "" -Password $AdminPwd  -PasswordNeverExpires $true -UserMayChangePassword $true -Confirm:$false -Verbose
            Disable-LocalUser -SID $localAdmin.SID.Value -Confirm:$false -Verbose
        }
        catch {
            $_.Exception.Message
        }
    }

    Stop-Transcript

    #endregion Setup Local Accounts

    #region Setup Applications

    #? Note: This section only applies to VMs that will be SQL or IIS servers
    if ($ServerType -eq "SQL") {
        Start-Logging -TaskName "ApplicationSetup-SQL"
        # Copy SQL DVD to local disk
        Copy-Item -Path "D:\" -Destination "C:\Temp\SQLServer2016" -Recurse -Force -Confirm:$false -Verbose

        try {
            # Configure Disks
            Get-Disk -Number 1 | Initialize-Disk -PartitionStyle GPT -Confirm:$false -Verbose
            Get-Disk -Number 2 | Initialize-Disk -PartitionStyle GPT -Confirm:$false -Verbose
            Get-Disk -Number 3 | Initialize-Disk -PartitionStyle GPT -Confirm:$false -Verbose
            Get-Disk -Number 4 | Initialize-Disk -PartitionStyle GPT -Confirm:$false -Verbose
            Get-Disk -Number 5 | Initialize-Disk -PartitionStyle GPT -Confirm:$false -Verbose

            # Create Volumes
            New-Volume -DiskNumber 1 -FileSystem NTFS -FriendlyName "Backups" -DriveLetter "B" -Verbose
            New-Volume -DiskNumber 2 -FileSystem NTFS -FriendlyName "Data" -DriveLetter "E" -Verbose
            New-Volume -DiskNumber 3 -FileSystem NTFS -FriendlyName "Logs" -DriveLetter "L" -Verbose
            New-Volume -DiskNumber 4 -FileSystem NTFS -FriendlyName "Shared" -DriveLetter "S" -Verbose
            New-Volume -DiskNumber 5 -FileSystem NTFS -FriendlyName "Temp" -DriveLetter "T" -Verbose
        }
        catch {
            Write-Host "##vso[task.logissue type=error;] Unable to configure the drives for SQL."
            $_.Exception.Message
            Stop-Transcript
            exit 1
        }
        Stop-Transcript
    }
    elseif ($ServerType -eq "IIS" -and (Get-WindowsFeature -Name "Web-Server").InstallState -eq "Available") {
        Start-Logging -TaskName "ApplicationSetup-IIS"

        try {
            Install-WindowsFeature -Name Web-Server -IncludeManagementTools -Confirm:$false -Verbose
        }
        catch {
            Write-Host "##vso[task.logissue type=error;] Unable to configure the drives for IIS."
            $_.Exception.Message
            Stop-Transcript
            exit 1
        }
        Stop-Transcript
    }

    #endregion Setup Applications

    #region Install Software Packages

    Start-Logging -TaskName "InstallPackages"

    Write-Host "##[command] Checking for the 'Temp\Packages' folder..."
    if (!(Test-Path -Path "$($env:SystemDrive)\Temp\Packages\")) {
        New-Item -Path "$($env:SystemDrive)\Temp" -Name "Packages" -ItemType Directory -Force -Verbose
    }

    Write-Host "##[command] Registering repositories and package providers..."
    Get-PackageProvider -Name Nuget -ForceBootstrap -Verbose
    Register-PSRepository -Name $RepoName1 -SourceLocation $RepoURL1 -InstallationPolicy Trusted -Verbose
    Register-PSRepository -Name $RepoName2 -SourceLocation $RepoURL2 -InstallationPolicy Trusted -Verbose
    $user = "AzureDevOps"
    $token = $env:Agent_PAT
    $base64auth = [convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $user, $token)))
    $destPath = "C:\temp\Packages"
    $destFile = "chocolatey.0.10.15.zip"
    $dest = "$($destPath)\$($destFile)"

    try {
        Write-Host "##[command] Finding and downloading the Chocolatey package with PowerShell PackageManagement..."
        Find-Package chocolatey -Source $RepoName1 | Save-Package -Path $destPath -Force -Verbose
    }
    catch {
        Write-Host "##vso[task.logissue type=warning;] Downloading with PackageManagement failed."
        Write-Host "##[command] Finding and downloading the Chocolatey package using the ADO Rest API..."
        Invoke-RestMethod -Method Get -Uri $env:PackageURL -OutFile "$($dest)" -Headers @{Authorization = ("Basic {0}" -f $base64auth) } -Verbose
    }
    finally {
        if (Test-Path -Path "$($dest)") {
            try {
                Write-Host "##[command] Expanding the package archive..."
                Expand-Archive -Path "$($dest)" -DestinationPath "$($destPath)\chocolatey" -Force -Verbose
                Write-Host "##[command] Installing Chocolatey..."
                . "C:\temp\Packages\chocolatey\0.10.15\tools\chocolateyInstall.ps1"
                Write-Host "##[command] Having Chocolatey register with itself as a managed package..."
                choco upgrade chocolatey -y
            }
            catch {
                Write-Host "##vso[task.logissue type=warning;] Downloading with PackageManagement failed."
            }
        }
        else {

        }
    }

    # Enable Chocolatey FIPS compliant checksums
    choco feature enable -n useFipsCompliantChecksums

    # Register internal package source, PS repository and Chocolatey source if they do not currently exist
    if (!(Get-PackageSource -Name $RepoName1 -ErrorAction SilentlyContinue) -or !(Get-PackageSource -Name $RepoName2 -ErrorAction SilentlyContinue)) {
        Register-PackageSource -Name "$RepoName1" -Location "$RepoURL1" -ProviderName Nuget -Trusted -Force -Confirm:$false -Verbose
        Register-PackageSource -Name "$RepoName2" -Location "$RepoURL2" -ProviderName Nuget -Trusted -Force -Confirm:$false -Verbose
    }
    if (!(Get-PSRepository -Name $RepoName1 -ErrorAction SilentlyContinue) -or !(Get-PSRepository -Name $RepoName2 -ErrorAction SilentlyContinue)) {
        Register-PSRepository -Name "$RepoName1" -SourceLocation "$RepoURL1" -PackageManagementProvider NuGet -InstallationPolicy Trusted -Verbose
        Register-PSRepository -Name "$RepoName2" -SourceLocation "$RepoURL2" -PackageManagementProvider NuGet -InstallationPolicy Trusted -Verbose
    }
    $chocoSources = choco sources list
    if (!($chocoSources | Where-Object { $_ -like "*$($RepoName1)*" }) -or !($chocoSources | Where-Object { $_ -like "*$($RepoName2)*" })) {
        choco source add -n="$RepoName1" -s="$RepoURL1"
        choco source add -n="$RepoName2" -s="$RepoURL2"
    }

    # Install updated PowerShellGet and PackageManagement PS modules
    #? Required to allow PowerShell package management and NuGet to function with FIPS enabled
    Install-Module -Name PowerShellGet -Force -Scope AllUsers -SkipPublisherCheck -AllowClobber -Verbose

    # Install required software with Chocolatey
    choco install "Pester" --version "4.10.1" -y
    choco install "cmclient" -y

    Stop-Transcript

    #endregion Install Software Packages

    #region DSC Pull Client Config

    Start-Logging -TaskName "DSCPullClientConfig"

    if (!($DSCPullServer)) {
        Write-Warning "DSC Pull Server not specified. Skipping DSC client node configuration..."
        return
    }
    else {
        $ComputerName = $env:COMPUTERNAME
        switch ((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").InstallationType) {
            "Server" { $osConfig = "WindowsGUI" }
            "Server Core" { $osConfig = "WindowsCORE" }
        }

        if (($ServerType -eq "IIS") -or ($ServerType -eq "SQL") -or ($ServerType -eq "DomainController")) {
            $confNames = @("WindowsBaseOS", "$($osConfig)", "$($ServerType)")
            [DSCLocalConfigurationManager()]
            Configuration LCMConfiguration {
                param (
                    [string]$NodeName = $ComputerName
                )
                Node $NodeName {
                    Settings {
                        RefreshMode          = 'Pull'
                        ConfigurationMode    = 'ApplyAndAutoCorrect'
                        RebootNodeIfNeeded   = $true
                        RefreshFrequencyMins = 30
                        AllowModuleOverwrite = $true
                    }
                    ConfigurationRepositoryWeb "PSDSCPullServer" {
                        ServerURL          = "https://$($DSCPullServer):8080/PSDSCPullServer.svc"
                        RegistrationKey    = "$($RegKey)"
                        ConfigurationNames = $confNames
                    }
                    ReportServerWeb "PSDSCReportServer" {
                        ServerURL       = "https://$($DSCPullServer):8080/PSDSCPullServer.svc"
                        RegistrationKey = "$($RegKey)"
                    }
                    PartialConfiguration "WindowsBaseOS" {
                        Description         = "Windows Base Operating System Configuration"
                        ConfigurationSource = @("[ConfigurationRepositoryWeb]PSDSCPullServer")
                    }
                    PartialConfiguration "$($osConfig)" {
                        Description         = "Operating System Installation Type Configuration (GUI or CORE)"
                        ConfigurationSource = @("[ConfigurationRepositoryWeb]PSDSCPullServer")
                        DependsOn           = '[PartialConfiguration]WindowsBaseOS'
                    }
                    PartialConfiguration "$($ServerType)" {
                        Description         = "$($ServerType)-specific Configuration"
                        ConfigurationSource = @("[ConfigurationRepositoryWeb]PSDSCPullServer")
                        DependsOn           = '[PartialConfiguration]WindowsBaseOS'
                    }
                }
            }
        }
        else {
            $confNames = @("WindowsBaseOS", $osConfig)
            [DSCLocalConfigurationManager()]
            Configuration LCMConfiguration {
                param (
                    [string]$NodeName = $ComputerName
                )
                Node $NodeName {
                    Settings {
                        RefreshMode          = 'Pull'
                        ConfigurationMode    = 'ApplyAndAutoCorrect'
                        RebootNodeIfNeeded   = $true
                        RefreshFrequencyMins = 30
                        AllowModuleOverwrite = $true
                    }
                    ConfigurationRepositoryWeb "PSDSCPullServer" {
                        ServerURL          = "https://$($DSCPullServer):8080/PSDSCPullServer.svc"
                        RegistrationKey    = "$($RegKey)"
                        ConfigurationNames = $confNames
                    }
                    ReportServerWeb "PSDSCReportServer" {
                        ServerURL       = "https://$($DSCPullServer):8080/PSDSCPullServer.svc"
                        RegistrationKey = "$($RegKey)"
                    }
                    PartialConfiguration "WindowsBaseOS" {
                        Description         = "Windows Base Operating System Configuration"
                        ConfigurationSource = @("[ConfigurationRepositoryWeb]PSDSCPullServer")
                    }
                    PartialConfiguration "$($osConfig)" {
                        Description         = "Operating System Installation Type Configuration (GUI or CORE)"
                        ConfigurationSource = @("[ConfigurationRepositoryWeb]PSDSCPullServer")
                        DependsOn           = '[PartialConfiguration]WindowsBaseOS'
                    }
                }
            }
        }

        if (!(Test-Path -Path "C:\Temp\DSCConfig\")) {
            New-Item -Path "C:\Temp" -Name "DSCConfig" -ItemType Directory -Force -Verbose
        }

        LCMConfiguration -NodeName $ComputerName -OutputPath "C:\Temp\DSCConfig\" -Verbose
        Set-DscLocalConfigurationManager -Path "C:\Temp\DSCConfig\" -Force -Verbose
    }

    Stop-Transcript

    #endregion DSC Pull Client Config
}

#endregion VM Configuration
$adoPWD = ConvertTo-SecureString -String $env:ADODev_PWD -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($env:adodevUser, $adoPWD)
Invoke-Command -Computername $VMName -ScriptBlock $scriptBlock -Credential $cred
