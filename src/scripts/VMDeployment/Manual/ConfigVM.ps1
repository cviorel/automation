<#
    .SYNOPSIS
        Configures a newly deployed VM.

    .DESCRIPTION
        The various user-provided parameters enable the script to configure a new VM according to the requirements of the VM's installed applications and/or operating environment. All required disk configurations are made, agents are installed and security (and other) configuration items are set by DSC.

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

    .PARAMETER VMName
        The fully-qualified domain name of the new VM.
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

    .PARAMETER GuestName
        The name that will be used to rename the built-in Guest account on domain memeber servers.
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

    .PARAMETER DMZcreds
        The credentials that will be used to access the DMZ domain (if needed).
        Required: False
        Type: SecureCredential
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

    .PARAMETER DSCPullServer
        The FQDN for the DSC pull server.
        Required: False
        Type: String
        Parameter Sets: All
        Position: Named
        Default Value: none
        Accept pipeline input: False
        Accept wildcard characters: False

    .PARAMETER DSCRegKey
        The GUID key for registering clients with the DSC pull server.
        Required: False
        Type: String
        Parameter Sets: All
        Position: Named
        Default Value: none
        Accept pipeline input: False
        Accept wildcard characters: False

    .EXAMPLE
        PS C:\> Config_VM.ps1

        Values for the required parameters can be passed in from the "Initiate_Deployment.ps1" script or manually on the command line.

    .INPUTS
        None

    .OUTPUTS
        None

    .NOTES
        Important: Some parameter values presented in this script may be examples only and should be changed before this script is used in a testing or production scenario. Carefully review all configuration values before deployment.

        The VM deployment process initiated by this script requires the use of Microsoft System Center Virtual Machine Manager for VM provisioning.

        The VirtualMachineManager PowerShell module is required to use this script.

        Author: Mike Nickerson
#>

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

    [parameter(HelpMessage = "The name of the new VM.")]
    [string]$VMName,

    [parameter(HelpMessage = "The password for the local administrator account.")]
    [securestring]$LocalAdminPwd,

    [parameter(HelpMessage = "The password for the local guest account.")]
    [securestring]$LocalGuestPwd,

    [parameter(HelpMessage = "The name that will be used to rename the built-in Administrator account on domain memeber servers.")]
    [string]$AdminName,

    [parameter(HelpMessage = "The name that will be used to rename the built-in Guest account on domain memeber servers.")]
    [string]$GuestName,

    [parameter(HelpMessage = "The name of the System Center Virtual Machine Manager server.")]
    [string]$VMMServerName,

    [parameter(HelpMessage = "The URL for the NuGet or Azure DevOps Artifacts repository containing packages to be installed on the new VM.")]
    [string]$RepoURL,

    [parameter(HelpMessage = "The FQDN for the DSC pull server.")]
    [string]$DSCPullServer,

    [parameter(HelpMessage = "The GUID key for registering clients with the DSC pull server.")]
    [string]$DSCRegKey
)

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

    $vmProps = @(
        [PSCustomObject]@{Name = "Server Type"; Value = $using:ServerType }
        [PSCustomObject]@{Name = "Operating System"; Value = $using:GuestOS }
        [PSCustomObject]@{Name = "UI Type"; Value = $using:UI }
        [PSCustomObject]@{Name = "Hardware Profile"; Value = $using:HardwareProfile }
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

    #region Set Registry Keys
    Start-Logging -TaskName "SetRegistryKeys"
    $newKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\VMProps"

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

    if ($localGuest.Name -ne $using:GuestName) {
        try {
            Rename-LocalUser -SID $localGuest.SID.Value -NewName $using:GuestName -Confirm:$false -Verbose
        }
        catch {
            $_.Exception.Message
        }
        finally {
            Set-LocalUser -SID $localGuest.SID.Value -FullName $using:GuestName -Description "" -Password $using:LocalGuestPwd -PasswordNeverExpires $true -UserMayChangePassword $false -Confirm:$false -Verbose
            Disable-LocalUser -SID $localGuest.SID.Value -Confirm:$false -Verbose
        }
    }
    elseif ($localGuest.Name -eq $GuestName) {
        try {
            Set-LocalUser -SID $localGuest.SID.Value -FullName $using:GuestName -Description "" -Password $using:LocalGuestPwd -PasswordNeverExpires $true -UserMayChangePassword $false -Confirm:$false -Verbose
            Disable-LocalUser -SID $localGuest.SID.Value -Confirm:$false -Verbose
        }
        catch {
            $_.Exception.Message
        }
    }

    if ($localAdmin.Name -ne $using:AdminName) {
        try {
            Rename-LocalUser -SID $localAdmin.SID.Value -NewName $using:AdminName -Confirm:$false -Verbose
        }
        catch {
            $_.Exception.Message
        }
        finally {
            Set-LocalUser -SID $localAdmin.SID.Value -FullName $using:AdminName -Description "" -Password $using:LocalAdminPwd -PasswordNeverExpires $true -UserMayChangePassword $true -Confirm:$false -Verbose
            Disable-LocalUser -SID $localAdmin.SID.Value -Confirm:$false -Verbose
        }
    }
    elseif ($localAdmin.Name -eq $using:AdminName) {
        try {
            Set-LocalUser -SID $localAdmin.SID.Value -FullName $using:AdminName -Description "" -Password $using:LocalAdminPwd -PasswordNeverExpires $true -UserMayChangePassword $true -Confirm:$false -Verbose
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
    if ($using:ServerType -eq "SQL") {
        Start-Logging -TaskName "ApplicationSetup-SQL"
        #* Copy SQL DVD to local disk
        Copy-Item -Path "D:\" -Destination "C:\Temp\SQLServer2016" -Recurse -Force -Confirm:$false -Verbose

        try {
            #* Configure Disks
            Get-Disk -Number 1 | Initialize-Disk -PartitionStyle GPT -Confirm:$false -Verbose
            Get-Disk -Number 2 | Initialize-Disk -PartitionStyle GPT -Confirm:$false -Verbose
            Get-Disk -Number 3 | Initialize-Disk -PartitionStyle GPT -Confirm:$false -Verbose
            Get-Disk -Number 4 | Initialize-Disk -PartitionStyle GPT -Confirm:$false -Verbose
            Get-Disk -Number 5 | Initialize-Disk -PartitionStyle GPT -Confirm:$false -Verbose

            #* Create Volumes
            New-Volume -DiskNumber 1 -FileSystem NTFS -FriendlyName "Backups" -DriveLetter "B" -Verbose
            New-Volume -DiskNumber 2 -FileSystem NTFS -FriendlyName "Data" -DriveLetter "E" -Verbose
            New-Volume -DiskNumber 3 -FileSystem NTFS -FriendlyName "Logs" -DriveLetter "L" -Verbose
            New-Volume -DiskNumber 4 -FileSystem NTFS -FriendlyName "Shared" -DriveLetter "S" -Verbose
            New-Volume -DiskNumber 5 -FileSystem NTFS -FriendlyName "Temp" -DriveLetter "T" -Verbose
        }
        catch {
            Write-Output "Unable to configure the drives."
            $_.Exception.Message
        }
        Stop-Transcript
    }
    elseif ($using:ServerType -eq "WEB" -and (Get-WindowsFeature -Name "Web-Server").InstallState -eq "Available") {
        Start-Logging -TaskName "ApplicationSetup-IIS"

        try {
            Install-WindowsFeature -Name Web-Server -IncludeManagementTools -Confirm:$false -Verbose
        }
        catch {
            Write-Output "Unable to install IIS features."
            $_.Exception.Message
        }
        Stop-Transcript
    }
    #endregion Setup Applications

    #region Install Software Packages
    Start-Logging -TaskName "InstallAgents"

    if (!(Test-Path -Path "$($env:SystemDrive)\Temp\Packages\")) {
        New-Item -Path "$($env:SystemDrive)\Temp" -Name "Packages" -ItemType Directory -Force -Verbose
    }

    $packageRepo = $using:RepoURL
    $searchUrl = ($packageRepo.Trim('/'), 'Packages()?$filter=(Id%20eq%20%27chocolatey%27)%20and%20IsLatestVersion') -join '/'
    $localChocolateyPackageFilePath = "$($env:SystemDrive)\Temp\Packages\chocolatey.0.10.15.nupkg"
    $ChocoInstallPath = "$($env:SystemDrive)\ProgramData\Chocolatey\bin"
    $env:ChocolateyInstall = "$($env:SystemDrive)\ProgramData\Chocolatey"
    $env:Path += ";$ChocoInstallPath"
    $DebugPreference = "Continue";
    function Get-Downloader {
        param (
            [string]$url
        )

        $downloader = New-Object System.Net.WebClient

        $defaultCreds = [System.Net.CredentialCache]::DefaultCredentials
        if (!($defaultCreds)) {
            $downloader.Credentials = $defaultCreds
        }

        $ignoreProxy = $env:chocolateyIgnoreProxy
        if ($ignoreProxy -and $ignoreProxy -eq 'true') {
            Write-Debug "Explicitly bypassing proxy due to user environment variable"
            $downloader.Proxy = [System.Net.GlobalProxySelection]::GetEmptyWebProxy()
        }
        else {
            # check if a proxy is required
            $explicitProxy = $env:chocolateyProxyLocation
            $explicitProxyUser = $env:chocolateyProxyUser
            $explicitProxyPassword = $env:chocolateyProxyPassword
            if ($explicitProxy -and $explicitProxy -ne '') {
                # explicit proxy
                $proxy = New-Object System.Net.WebProxy($explicitProxy, $true)
                if ($explicitProxyPassword -and $explicitProxyPassword -ne '') {
                    #$passwd = ConvertTo-SecureString $explicitProxyPassword -AsPlainText -Force
                    $proxy.Credentials = New-Object System.Management.Automation.PSCredential ($explicitProxyUser, $passwd)
                }

                Write-Debug "Using explicit proxy server '$explicitProxy'."
                $downloader.Proxy = $proxy

            }
            elseif (!$downloader.Proxy.IsBypassed($url)) {
                $creds = $defaultCreds
                if (!($creds)) {
                    Write-Debug "Default credentials were null. Attempting backup method"
                    $cred = Get-Credential
                    $creds = $cred.GetNetworkCredential();
                }

                $proxyaddress = $downloader.Proxy.GetProxy($url).Authority
                Write-Debug "Using system proxy server '$proxyaddress'."
                $proxy = New-Object System.Net.WebProxy($proxyaddress)
                $proxy.Credentials = $creds
                $downloader.Proxy = $proxy
            }
        }

        return $downloader
    }

    function Save-File {
        param (
            [string]$url,
            [string]$file
        )
        $downloader = Get-Downloader $url
        $downloader.DownloadFile($url, $file)
    }

    function Save-Package {
        param (
            [string]$packageODataSearchUrl,
            [string]$file
        )
        $downloader = Get-Downloader $packageODataSearchUrl
        Write-Output "Querying latest package from $packageODataSearchUrl"
        [xml]$pkg = $downloader.DownloadString($packageODataSearchUrl)
        $packageDownloadUrl = $pkg.feed.entry.content.src
        Write-Output "Downloading $packageDownloadUrl to $file"
        $downloader.DownloadFile($packageDownloadUrl, $file)
    }

    function Install-LocalChocolateyPackage {
        param (
            [string]$chocolateyPackageFilePath = ''
        )

        if ($chocolateyPackageFilePath -or $chocolateyPackageFilePath -eq '') {
            throw "You must specify a local package to run the local install."
        }

        if (!(Test-Path($chocolateyPackageFilePath))) {
            throw "No file exists at $chocolateyPackageFilePath"
        }

        if (!($env:TEMP)) {
            $env:TEMP = Join-Path $env:SystemDrive 'temp'
        }
        $chocTempDir = Join-Path $env:TEMP "chocolatey"
        $tempDir = Join-Path $chocTempDir "chocInstall"
        if (![System.IO.Directory]::Exists($tempDir)) { [System.IO.Directory]::CreateDirectory($tempDir) }
        $file = Join-Path $tempDir "chocolatey.zip"
        Copy-Item $chocolateyPackageFilePath $file -Force
        Write-Output "Extracting $file to $tempDir..."
        Expand-Archive -Path "$file" -DestinationPath "$tempDir" -Force
        Write-Output "Installing chocolatey on this machine"
        $toolsFolder = Join-Path $tempDir "tools"
        $chocInstallPS1 = Join-Path $toolsFolder "chocolateyInstall.ps1"

        & $chocInstallPS1

        Write-Output 'Ensuring chocolatey commands are on the path'
        $chocInstallVariableName = "ChocolateyInstall"
        $chocoPath = [Environment]::GetEnvironmentVariable($chocInstallVariableName)
        if (!($chocoPath) -or $chocoPath -eq '') {
            $chocoPath = '$($env:SystemDrive)\ProgramData\Chocolatey'
        }

        $chocoExePath = Join-Path $chocoPath 'bin'

        if ($($env:Path).ToLower().Contains($($chocoExePath).ToLower()) -eq $false) {
            $env:Path = [Environment]::GetEnvironmentVariable('Path', [System.EnvironmentVariableTarget]::Machine);
        }
    }

    # Install Chocolatey unless it is already installed
    if (!(Test-Path $ChocoInstallPath)) {
        if ($searchUrl) {
            Save-Package $searchUrl $localChocolateyPackageFilePath
        }
        Install-LocalChocolateyPackage $localChocolateyPackageFilePath
    }

    # Enable Chocolatey FIPS compliant checksums
    choco feature enable -n useFipsCompliantChecksums

    # Register internal package source, PS repository and Chocolatey source if they do not currently exist
    if (!(Get-PackageSource -Name $using:RepoName -ErrorAction SilentlyContinue)) {
        Register-PackageSource -Name "$using:RepoName" -Location "$using:RepoURL" -ProviderName Nuget -Trusted -Force -Confirm:$false -Verbose
    }
    if (!(Get-PSRepository -Name $using:RepoName -ErrorAction SilentlyContinue)) {
        Register-PSRepository -Name "$using:RepoName" -SourceLocation "$using:RepoURL" -PackageManagementProvider NuGet -InstallationPolicy Trusted -Verbose
    }
    $chocoSources = choco sources list
    if (!($chocoSources | Where-Object { $_ -like "*$($using:RepoName)*" })) {
        choco source add -n="$using:RepoName" -s="$using:RepoURL"
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

    if (!($using:DSCPullServer)) {
        Write-Warning "DSC Pull Server not specified. Skipping DSC client node configuration..."
        return
    }
    else {
        $ComputerName = $env:COMPUTERNAME
        switch ((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").InstallationType) {
            "Server" { $osConfig = "WindowsGUI" }
            "Server Core" { $osConfig = "WindowsCORE" }
        }

        if (($using:ServerType -eq "IIS") -or ($using:ServerType -eq "SQL") -or ($using:ServerType -eq "DomainController")) {
            $confNames = @("WindowsBaseOS", "$($osConfig)", "$($using:ServerType)")
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
                        ServerURL          = "https://$($using:DSCPullServer):8080/PSDSCPullServer.svc"
                        RegistrationKey    = "$($RegKey)"
                        ConfigurationNames = $confNames
                    }
                    ReportServerWeb "PSDSCReportServer" {
                        ServerURL       = "https://$($using:DSCPullServer):8080/PSDSCPullServer.svc"
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
                    PartialConfiguration "$($using:ServerType)" {
                        Description         = "$($using:ServerType)-specific Configuration"
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
                        ServerURL          = "https://$($using:DSCPullServer):8080/PSDSCPullServer.svc"
                        RegistrationKey    = "$($RegKey)"
                        ConfigurationNames = $confNames
                    }
                    ReportServerWeb "PSDSCReportServer" {
                        ServerURL       = "https://$($using:DSCPullServer):8080/PSDSCPullServer.svc"
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

Invoke-Command -Computername $VMName -ScriptBlock $scriptBlock

#region Finalize SQL Server Setup
if ($ServerType -eq "SQL") {
    # Eject SQL installation ISO
    Get-SCVirtualDVDDrive -VMMServer $vmmServer -VM $VMName | Set-SCVirtualDVDDrive -NoMedia
    Restart-Computer -ComputerName $VMName -Force -Confirm:$false
}
#endregion Finalize SQL Server Setup
