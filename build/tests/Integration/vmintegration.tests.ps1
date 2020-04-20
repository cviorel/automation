####################################################################
# Integration tests for VM Deployment
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
    [string]$ApplicationType
)

Describe -Name "VM Availability Tests" {

    Context -Name "Basic Connectivity" {

        It -Name "VM Connectivity - Ping" {
            (Test-NetConnection -ComputerName $ComputerName).PingSucceeded | Should -Be $true
        }

        It -Name "VM Connectivity - RDP" {
            (Test-NetConnection -ComputerName $ComputerName -CommonTCPPort RDP).TcpTestSucceeded | Should -Be $true
        }

        It -Name "VM Connectivity - WinRM" {
            (Test-NetConnection -ComputerName $ComputerName -CommonTCPPort WINRM).TcpTestSucceeded | Should -Be $true
        }

        It -Name "VM Connectivity - SMB" {
            (Test-NetConnection -ComputerName $ComputerName -CommonTCPPort SMB).TcpTestSucceeded | Should -Be $true
        }
    }
}

$regProps = @(
    "Server Type",
    "Operating System",
    "UI Type",
    "Hardware Profile"
)
$psSession = New-PSSession -ComputerName $ComputerName
$cimSession = New-CimSession -ComputerName $ComputerName
$regKey = Invoke-Command -Session $psSession -Scriptblock { Get-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\VMProps\" }
$regValues = Invoke-Command -Session $psSession -Scriptblock { Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\VMProps\" }
$locAccts = Invoke-Command -Session $psSession -Scriptblock { Get-LocalUser }
$locGroup = Invoke-Command -Session $psSession -ScriptBlock { Get-LocalGroupMember -Group "Administrators" }
$localGuest = $locAccts | Where-Object { $_.SID.Value -like "*-501" }
$localAdmin = $locAccts | Where-Object { $_.SID.Value -like "*-500" }
$appType = $regValues.$($regProps[0])
$disks = Get-Disk -CimSession $cimSession
$partitions = Get-Partition -CimSession $cimSession | Where-Object { $_.Type -eq "Basic" }
$vols = $partitions | Get-Volume -CimSession $cimSession
$services = Get-Service -ComputerName $ComputerName

Describe -Name "Custom Registry Settings" {


    It -Name "Custom Registry Key Exists" {
        $regKey | Should -Be "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\VMProps"
    }

    It -Name "$($regProps[0]) Property Exists" {
        $regKey.Property | Should -Contain "Server Type"
    }

    It -Name "$($regProps[0]) Value Exists" {
        $regValues.$($regProps[0]) | Should -Not -Be $null
    }

    It -Name "$($regProps[0]) Has a Value" {
        $regValues.$($regProps[0]) | Should -Be "DSC"
    }

    It -Name "$($regProps[1]) Property Exists" {
        $regKey.Property | Should -Contain "Operating System"
    }

    It -Name "$($regProps[1]) Value Exists" {
        $regValues.$($regProps[1]) | Should -Not -Be $null
    }

    It -Name "$($regProps[1]) Has a Value" {
        $regValues.$($regProps[1]) | Should -Be "Windows Server 2019 Standard"
    }

    It -Name "$($regProps[2]) Property Exists" {
        $regKey.Property | Should -Contain "UI Type"
    }

    It -Name "$($regProps[2]) Value Exists" {
        $regValues.$($regProps[2]) | Should -Not -Be $null
    }

    It -Name "$($regProps[2]) Has a Value" {
        $regValues.$($regProps[2]) | Should -Be "CORE"
    }

    It -Name "$($regProps[3]) Property Exists" {
        $regKey.Property | Should -Contain "Hardware Profile"
    }

    It -Name "$($regProps[3]) Value Exists" {
        $regValues.$($regProps[3]) | Should -Not -Be $null
    }

    It -Name "$($regProps[3]) Has a Value" {
        $regValues.$($regProps[3]) | Should -Be "Hardware_Profile_4vCPU_8GB"
    }
}

Describe -Name "Local Accounts Configuration" {

    Context -Name "Built-in Administrator Account" {

        It -Name "User Name has been Changed (V-73623)" {
            $localAdmin.Name | Should -Not -Be "Administrator"
        }

        It -Name "User Name is $($AdminName)" {
            $localAdmin.Name | Should -Be "$($AdminName)"
        }

        It -Name "Password is Required" {
            $localAdmin.PasswordRequired | Should -Be $true
        }

        It -Name "Account is Disabled" {
            $localAdmin.Enabled | Should -Be $false
        }

        It -Name "Account is a Member of the Local Administrators Group" {
            $locGroup.Name | Should -Contain $localAdmin.Name
        }
    }

    Context -Name "Built-in Guest Account" {

        It -Name "User Name has been Changed (V-73625)" {
            $localGuest.Name | Should -Not -Be "Guest"
        }

        It -Name "User Name is $($GuestName)" {
            $localAdmin.Name | Should -Be "$($GuestName)"
        }

        It -Name "Password is Required" {
            $localGuest.PasswordRequired | Should -Be $true
        }

        It -Name "User Cannot Change Password" {
            $localGuest.UserMayChangePassword | Should -Be $false
        }

        It -Name "Account is Disabled (V-73809)" {
            $localGuest.Enabled | Should -Be $false
        }

        It -Name "Account is not a Member of the Local Administrators Group" {
            $locGroup.Name | Should -Not -Contain $localGuest.Name
        }
    }
}

Describe -Name "Application Specific Requirements" {

    If ($appType -eq "SQL") {

        Context -Name "SQL Server Requirements" {

            Context -Name "Features and Services" {
                $services = Get-Service -ComputerName $ComputerName -Name "MSSQLSERVER"

                It -Name "MSSQLSERVER Service Should be Running" {
                    ($services | Where-Object { $_.Name -eq "MSSQLSERVER" }).Status | Should -Be "Running"
                }
            }

            Context -Name "Drive Configuration" {

                It -Name "Required Number of Drives Present" {
                    $disks.Count | Should -Be 6
                }

                It -Name "Required Number of Volumes Created" {
                    $vols.Count | Should -Be 6
                }

                It -Name "All Drives are Online" {
                    $disks.OperationalStatus | Should -Be "Online"
                }

                Context -Name "Backups Drive" {
                    $backupsDrive = $disks | Where-Object { $_.Number -eq 1 }
                    $backupsPart = $partitions | Where-Object { $_.DiskNumber -eq 1 }
                    $backupsVol = $vols | Where-Object { $_.DriveLetter -eq "B" }

                    It -Name "Drive Number is '1'" {
                        $backupsDrive.Number | Should -Be 1
                    }

                    It -Name "Drive Letter is 'B'" {
                        $backupsPart.DriveLetter | Should -Be "B"
                    }

                    It -Name "File System Label is 'Backups'" {
                        $backupsVol.FriendlyName | Should -Be "Backups"
                    }

                    It -Name "Total Size is at Least '50 GB'" {
                        $backupsDrive.Size | Should -BeGreaterOrEqual 53687091200
                    }
                }

                Context -Name "Data Drive" {
                    $dataDrive = $disks | Where-Object { $_.Number -eq 2 }
                    $dataPart = $partitions | Where-Object { $_.DiskNumber -eq 2 }
                    $dataVol = $vols | Where-Object { $_.DriveLetter -eq "E" }

                    It -Name "Drive Number is '2'" {
                        $dataDrive.Number | Should -Be 2
                    }

                    It -Name "Drive Letter is 'E'" {
                        $dataPart.DriveLetter | Should -Be "E"
                    }

                    It -Name "File System Label is 'Data'" {
                        $dataVol.FriendlyName | Should -Be "Data"
                    }

                    It -Name "Total Size is at Least '50 GB'" {
                        $dataDrive.Size | Should -BeGreaterOrEqual 53687091200
                    }
                }

                Context -Name "Logs Drive" {
                    $logsDrive = $disks | Where-Object { $_.Number -eq 3 }
                    $logsPart = $partitions | Where-Object { $_.DiskNumber -eq 3 }
                    $logsVol = $vols | Where-Object { $_.DriveLetter -eq "L" }

                    It -Name "Drive Number is '3'" {
                        $logsDrive.Number | Should -Be 3
                    }

                    It -Name "Drive Letter is 'L'" {
                        $logsPart.DriveLetter | Should -Be "L"
                    }

                    It -Name "File System Label is 'Logs'" {
                        $logsVol.FriendlyName | Should -Be "Logs"
                    }

                    It -Name "Total Size is at Least '20 GB'" {
                        $logsDrive.Size | Should -BeGreaterOrEqual 21474836480
                    }
                }

                Context -Name "Shared Drive" {
                    $sharedDrive = $disks | Where-Object { $_.Number -eq 4 }
                    $sharedPart = $partitions | Where-Object { $_.DiskNumber -eq 4 }
                    $sharedVol = $vols | Where-Object { $_.DriveLetter -eq "S" }

                    It -Name "Drive Number is '4'" {
                        $sharedDrive.Number | Should -Be 4
                    }

                    It -Name "Drive Letter is 'S'" {
                        $sharedPart.DriveLetter | Should -Be "S"
                    }

                    It -Name "File System Label is 'Shared'" {
                        $sharedVol.FriendlyName | Should -Be "Shared"
                    }

                    It -Name "Total Size is at Least '30 GB'" {
                        $sharedDrive.Size | Should -BeGreaterOrEqual 32212254720
                    }
                }

                Context -Name "Temp Drive" {
                    $tempDrive = $disks | Where-Object { $_.Number -eq 5 }
                    $tempPart = $partitions | Where-Object { $_.DiskNumber -eq 5 }
                    $tempVol = $vols | Where-Object { $_.DriveLetter -eq "T" }

                    It -Name "Drive Number is '5'" {
                        $tempDrive.Number | Should -Be 5
                    }

                    It -Name "Drive Letter is 'T'" {
                        $tempPart.DriveLetter | Should -Be "T"
                    }

                    It -Name "File System Label is 'Temp'" {
                        $tempVol.FriendlyName | Should -Be "Temp"
                    }

                    It -Name "Total Size is at Least '20 GB'" {
                        $tempDrive.Size | Should -BeGreaterOrEqual 21474836480
                    }
                }
            }
        }
    }
    elseif ($appType -eq "IIS") {
        Context -Name "IIS Requirements" {

            Context -Name "Features and Services" {
                $feature = Get-WindowsFeature -ComputerName $ComputerName -Name "Web-Server"

                It -Name "Web-Server Feature is Installed" {
                    $feature.Installed | Should -Be $true
                }

                It -Name "W3SVC Service Should be Running" {
                    ($services | Where-Object { $_.Name -eq "W3SVC" }).Status | Should -Be "Running"
                }
            }

            Context -Name "Drive Configuration" {
                # TODO: Add drive configuration checks as needed
            }
        }
    }
    else {

    }
}

Describe -Name "Required Software is Installed" {

}

Get-CimSession -Name $cimSession.Name | Remove-CimSession -Confirm:$false
Get-PSSession -Name $psSession.Name | Remove-PSSession -Confirm:$false