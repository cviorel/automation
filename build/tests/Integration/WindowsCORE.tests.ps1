####################################################################
# Integration tests for WindowsCORE Config
####################################################################

Describe "General Windows Server Core Configuration Items" {

    Context "Disabled Windows Features" {

        It -Name "Disable Feature - Print and Document Services" {
            (Get-WindowsFeature -Name "Print-Services").InstallState | Should -Be "Available"
        }

        It -Name "Disable Feature - Print Server" {
            (Get-WindowsFeature -Name "Print-Server").InstallState | Should -Be "Available"
        }

        It -Name "Disable Feature - LPD Service" {
            (Get-WindowsFeature -Name "Print-LPD-Service").InstallState | Should -Be "Available"
        }
    }

    Context "Disabled and Stopped Services" {
        $services = Get-Service

        It -Name "Stopped Service - Internet Connection Sharing (ICS)" {
            ($services | Where-Object { $_.Name -eq "SharedAccess" }).Status | Should -Be "Stopped"
        }

        It -Name "Disabled Service - Internet Connection Sharing (ICS)" {
            ($services | Where-Object { $_.Name -eq "SharedAccess" }).StartType | Should -Be "Disabled"
        }

        It -Name "Stopped Service - Link-Layer Topology Discovery Mapper" {
            ($services | Where-Object { $_.Name -eq "lltdsvc" }).Status | Should -Be "Stopped"
        }

        It -Name "Disabled Service - Link-Layer Topology Discovery Mapper" {
            ($services | Where-Object { $_.Name -eq "lltdsvc" }).StartType | Should -Be "Disabled"
        }

        It -Name "Stopped Service - Windows Insider Service" {
            ($services | Where-Object { $_.Name -eq "wisvc" }).Status | Should -Be "Stopped"
        }

        It -Name "Disabled Service - Windows Insider Service" {
            ($services | Where-Object { $_.Name -eq "wisvc" }).StartType | Should -Be "Disabled"
        }
    }
}
