############################################################################
# Unit tests for DSC Configurations
############################################################################

[cmdletbinding()]
param (
    [parameter()]
    [string]$ConfigName
)

$WarningPreference = "SilentlyContinue"

$script:ProjectRoot = $env:Build_SourcesDirectory

if (-not $script:ProjectRoot) {
    $script:ProjectRoot = $PSScriptRoot
}

$script:SourceModule = Join-Path -Path $script:ProjectRoot -ChildPath "src"
$script:SourceConfigs = Join-Path -Path $script:SourceModule -ChildPath "configurations"

Describe -Name "##[section] Checking $($ConfigName) MOF Compilation" {

    Context -Name "##[command] Node Configuration" {
        $mofPath = Join-Path -Path $script:SourceConfigs -ChildPath "compiled"
        $mof = Get-Item -Path "$($mofPath)\$($ConfigName).mof"
        $checksum = Get-Item -Path "$($mofPath)\$($ConfigName).mof.checksum"

        It -Name "Script should generate a MOF file with the name $($ConfigName)" {
            $mof | Should -Exist
        }

        It -Name "Script should generate a single MOF file for $($ConfigName)" {
            ($mof).count | Should -Be 1
        }

        It -Name "Script should generate a version 2.0 MOF document" {
            $mofContent = Get-Content -Path $mof
            $mofContent | Where-Object { $_ -match "Version=`"2.0.0`";" } | Should -Be " Version=`"2.0.0`";"
        }

        It -Name "MOF should have a matching checksum file" {
            $checksum | Should -Exist
        }

        It -Name "Checksum should have a value" {
            (Get-Content $checksum) | Should -Not -BeNullOrEmpty
        }
    }
}