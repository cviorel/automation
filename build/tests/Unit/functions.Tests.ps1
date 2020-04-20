############################################################################
# Unit tests for Functions
############################################################################

$WarningPreference = "SilentlyContinue"

$script:ProjectRoot = $env:Build_SourcesDirectory

if (-not $ProjectRoot) {
    $script:ProjectRoot = $PSScriptRoot
}

$script:ProjectName = $env:Build_Repository_Name
$script:BuildFiles = Join-Path -Path $script:ProjectRoot -ChildPath "build"
$script:SourceModule = Join-Path -Path $script:ProjectRoot -ChildPath "src"
$script:manifestPath = Join-Path -Path $SourceModule -ChildPath "$($script:ProjectName).psd1"
$script:ChangelogPath = Join-Path -Path $script:ProjectRoot -ChildPath "CHANGELOG.md"

if (Get-Module -Name $script:ProjectName -ErrorAction "SilentlyContinue") {
    Remove-Module -Name $script:ProjectName -Force
}

Import-Module $script:manifestPath -Force
$commands = Get-Command -Module $script:ProjectName -ErrorAction "Stop"

Describe -Name "##[section] Testing Module Manifest" {
    Context -Name "##[command] Manifest Validation" {
        $script:manifest = $null
        $script:manifest = Test-ModuleManifest -Path $script:manifestPath -Verbose:$false -ErrorAction "Stop" -WarningAction "SilentlyContinue"

        It -Name "Has a valid manifest" {
            $script:manifest | Should -Not -BeNullOrEmpty
        }

        It -Name "Has a valid name in the manifest" {
            $script:manifest.Name | Should -Be $script:ProjectName
        }

        It -Name "Has a valid root module" {
            $script:manifest.RootModule | Should -Be "$($script:ProjectName).psm1"
        }

        It -Name "Has a valid description" {
            $script:manifest.Description | Should -Not -BeNullOrEmpty
        }

        It -Name "Has a valid author" {
            $script:manifest.Author | Should -Not -BeNullOrEmpty
        }

        It -Name "Has a valid guid" {
            { [guid]::Parse($script:manifest.Guid) } | Should -Not -BeNullOrEmpty
        }

        It -Name "Has a valid copyright" {
            $script:manifest.CopyRight | Should -Not -BeNullOrEmpty
        }

        It -Name "Has a valid version in the manifest" {
            $script:manifest.Version -as [Version] | Should -Not -BeNullOrEmpty
        }

        It -Name "Has a valid version in the changelog" {
            $changelogVersions = $null
            $changelogVersions = @()
            $changelog = Get-Content $script:ChangelogPath
            foreach ($line in $changelog) {
                if ($line -match "^##\s\[(?<Version>(\d+\.){1,3}\d+)\]") {
                    $version = $line -replace ("## ", "")
                    $version = $version -replace ("\[", "")
                    $version = $version -replace ("\]", "")
                    $changelogVersions += $version
                }
            }
            $script:currentVersion = ($changelogVersions | Measure-Object -Maximum).Maximum
            $script:currentVersion | Should -Not -BeNullOrEmpty
        }

        It -Name "Has matching changelog and manifest versions" {
            $versions = ($script:currentVersion -eq $script:manifest.Version.ToString())
            $versions | Should -BeTrue
        }

        It -Name "Exports the same number of public funtions as what is listed in the Module Manifest" {
            $script:manifestExported.Count | Should -BeExactly $moduleExported.Count
        }

        foreach ($command in $moduleExported) {
            It -Name "Includes the $($command) in the Module Manifest ExportedFunctions" {
                $script:manifestExported -contains $command | Should -BeTrue
            }
        }
    }
}

Describe -Name "##[section] Testing Module Functions for Syntax Errors" {
    Context -Name "##[command] Running PSScriptAnalyzer Tests on Public Functions" {
        [ValidateSet('Error', 'Warning', 'Any', 'None')]
        $ScriptAnalysisFailBuildOnSeverityLevel = 'Error'
        $ScriptAnalyzerSettingsPath = "$script:BuildFiles\Tests\PSScriptAnalyzerSettings.psd1"
        $pubFunctionsPath = Join-Path -Path $SourceModule -ChildPath "/public"
        #$results = Invoke-ScriptAnalyzer -Path $pubFunctionsPath -Recurse -Settings $ScriptAnalyzerSettingsPath
        Invoke-ScriptAnalyzer -Path $pubFunctionsPath -Recurse -Settings $ScriptAnalyzerSettingsPath -Verbose
        <#It -Name "Public functions should pass PSSA tests" {
            $results | Should -BeNullOrEmpty
        }#>
    }
    Context -Name "##[command] Running PSScriptAnalyzer Tests on Private Functions" {
        [ValidateSet('Error', 'Warning', 'Any', 'None')]
        $ScriptAnalysisFailBuildOnSeverityLevel = 'Error'
        $ScriptAnalyzerSettingsPath = "$script:BuildFiles\Tests\PSScriptAnalyzerSettings.psd1"
        $privFunctionsPath = Join-Path -Path $SourceModule -ChildPath "/private"
        $results = Invoke-ScriptAnalyzer -Path $privFunctionsPath -Recurse -Settings $ScriptAnalyzerSettingsPath

        It -Name "Private functions should pass PSSA tests" {
            $results | Should -BeNullOrEmpty
        }
    }
}

Describe -Name "##[section] Testing Help Content" {
    foreach ($command in $commands) {
        $commandName = $command.Name

        $help = Get-Help $commandName -ErrorAction SilentlyContinue

        Describe "##[section] Test help for $($commandName)" {

            Context -Name "##[command] General help items" {

                It -Name "Gets synopsis for $($commandName)" {
                    $help.SYNOPSIS | Should -Not -BeNullOrEmpty
                }

                It -Name "Gets description for $($commandName)" {
                    $help.DESCRIPTION | Should -Not -BeNullOrEmpty
                }

                It -Name "Gets example code from $($commandName)" {
                    ($help.Examples.Example | Select-Object -First 1).Code | Should -Not -BeNullOrEmpty
                }

                It -Name "Gets example help from $($commandName)" {
                    ($help.Examples.Example.Remarks | Select-Object -First 1).Text | Should -Not -BeNullOrEmpty
                }
            }

            Context -Name "##[command] Test parameter help for $($commandName)" {

                $common = "Debug", "ErrorAction", "ErrorVariable", "InformationAction", "InformationVariable", "OutBuffer",
                "OutVariable", "PipelineVariable", "Verbose", "WarningAction", "WarningVariable", "Confirm", "Whatif"

                $parameters = $command.ParameterSets.Parameters |
                    Sort-Object -Property Name -Unique |
                    Where-Object { $_.Name -notin $common }
                $parameterNames = $parameters.Name

                $helpParameters = $help.Parameters.Parameter |
                    Where-Object { $_.Name -notin $common } |
                    Sort-Object -Property Name -Unique
                $helpParameterNames = $helpParameters.Name

                foreach ($parameter in $parameters) {
                    $parameterName = $parameter.Name
                    $parameterHelp = $help.parameters.parameter | Where-Object Name -EQ $parameterName

                    It -Name "Gets help for parameter: $($parameterName) : in $($commandName)" {
                        $parameterHelp.Description.Text | Should -Not -BeNullOrEmpty
                    }

                    It -Name "Help for $($parameterName) parameter in $commandName has correct Mandatory value" {
                        $codeMandatory = $parameter.IsMandatory.toString()
                        $parameterHelp.Required | Should -Be $codeMandatory
                    }

                    It -Name "Help for $commandName has correct parameter type for $($parameterName)" {
                        $codeType = $parameter.ParameterType.Name
                        $helpType = if ($parameterHelp.parameterValue) { $parameterHelp.parameterValue.Trim() }
                        $helpType | Should -Be $codeType
                    }
                }

                foreach ($helpParm in $HelpParameterNames) {
                    It -Name "Finds help parameter in code: $($helpParm)" {
                        $helpParm -in $parameterNames | Should -Be $true
                    }
                }
            }

            Context -Name "##[command] Help Links Should -Be Valid for $($commandName)" {

                if ($null -ne $help.relatedLinks) {
                    $links = $help.relatedLinks.navigationLink.uri
                    foreach ($link in $links) {
                        It -Name "[$link] should return HTTP 200 status for $($commandName)" {
                            $Results = Invoke-WebRequest -Uri $link -UseBasicParsing
                            Write-Host "            ##[debug] HTTP Status: $($Results.StatusCode)"
                            $Results.StatusCode | Should -Be "200"
                        }
                    }
                }
                else {
                    Write-Host "            ##[debug] No help URLs found for $($commandName)"
                }
            }
        }
    }
}