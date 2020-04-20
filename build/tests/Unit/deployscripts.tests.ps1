############################################################################
# Unit tests for VM Deployment Scripts
############################################################################

$WarningPreference = "SilentlyContinue"

$script:ProjectRoot = $env:Build_SourcesDirectory

if (-not $script:ProjectRoot) {
    $script:ProjectRoot = $PSScriptRoot
}

$script:ProjectName = $env:Build_Repository_Name
$script:BuildFiles = Join-Path -Path $script:ProjectRoot -ChildPath "build"
$script:SourceModule = Join-Path -Path $script:ProjectRoot -ChildPath "src"
$script:SourceScripts = Join-Path -Path $script:SourceModule -ChildPath "scripts"
$script:DeployScripts = Join-Path -Path $script:SourceScripts -ChildPath "VMDeployment"
Write-Host "##[debug] Deployment Scripts Path: $($script:DeployScripts)"

if (Get-Module -Name $script:ProjectName -ErrorAction "SilentlyContinue") {
    Remove-Module -Name $script:ProjectName -Force
}

$script:scripts = Get-ChildItem -Path $script:DeployScripts -Filter "*.ps1" -Recurse
Write-Host "##[debug] Scripts: $($script:scripts)"

Describe -Name "##[section] Testing Deployment Scripts for Module $($script:ProjectName)" {

    Context -Name "##[command] Running PSScriptAnalyzer Tests on Deployment Scripts" {
        [ValidateSet('Error', 'Warning', 'Any', 'None')]
        $ScriptAnalysisFailBuildOnSeverityLevel = 'Error'
        $ScriptAnalyzerSettingsPath = "$script:BuildFiles\Tests\PSScriptAnalyzerSettings.psd1"
        #$results = Invoke-ScriptAnalyzer -Path $script:SourceScripts -Recurse -Settings $ScriptAnalyzerSettingsPath
        Invoke-ScriptAnalyzer -Path $script:SourceScripts -Recurse -Settings $ScriptAnalyzerSettingsPath -Verbose
<#
        It -Name "Scripts should pass PSSA tests" {
            $results | Should -BeNullOrEmpty
        }#>
    }
}

Describe -Name "##[section] Testing Help Content" {
    foreach ($script in $script:scripts) {
        $scriptName = $script.Name
        Write-Host "##[debug] $($scriptName)"
        $scriptPath = $script.FullName
        $content = Get-Content -Raw -Encoding UTF8 -Path $scriptPath
        $tokens = $errors = @()
        $help = Get-Help -Name $scriptPath -Full -ErrorAction SilentlyContinue
        $code = [System.Management.Automation.Language.Parser]::ParseInput($content, [Ref]$tokens, [Ref]$errors)

        Describe "##[section] Test help for $($scriptName)" {

            Context -Name "##[command] General help items" {

                It -Name "Gets synopsis for $($scriptName)" {
                    $help.SYNOPSIS | Should -Not -BeNullOrEmpty
                }

                It -Name "Gets description for $($scriptName)" {
                    $help.DESCRIPTION | Should -Not -BeNullOrEmpty
                }

                It -Name "Gets example code from $($scriptName)" {
                    ($help.Examples.Example | Select-Object -First 1).Code | Should -Not -BeNullOrEmpty
                }

                It -Name "Gets example help from $($scriptName)" {
                    ($help.Examples.Example.Remarks | Select-Object -First 1).Text | Should -Not -BeNullOrEmpty
                }
            }

            Context -Name "##[command] Test parameter help for $($scriptName)" {

                $common = "Debug", "ErrorAction", "ErrorVariable", "InformationAction", "InformationVariable", "OutBuffer",
                "OutVariable", "PipelineVariable", "Verbose", "WarningAction", "WarningVariable", "Confirm", "Whatif"

                $parameters = $code.ParamBlock.Parameters |
                    Sort-Object -Property Name -Unique |
                    Where-Object { $_.Name -notin $common }
                $parameterNames = $parameters.Name.VariablePath.UserPath

                $helpParameters = $help.Parameters.Parameter |
                    Where-Object { $_.Name -notin $common } |
                    Sort-Object -Property Name -Unique
                $helpParameterNames = $helpParameters.Name

                foreach ($parameter in $parameters) {
                    $parameterName = $parameter.Name.VariablePath.UserPath
                    $parameterHelp = $help.parameters.parameter | Where-Object Name -EQ $parameterName

                    It -Name "Gets help for parameter: $($parameterName): in $($scriptName)" {
                        $parameterHelp.Description.Text | Should -Not -BeNullOrEmpty
                    }

                    It -Name "Help for $($scriptName) has correct parameter type for $($parameterName)" {
                        $codeType = $parameter.StaticType.Name
                        $helpType = $parameterHelp.parameterValue
                        $helpType | Should -Be $codeType
                    }
                }

                foreach ($helpParam in $HelpParameterNames) {
                    It -Name "Finds help parameter in code: $($helpParam)" {
                        $helpParam -in $parameterNames | Should -Be $true
                    }
                }
            }

            Context -Name "##[command] Help Links Should -Be Valid for $($scriptName)" {

                if ($null -ne $help.relatedLinks) {
                    $links = $help.relatedLinks.navigationLink.uri
                    foreach ($link in $links) {
                        It -Name "[$link] should return HTTP 200 status for $($scriptName)" {
                            $Results = Invoke-WebRequest -Uri $link -UseBasicParsing
                            Write-Host "            ##[debug] HTTP Status: $($Results.StatusCode)"
                            $Results.StatusCode | Should -Be "200"
                        }
                    }
                }
                else {
                    Write-Host "            ##[debug] No help URLs found for  $($scriptName)"
                }
            }
        }
    }
}