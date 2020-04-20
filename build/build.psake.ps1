# PSake makes variables declared here available in other scriptblocks
Properties {
    $script:ProjectRoot = $env:Build_SourcesDirectory
    if (-not $script:ProjectRoot) {
        $script:ProjectRoot = $PSScriptRoot
    }

    # Set 'ProjectName' (Module Name) to the name of the repositor
    #! Important: The ProjectName, repository name and module (PSD1/PSM1) file names must be the same
    $script:ProjectName = $env:Build_Repository_Name

    # Source Paths
    $script:BuildFiles = Join-Path -Path $script:ProjectRoot -ChildPath "build"
    $script:TestsPath = Join-Path -Path $script:BuildFiles -ChildPath "tests"
    $script:UnitTests = Join-Path -Path $script:TestsPath -ChildPath "Unit"
    $script:IntTests = Join-Path -Path $script:TestsPath -ChildPath "Integration"

    $script:UnitScriptTests = Join-Path -Path $script:TestsPath -ChildPath "Unit\utilityscripts.tests.ps1"
    $script:UnitFunctionTests = Join-Path -Path $script:TestsPath -ChildPath "Unit\function.tests.ps1"
    $script:UnitConfigTests = Join-Path -Path $script:TestsPath -ChildPath "Unit\configscripts.tests.ps1"
    $script:UnitDeployScriptTests = Join-Path -Path $script:TestsPath -ChildPath "Unit\deployscripts.tests.ps1"
    $script:IntWindowsBaseOSTests = Join-Path -Path $script:TestsPath -ChildPath "Integration\WindowsBaseOS.tests.ps1"
    $script:IntWindowsCORETests = Join-Path -Path $script:TestsPath -ChildPath "Integration\WindowsCORE.tests.ps1"
    $script:IntWindowsGUITests = Join-Path -Path $script:TestsPath -ChildPath "Integration\WindowsGUI.tests.ps1"
    $script:IntIISTests = Join-Path -Path $script:TestsPath -ChildPath "Integration\IIS.tests.ps1"
    $script:IntSQLBasicTests = Join-Path -Path $script:TestsPath -ChildPath "Integration\SQLBasic.tests.ps1"
    $script:IntSQLHardenedTests = Join-Path -Path $script:TestsPath -ChildPath "Integration\SQLHardened.tests.ps1"
    $script:IntDomainControllerTests = Join-Path -Path $script:TestsPath -ChildPath "Integration\DomainController.tests.ps1"
    $script:IntVMPropsTests = Join-Path -Path $script:TestsPath -ChildPath "Integration\vmintegration.tests.ps1"
    $script:IntLCMTests = Join-Path -Path $script:TestsPath -ChildPath "Integration\lcmintegration.tests.ps1"
    $script:TestVMs = @(
        "$($env:DSCClient01)",
        "$($env:DSCClient02)",
        "$($env:DSCClient03)"
    )

    $script:SourceDocs = Join-Path -Path $script:ProjectRoot -ChildPath "docs"
    $script:SourceModule = Join-Path -Path $script:ProjectRoot -ChildPath "src"
    $script:SourceScripts = Join-Path -Path $script:SourceModule -ChildPath "scripts"
    $script:DeployScripts = Join-Path -Path $script:SourceScripts -ChildPath "VMDeployment"
    $script:SourceConfigs = Join-Path -Path $script:SourceModule -ChildPath "configurations"
    $script:Sources += @(
        $script:BuildFiles,
        $script:SourceModule,
        $script:SourceDocs,
        $script:SourceScripts,
        $script:SourceConfigs
    )

    # Destination Paths
    $script:StagingDir = $env:Build_ArtifactStagingDirectory
    $script:TestResultsDir = $env:Common_TestResultsDirectory
    $script:ToolsDir = Join-Path -Path $script:StagingDir -ChildPath "tools"
    $script:StagedModuleDir = Join-Path -Path $script:ToolsDir -ChildPath $script:ProjectName
    $script:StagedManifest = Join-Path -Path $script:StagedModuleDir -ChildPath "$($script:ProjectName).psd1"
    $script:StagedDocs = Join-Path -Path $script:StagedModuleDir -ChildPath 'docs'
    $script:StagedScripts = Join-Path -Path $script:StagedModuleDir -ChildPath 'scripts'
    $script:StagedConfigs = Join-Path -Path $script:StagedModuleDir -ChildPath 'configurations'
    $script:Destinations += @(
        $script:ToolsDir,
        $script:StagedModuleDir,
        $script:StagedDocs,
        $script:StagedScripts,
        $script:StagedConfigs
    )
}

# Define top-level tasks
Task 'Default' -Depends 'Test'

# Show build variables
Task 'Init' {
    Write-Host "##[section] Display Pipeline Environment Variables"
    Write-Host "------------------------------"
    Write-Host "##[debug] Staging Directory: $env:Build_StagingDirectory"
    Write-Host "##[debug] Sources Directory: $env:Build_SourcesDirectory"
    Write-Host "##[debug] Test Results Directory: $env:Common_TestResultsDirectory"
    Write-Host "##[debug] Pipeline Build Number: $env:Build_BuildNumber"
    Write-Host "##[debug] Repository Name: $env:Build_Repository_Name"
    Write-Host "##[debug] Repository Branch: $env:Build_SourceBranchName"
    Write-Host "##[debug] Build Requested By: $env:Build_RequestedFor"
    Write-Host "------------------------------`n"

    # Check file paths
    # Sources
    foreach ($path in $script:Sources) {
        if (!(Test-Path $path)) {
            Write-Host "##vso[task.logissue type=error] Source path: [$($path)] is missing."
            exit 1
        }
        else {
            Write-Host "##[command] Found source path: [$($path)]..."
        }
    }
    # Destinations
    foreach ($path in $script:Destinations) {
        if (!(Test-Path $path)) {
            Write-Host "##[command] Path: [$($path)] is missing. Creating the required folder..."
            New-Item -Path $path -ItemType Directory -Force -Verbose
        }
        else {
            Write-Host "##[command] Found destination path: [$($path)]..."
        }
    }
}

Task 'StageModule' {
    # Create a single .psm1 module file containing all functions
    Write-Host "##[command] Adding Private functions from [$($script:ProjectName)] to new combined PSM1 file..."
    $privateFunctions = @( Get-ChildItem -Path "$script:SourceModule\Private\*.ps1" -Recurse -ErrorAction SilentlyContinue )
    Write-Host "##[command] Adding Public functions from [$($script:ProjectName)] to new combined PSM1 file..."
    $publicFunctions = @( Get-ChildItem -Path "$script:SourceModule\Public\*.ps1" -Recurse -ErrorAction SilentlyContinue )
    $combinedModulePath = Join-Path -Path $script:StagedModuleDir -ChildPath "$($script:ProjectName).psm1"
    @($publicFunctions + $privateFunctions) | Get-Content | Add-Content -Path $combinedModulePath -Verbose

    Write-Host "##[command] Copying DscPullServerSetup.psm1 to the staging folder..."
    $DscPullServerSetup = Join-Path -Path $script:SourceModule -ChildPath "DscPullServerSetup.psm1"
    Copy-Item -Path $DscPullServerSetup -Destination $script:StagedModuleDir -Force -Verbose

    # Copy required folders and files to staging dirs
    Write-Host "##[command] Copying required files and folders to the staging folder for packaging..."
    $pathsToCopy = @(
        Join-Path -Path $script:ProjectRoot -ChildPath "CHANGELOG.md"
        Join-Path -Path $script:ProjectRoot -ChildPath "LICENSE.txt"
        Join-Path -Path $script:ProjectRoot -ChildPath "build\chocolatey*"
        Join-Path -Path $script:ProjectRoot -ChildPath "assets\*"
    )
    Copy-Item -Path $pathsToCopy -Destination $script:ToolsDir -Recurse -Verbose

    Write-Host "##[command] Copying utility scripts to the staging folder..."
    #$scripts = Join-Path -Path $script:ProjectRoot -ChildPath "scripts\*"
    Copy-Item -Path $script:SourceScripts -Destination $script:StagedScripts -Force -Verbose

    Write-Host "##[command] Copying DSC configuration scripts and compiled MOFs to the staging folder..."
    $configs = Join-Path -Path $script:SourceConfigs -ChildPath "**"
    Copy-Item -Path $configs -Destination "$($script:StagedModuleDir)\configurations" -Recurse -Force -Verbose

    Write-Host "##[command] Copying the NuSpec file to the staging folder..."
    $NuSpecFile = Join-Path -Path $script:BuildFiles -ChildPath "$($script:ProjectName).nuspec"
    Copy-Item -Path $NuSpecFile -Destination $script:StagingDir -Force -Verbose
    Copy-Item -Path "$($script:SourceModule)\$($script:ProjectName).psd1" -Destination $script:StagedModuleDir -Force -Verbose
}

Task 'ImportStagedModule' {
    Write-Host "##[command] Reloading staged module from path: [$script:StagedModuleDir]`n"
    if (Get-Module -Name $script:ProjectName) {
        Remove-Module -Name $script:ProjectName
    }
    Import-Module -Name $script:StagedModuleDir -ErrorAction 'Stop' -Force -Global
}

#region Unit Tests

Task 'UnitTestUtilityFunctions' {
    $TestFilePath = Join-Path -Path $script:TestResultsDir -ChildPath "UnitTests-Functions_$($env:Build_BuildNumber).xml"
    Invoke-Pester -Script "$($script:UnitTests)\functions.Tests.ps1" -PassThru -OutputFormat 'NUnitXml' -OutputFile $TestFilePath -PesterOption @{ IncludeVSCodeMarker = $true } -EnableExit
    <#if ($TestResults.FailedCount -gt 0) {
        Write-Host "##vso[task.logissue type=error;] Failed '$($TestResults.FailedCount)' tests, build failed"
        exit 1
    }#>
}

Task 'UnitTestUtilityScripts' {
    $TestFilePath = Join-Path -Path $script:TestResultsDir -ChildPath "UnitTests-UtilityScripts_$($env:Build_BuildNumber).xml"
    Invoke-Pester -Script "$($script:UnitTests)\utilityscripts.tests.ps1" -PassThru -OutputFormat 'NUnitXml' -OutputFile $TestFilePath -PesterOption @{ IncludeVSCodeMarker = $true } -EnableExit
    <#if ($TestResults.FailedCount -gt 0) {
        Write-Host "##vso[task.logissue type=error;] Failed '$($TestResults.FailedCount)' tests, build failed"
        exit 1
    }#>
}

Task 'UnitTestDeployScripts' {
    $TestFilePath = Join-Path -Path $script:TestResultsDir -ChildPath "Unit-DeployScripts_$($env:Build_BuildNumber).xml"
    $scripts = Get-ChildItem -Path $script:DeployScripts -Filter "*.ps1" -Recurs
    foreach ($script in $scripts) {
        Invoke-Pester -Script $script:UnitDeployScriptTests -PassThru -OutputFormat 'NUnitXml' -OutputFile $TestFilePath -PesterOption @{ IncludeVSCodeMarker = $true } -EnableExit

    }
}

Task 'UnitTestConfigScripts' {
    $TestFilePath = Join-Path -Path $script:TestResultsDir -ChildPath "UnitTests-ConfigScripts_$($env:Build_BuildNumber).xml"
    $configFiles = Get-ChildItem -Path $script:SourceConfigs -Filter "*.ps1"
    $configNames = $configFiles.Name -replace (".ps1", "")
    foreach ($config in $configNames) {
        Invoke-Pester -Script @{ Path = $script:UnitConfigTests; Parameters = @{ ConfigName = $config } } -PassThru -OutputFormat 'NUnitXml' -OutputFile $TestFilePath -PesterOption @{ IncludeVSCodeMarker = $true } -EnableExit
    }
}

#endregion Unit Tests

#region Integration Tests

Task 'IntTestWindowsBaseOSConfig' {
    $TestFilePath = Join-Path -Path $script:TestResultsDir -ChildPath "Integration-WindowsBaseOS_$($env:Build_BuildNumber).xml"
    $TestResults = Invoke-Pester -Script @{ Path = $script:IntWindowsBaseOSTests; Parameters = @{ AdminName = $env:LocalAdmin_Name; GuestName = $env:LocalGuest_Name } } -PassThru -OutputFormat 'NUnitXml' -OutputFile $TestFilePath -PesterOption @{ IncludeVSCodeMarker = $true }

    if ($TestResults.FailedCount -gt 0) {
        Write-Host "##vso[task.logissue type=error;] Failed '$($TestResults.FailedCount)' tests, build failed"
        exit 1
    }
}

Task 'IntTestWindowsCOREConfig' {
    $TestFilePath = Join-Path -Path $script:TestResultsDir -ChildPath "Integration-WindowsCORE_$($env:Build_BuildNumber).xml"
    $TestResults = Invoke-Pester -Script $script:IntWindowsCORETests -PassThru -OutputFormat 'NUnitXml' -OutputFile $TestFilePath -PesterOption @{ IncludeVSCodeMarker = $true }

    if ($TestResults.FailedCount -gt 0) {
        Write-Host "##vso[task.logissue type=error;] Failed '$($TestResults.FailedCount)' tests, build failed"
        exit 1
    }
}

Task 'IntTestWindowsGUIConfig' {
    $TestFilePath = Join-Path -Path $script:TestResultsDir -ChildPath "Integration-WindowsGUI_$($env:Build_BuildNumber).xml"
    $TestResults = Invoke-Pester -Script $script:IntWindowsGUITests -PassThru -OutputFormat 'NUnitXml' -OutputFile $TestFilePath -PesterOption @{ IncludeVSCodeMarker = $true }

    if ($TestResults.FailedCount -gt 0) {
        Write-Host "##vso[task.logissue type=error;] Failed '$($TestResults.FailedCount)' tests, build failed"
        exit 1
    }
}

Task 'IntTestIISConfig' {
    $TestFilePath = Join-Path -Path $script:TestResultsDir -ChildPath "Integration-IIS_$($env:Build_BuildNumber).xml"
    $TestResults = Invoke-Pester -Script $script:IntIISTests -PassThru -OutputFormat 'NUnitXml' -OutputFile $TestFilePath -PesterOption @{ IncludeVSCodeMarker = $true }

    if ($TestResults.FailedCount -gt 0) {
        Write-Host "##vso[task.logissue type=error;] Failed '$($TestResults.FailedCount)' tests, build failed"
        exit 1
    }
}

Task 'IntTestSQLBasicConfig' {
    $TestFilePath = Join-Path -Path $script:TestResultsDir -ChildPath "Integration-SQLBasic_$($env:Build_BuildNumber).xml"
    $TestResults = Invoke-Pester -Script $script:IntSQLBasicTests -PassThru -OutputFormat 'NUnitXml' -OutputFile $TestFilePath -PesterOption @{ IncludeVSCodeMarker = $true }

    if ($TestResults.FailedCount -gt 0) {
        Write-Host "##vso[task.logissue type=error;] Failed '$($TestResults.FailedCount)' tests, build failed"
        exit 1
    }
}

Task 'IntTestSQLHardenedConfig' {
    $TestFilePath = Join-Path -Path $script:TestResultsDir -ChildPath "Integration-SQLHardened_$($env:Build_BuildNumber).xml"
    $TestResults = Invoke-Pester -Script $script:IntSQLHardenedTests -PassThru -OutputFormat 'NUnitXml' -OutputFile $TestFilePath -PesterOption @{ IncludeVSCodeMarker = $true }

    if ($TestResults.FailedCount -gt 0) {
        Write-Host "##vso[task.logissue type=error;] Failed '$($TestResults.FailedCount)' tests, build failed"
        exit 1
    }
}

Task 'IntTestDomainControllerConfig' {
    $TestFilePath = Join-Path -Path $script:TestResultsDir -ChildPath "Integration-DomainController_$($env:Build_BuildNumber).xml"
    $TestResults = Invoke-Pester -Script $script:IntDomainControllerTests -PassThru -OutputFormat 'NUnitXml' -OutputFile $TestFilePath -PesterOption @{ IncludeVSCodeMarker = $true }

    if ($TestResults.FailedCount -gt 0) {
        Write-Host "##vso[task.logissue type=error;] Failed '$($TestResults.FailedCount)' tests, build failed"
        exit 1
    }
}

Task 'InTestVMProps' {
    $TestFilePath = Join-Path -Path $script:TestResultsDir -ChildPath "Integration-VMProps_$($env:Build_BuildNumber).xml"
    foreach ($vm in $script:TestVMs) {
        $TestResults = Invoke-Pester -Script @{ Path = $script:IntVMPropsTests; Parameters = @{ComputerName = $vm; AdminName = $env:LocalAdmin_Name; GuestName = $env:LocalGuest_Name } } -PassThru -OutputFormat 'NUnitXml' -OutputFile $TestFilePath -PesterOption @{ IncludeVSCodeMarker = $true }
        if ($TestResults.FailedCount -gt 0) {
            Write-Host "##vso[task.logissue type=error;] Failed '$($TestResults.FailedCount)' tests, build failed"
            exit 1
        }
    }
}

Task 'InDSCTesting' {
    $LCMTestFilePath = Join-Path -Path $script:TestResultsDir -ChildPath "Integration-LCMTesting_$($env:Build_BuildNumber).xml"
    foreach ($vm in $script:TestVMs) {
        $LCMTestResults = Invoke-Pester -Script @{ Path = $script:IntLCMTests; Parameters = @{ ComputerName = $vm; AdminName = $env:LocalAdmin_Name; GuestName = $env:LocalGuest_Name; DSCPullServer = $env:DSCPullServerTest } } -PassThru -OutputFormat 'NUnitXml' -OutputFile $LCMTestFilePath -PesterOption @{ IncludeVSCodeMarker = $true }
        if ($LCMTestResults.FailedCount -gt 0) {
            Write-Host "##vso[task.logissue type=error;] Failed '$($LCMTestResults.FailedCount)' tests, build failed"
            exit 1
        }
        $ConfigTestResults =
        foreach ($config in $env:configs) {
            Invoke-Pester -Script @{ Path = $script:TestsPath; Parameters = @{  } }
        }
        if ($ConfigTestResults.FailedCount -gt 0) {
            Write-Host "##vso[task.logissue type=error;] Failed '$($ConfigTestResults.FailedCount)' tests, build failed"
            exit 1
        }
    }
}

#endregion Integration Tests

Task 'UpdateDocumentation' -Depends 'ImportStagedModule' {
    $docFiles = Get-ChildItem -Path $script:SourceDocs | Where-Object { $_.Name -like "*.md" } | Select-Object -ExpandProperty Name
    $docFiles = $docFiles -replace "\.md"
    $functions = Get-Command -Module $script:ProjectName | Select-Object -ExpandProperty Name
    foreach ($function in $functions) {
        if ($function -in $docFiles) {
            Write-Host "##[command] Markdown help doc found for $($function)."
        }
        else {
            Write-Host "##[command] No markdown help doc found for $($function)."
            New-MarkdownHelp -Command $function -OutputFolder $script:StagedDocs -AlphabeticParamsOrder -Force -Verbose
        }
    }
    $scripts = Get-ChildItem -Path $script:SourceScripts | Where-Object { $_.Name -like "*.ps1" }
    foreach ($script in $scripts) {
        if ($script.Name -in $docFiles) {
            Write-Host "##[command] Markdown help doc found for $($script)."
        }
        else {
            Write-Host "##[command] No markdown help doc found for $($script)."
            New-MarkdownHelp -Command $script -OutputFolder $script:StagedDocs -AlphabeticParamsOrder -Force -Verbose
        }
    }

    # Create new external XML help file
    New-ExternalHelp -Path $script:SourceDocs -OutputPath $script:StagedDocs -ErrorAction SilentlyContinue -Force -Verbose | Out-Null
    # Update index.md
    Write-Host "##[command] Copying $($script:ProjectRoot)\README.md to $($script:StagedDocs)\index.md...`n"
    Copy-Item -Path "$($script:ProjectRoot)\README.md" -Destination "$($script:StagedDocs)\index.md" -Force -Verbose | Out-Null
}

Task 'CreateModuleZip' {
    try {
        $manifest = Test-ModuleManifest -Path $script:StagedManifest -ErrorAction Stop
        [Version]$manifestVersion = $manifest.Version
    }
    catch {
        Write-Host "##vso[task.logissue type=warning] Could not get manifest version from [$script:StagedManifest]"
    }

    # Create zip file
    try {
        $releaseFilename = "$($script:ProjectName)-v$($manifestVersion.ToString()).zip"
        $releasePath = Join-Path -Path $script:ToolsDir -ChildPath $releaseFilename
        Write-Host "##[command] Creating module zip file [$releaseFilename] using manifest version [$manifestVersion]"
        Compress-Archive -Path "$($script:ToolsDir)\$($script:ProjectName)\*" -DestinationPath $releasePath -Force -Verbose -ErrorAction Stop
    }
    catch {
        Write-Host "##vso[task.logissue type=error] Could not create release artifact [$releaseFilename] using manifest version [$manifestVersion]"
    }
}
