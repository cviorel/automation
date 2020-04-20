[CmdletBinding()]
param (
    [Parameter()]
    [System.String[]]
    $tasklist = 'Default'
)

# Execute PSake tasks
$invokePsakeParams = @{
    buildFile = (Join-Path -Path $env:Build_Repository_LocalPath -ChildPath 'build\build.psake.ps1')
    nologo    = $true
}

Invoke-psake @invokePsakeParams @PSBoundParameters

exit ( [int](-not $psake.build_success) )
