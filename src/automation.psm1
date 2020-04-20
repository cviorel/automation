[array]$paths = @(
    'Private',
    'Public'
)

foreach ($path in $paths) {
    "$(Split-Path -Path $MyInvocation.MyCommand.Path)\$path\*.ps1" | Resolve-Path | ForEach-Object { . $_.ProviderPath }
}

$Public = @( Get-ChildItem -Path $PSScriptRoot\src\Public\*.ps1 -ErrorAction SilentlyContinue )
$Private = @( Get-ChildItem -Path $PSScriptRoot\src\Private\*.ps1 -ErrorAction SilentlyContinue )

ForEach ($obj in @( $Public + $Private )) {
    try {
        . $obj.FullName
    }
    catch {
        $_.Exception.Message
    }
}