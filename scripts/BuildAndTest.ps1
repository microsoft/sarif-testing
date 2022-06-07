<#
.SYNOPSIS
    Build, test, and package the SARIF SDK.
.DESCRIPTION
    Builds the SARIF SDK for multiple target frameworks, runs the tests, and creates
    NuGet packages.
.PARAMETER Configuration
    The build configuration: Release or Debug. Default=Release
.PARAMETER BuildVerbosity
    Specifies the amount of information for MSBuild to display: quiet, minimal,
    normal, detailed, or diagnostic. Default=minimal
.PARAMETER NuGetVerbosity
    Specifies the amount of information for NuGet to display: quiet, normal,
    or detailed. Default=quiet
.PARAMETER NoClean
    Do not remove the outputs from the previous build.
.PARAMETER NoRestore
    Do not restore NuGet packages.
.PARAMETER NoObjectModel
    Do not rebuild the SARIF object model from the schema.
.PARAMETER NoBuild
    Do not build.
.PARAMETER NoTest
    Do not run tests.
.PARAMETER NoPackage
    Do not create NuGet packages.
.PARAMETER NoPublish
    Do not run dotnet publish, which creates a layout directory.
.PARAMETER NoSigningDirectory
    Do not create a directory containing the binaries that need to be signed.
.PARAMETER Associate
    Associate SARIF files with Visual Studio.
.PARAMETER NoFormat
    Do not format files based on dotnet-format tool
#>

[CmdletBinding()]
param(
    [string]
    [ValidateSet("Debug", "Release")]
    $Configuration="Release",

    [string]
    [ValidateSet("quiet", "minimal", "normal", "detailed", "diagnostic")]
    $BuildVerbosity = "minimal",

    [string]
    [ValidateSet("quiet", "normal", "detailed")]
    $NuGetVerbosity = "quiet",

    [switch]
    $NoClean,

    [switch]
    $NoRestore,

    [switch]
    $NoBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$InformationPreference = "Continue"
$NonWindowsOptions = @{}

$ScriptName = $([io.Path]::GetFileNameWithoutExtension($PSCommandPath))

Import-Module -Force $PSScriptRoot\ScriptUtilities.psm1
Import-Module -Force $PSScriptRoot\Projects.psm1

function Invoke-DotNetBuild($solutionFileRelativePath) {
    Write-Information "Building $solutionFileRelativePath..."

    $solutionFilePath = Join-Path $SourceRoot $solutionFileRelativePath
    & dotnet build $solutionFilePath --configuration $Configuration --verbosity $BuildVerbosity --no-incremental -bl
    
    if ($LASTEXITCODE -ne 0) {
        Exit-WithFailureMessage $ScriptName "Build of $solutionFilePath failed."
    }
}

# Create a directory containing all files necessary to execute an application.
# This operation is called "publish" because it is performed by "dotnet publish".
function Publish-Application($project, $framework) {
    Write-Information "Publishing $project for $framework ..."
    dotnet publish $SourceRoot\$project\$project.csproj --no-build --configuration $Configuration --framework $framework
}

function Remove-BuildOutput {
    Remove-DirectorySafely $BuildRoot
    foreach ($project in $Projects.All) {
        $objDir = "$SourceRoot\$project\obj"
        Remove-DirectorySafely $objDir
    }
}

if (-not $NoClean) {
    Remove-BuildOutput
}

if (-not $NoRestore) {
    foreach ($project in $Projects.All) {
        Write-Information "Restoring NuGet packages for $project..."
        & $RepoRoot\.nuget\NuGet.exe restore $SourceRoot\$project\$project.csproj -OutputDirectory "$NuGetPackageRoot" -Verbosity quiet
        if ($LASTEXITCODE -ne 0) {
            Exit-WithFailureMessage $ScriptName "NuGet restore failed for $project."
        }
    }
}

if (-not $?) {
    Exit-WithFailureMessage $ScriptName "BeforeBuild failed."
}

if (-not $NoBuild) {
    Invoke-DotNetBuild $SolutionFile
}

Write-Information "$ScriptName SUCCEEDED."