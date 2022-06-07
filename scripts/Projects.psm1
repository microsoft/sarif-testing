<#
.SYNOPSIS
    Provides a list of SARIF SDK projects and frameworks.
.DESCRIPTION
    The Projects module exports variables whose properties specify the
    various kinds of projects in the SARIF SDK, and the frameworks for which
    they are built.
#>

$Frameworks = @{}

# .NET Framework versions for which we build.
$Frameworks.NetFx = @("net452", "net461", "net472")

# Frameworks for which we build libraries.
$Frameworks.Library = @("netstandard2.0", "netstandard2.1") + $Frameworks.NetFx

# Frameworks for which we build applications.
$Frameworks.Application = @("netcoreapp3.1") + $Frameworks.NetFx

$Frameworks.All = ($Frameworks.Library + $Frameworks.Application | Select -Unique)

$Projects = @{}

$Projects.Libraries = @(
    "WebGoat.NET"
)

$Projects.Products = $Projects.Libraries

$Projects.All = $Projects.Products

Export-ModuleMember -Variable Frameworks, Projects