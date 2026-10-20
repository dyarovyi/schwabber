# Builds an optimized Schwabber.exe into dist\Schwabber (or dist\Schwabber-<runtime> with -SelfContained).
#   -SelfContained   bundle the .NET runtime so the exe runs on PCs without the .NET 8 Desktop Runtime
#   -Runtime         target runtime identifier, win-x64 (default) or win-arm64
param([switch]$SelfContained, [string]$Runtime = 'win-x64')
$ErrorActionPreference = 'Stop'

$windowsDir = Split-Path -Parent $PSScriptRoot
$projectDir = Split-Path -Parent $windowsDir
# Self-contained builds are for sharing, so they get their own folder, e.g. dist\Schwabber-win-x64.
$output = if ($SelfContained) { Join-Path $projectDir "dist\Schwabber-$Runtime" } else { Join-Path $projectDir 'dist\Schwabber' }

# Prefer a per-user SDK (dotnet-install.ps1 default location), then whatever is on PATH.
$dotnet = Join-Path $env:USERPROFILE '.dotnet\dotnet.exe'
if (Test-Path $dotnet) { $env:DOTNET_ROOT = Split-Path -Parent $dotnet }
else { $dotnet = (Get-Command dotnet -ErrorAction Stop).Source }

& (Join-Path $PSScriptRoot 'build-icon.ps1')

# Empty the folder rather than deleting it, so a build still works while Explorer or a terminal has it open.
if (Test-Path $output) { Get-ChildItem -Force $output | Remove-Item -Recurse -Force }
$selfContainedValue = if ($SelfContained) { 'true' } else { 'false' }
# Compression only applies to self-contained single files; it makes the bundled runtime much smaller.
$compress = if ($SelfContained) { 'true' } else { 'false' }
& $dotnet publish (Join-Path $windowsDir 'Schwabber\Schwabber.csproj') `
    -c Release -r $Runtime --self-contained $selfContainedValue -o $output `
    -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:DebugType=none `
    -p:EnableCompressionInSingleFile=$compress
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed with exit code $LASTEXITCODE" }

Write-Host ''
Write-Host "Built app: $(Join-Path $output 'Schwabber.exe')"
if (-not $SelfContained) { Write-Host 'Requires the .NET 8 Desktop Runtime. Use -SelfContained to bundle it.' }
