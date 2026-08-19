# Builds Windows MSIs for kproxy and kproxyd from the GoReleaser dist
# binaries using the WiX v4 toolset (`wix build`).
#
#   choco install wixtoolset -y          # WiX v4
#   .\packaging\build-msi.ps1 -Version 0.1.0
#
# The version must be a numeric x.y.z (MSI requirement). Points at the
# windows_amd64 binaries in dist/ by default.

param(
  [Parameter(Mandatory = $true)]
  [string]$Version,
  [string]$KproxyExe = "",
  [string]$KproxydExe = "",
  [string]$OutDir = "dist"
)

$ErrorActionPreference = "Stop"

$wix = Get-Command wix -ErrorAction SilentlyContinue
if (-not $wix) {
  throw "WiX v4+ not found. Install it with: dotnet tool install --global wix"
}
if ($Version -notmatch '^\d+\.\d+\.\d+$') {
  throw "Version must be numeric x.y.z, got '$Version'"
}

# WiX v7 requires accepting the OSMF EULA once per machine.
& wix eula accept wix7 2>$null
if ($LASTEXITCODE -ne 0) {
  & wix --acceptEula 2>$null
}

if (-not $KproxyExe) { $KproxyExe = "dist\kproxy_windows_amd64_v1\kproxy.exe" }
if (-not $KproxydExe) { $KproxydExe = "dist\kproxyd_windows_amd64_v1\kproxyd.exe" }

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

$targets = @(
  @{ Name = "kproxy";  Exe = $KproxyExe;  Wxs = "packaging\windows\kproxy.wxs" },
  @{ Name = "kproxyd"; Exe = $KproxydExe; Wxs = "packaging\windows\kproxyd.wxs" }
)

foreach ($t in $targets) {
  if (-not (Test-Path $t.Exe)) { throw "missing binary: $($t.Exe)" }
  $out = Join-Path $OutDir "$($t.Name)_${Version}_windows_amd64.msi"
  Write-Host "==> $out"
  & wix build $t.Wxs -d "Version=$Version" -d "ExePath=$(Resolve-Path $t.Exe)" -arch x64 -o $out
  if ($LASTEXITCODE -ne 0) { throw "wix build failed for $($t.Name)" }
}

Write-Host "==> done"