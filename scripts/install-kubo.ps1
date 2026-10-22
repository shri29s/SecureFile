$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
$runtimeDir = Join-Path $projectRoot '.runtime'
$zipPath = Join-Path $runtimeDir 'kubo.zip'
$expectedDigest = 'c25871516dec4d97ce1d160a26c1e3fdad294cb0eea065c0c0343bcfca86c524'

if (!(Test-Path -LiteralPath $runtimeDir)) {
    New-Item -ItemType Directory -Force -Path $runtimeDir | Out-Null
}

$ipfsBinary = Join-Path $runtimeDir 'kubo/ipfs.exe'
if (Test-Path -LiteralPath $ipfsBinary) {
    Write-Host "Kubo is already installed at $ipfsBinary"
    exit 0
}

Write-Host "Downloading Kubo v0.43.1..."
$url = 'https://github.com/ipfs/kubo/releases/download/v0.43.1/kubo_v0.43.1_windows-amd64.zip'
Invoke-WebRequest -Uri $url -OutFile $zipPath

$actualDigest = (Get-FileHash -Path $zipPath -Algorithm SHA256).Hash.ToLower()
if ($actualDigest -ne $expectedDigest) {
    throw "Checksum mismatch. Expected: $expectedDigest, Actual: $actualDigest"
}

Write-Host "Checksum verified. Extracting..."
Expand-Archive -Path $zipPath -DestinationPath $runtimeDir -Force
Remove-Item -Path $zipPath -Force
Write-Host "Kubo installed successfully at $ipfsBinary"
