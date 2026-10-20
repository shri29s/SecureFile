$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
$env:IPFS_PATH = Join-Path $projectRoot '.runtime/ipfs'
$ipfsBinary = Join-Path $projectRoot '.runtime/kubo/ipfs.exe'
if (!(Test-Path -LiteralPath $ipfsBinary)) { throw 'Kubo is missing. See README.md for installation.' }
if (!(Test-Path -LiteralPath (Join-Path $env:IPFS_PATH 'config'))) {
    & $ipfsBinary init --profile=test
    & $ipfsBinary config Addresses.API /ip4/127.0.0.1/tcp/5001
    & $ipfsBinary config Addresses.Gateway /ip4/127.0.0.1/tcp/8081
}
& $ipfsBinary daemon --offline
