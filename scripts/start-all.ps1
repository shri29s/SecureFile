# scripts/start-all.ps1
$ErrorActionPreference = 'Continue'
$projectRoot = Split-Path $PSScriptRoot -Parent
Set-Location $projectRoot

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "  Launching SecureFile Local Environment" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

# 1. Start Hardhat Node
$chainListening = Get-NetTCPConnection -LocalPort 8545 -ErrorAction SilentlyContinue
if (-not $chainListening) {
    Write-Host "[1/3] Starting Hardhat blockchain node in new window..." -ForegroundColor Yellow
    Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$projectRoot'; Write-Host '--- Hardhat Node (Port 8545) ---' -ForegroundColor Green; npm run chain"
    Start-Sleep -Seconds 4
} else {
    Write-Host "[1/3] Hardhat blockchain node is already running on port 8545." -ForegroundColor Green
}

# 2. Deploy contract to chain
Write-Host "Deploying / verifying contract on chain..." -ForegroundColor Yellow
try {
    node scripts/deploy.js
} catch {
    Write-Host "Deploy notice: $_" -ForegroundColor DarkGray
}

# 3. Start IPFS Kubo Node
$ipfsListening = Get-NetTCPConnection -LocalPort 5001 -ErrorAction SilentlyContinue
if (-not $ipfsListening) {
    Write-Host "[2/3] Starting Kubo IPFS daemon in new window..." -ForegroundColor Yellow
    Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$projectRoot'; Write-Host '--- Kubo IPFS Node (Port 5001) ---' -ForegroundColor Green; powershell -ExecutionPolicy Bypass -File .\scripts\ipfs.ps1"
    Start-Sleep -Seconds 4
} else {
    Write-Host "[2/3] Kubo IPFS node is already running on port 5001." -ForegroundColor Green
}

# 4. Start Proxy & UI Server
$proxyListening = Get-NetTCPConnection -LocalPort 3001 -ErrorAction SilentlyContinue
if (-not $proxyListening) {
    Write-Host "[3/3] Starting SecureFile Proxy Server in new window..." -ForegroundColor Yellow
    Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$projectRoot'; Write-Host '--- SecureFile Proxy & UI (Port 3001) ---' -ForegroundColor Green; npm start"
    Start-Sleep -Seconds 3
} else {
    Write-Host "[3/3] SecureFile server is already running on port 3001." -ForegroundColor Green
}

Write-Host ""
Write-Host "==================================================" -ForegroundColor Green
Write-Host "  SecureFile is ready!" -ForegroundColor Green
Write-Host "  Preview URL: http://127.0.0.1:3001" -ForegroundColor Green
Write-Host "==================================================" -ForegroundColor Green

Start-Process "http://127.0.0.1:3001"
