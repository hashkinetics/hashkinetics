# HashKinetics local devnet launcher (Windows)
# Usage: .\devnet.ps1 [-N 4] [-Fresh] [-RotateEvery 30] [-ProverUrl http://127.0.0.1:9911]
#   -RotateEvery N : each validator rotates its operational key every N blocks (SCMS demo).
#   -ProverUrl URL : hk-prove endpoint (WSL GPU service) — nodes fetch the spend/mint
#                    verifying keys from it and verify shielded-pool STARKs in-node.
#                    Without it, shielded txs are REJECTED (secure default).
param(
    [int]$N = 4,
    [switch]$Fresh,
    [int]$RotateEvery = 0,
    [string]$ProverUrl = ""
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "Building hk-node (release, transparent-only)..." -ForegroundColor Cyan
# --no-default-features: sp1-sdk (in-node STARK verification) needs POSIX and cannot build
# on Windows. This launcher runs the TRANSPARENT devnet; for the shielded pool use the WSL
# launcher: ./devnet.sh --prover-url http://127.0.0.1:9911  (see devnet.sh).
cargo build --release -p hk-node --no-default-features
if ($LASTEXITCODE -ne 0) { throw "build failed" }

$bin = Join-Path $PSScriptRoot "target\release\hk-node.exe"
$home_dir = Join-Path $PSScriptRoot "devnet"

if ($Fresh -and (Test-Path $home_dir)) {
    Write-Host "Removing existing devnet state..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force $home_dir
}

if (-not (Test-Path $home_dir)) {
    & $bin testnet $N $home_dir
    if ($LASTEXITCODE -ne 0) { throw "testnet generation failed" }
}

$rotate = ""
if ($RotateEvery -gt 0) {
    $rotate = "`$env:HK_ROTATE_EVERY='$RotateEvery'; "
    Write-Host "SCMS demo: each validator rotates its operational key every $RotateEvery blocks." -ForegroundColor Magenta
}

$prover = ""
if ($ProverUrl -ne "") {
    $prover = "`$env:HK_PROVER_URL='$ProverUrl'; "
    Write-Host "Shielded pool: nodes will fetch verifying keys from $ProverUrl and verify STARKs in-node." -ForegroundColor Magenta
}

Write-Host "Launching $N validators (one window each)..." -ForegroundColor Cyan
for ($i = 0; $i -lt $N; $i++) {
    $node_home = Join-Path $home_dir "node$i"
    Start-Process powershell -ArgumentList @(
        "-NoExit",
        "-Command",
        "$rotate$prover`$env:RUST_LOG='info'; & '$bin' start '$node_home'"
    )
}

Write-Host "Done. Watch for 'Committed block' lines with matching app_hash across all windows." -ForegroundColor Green
Write-Host "(Consensus votes are hash-based LMS/HSS over SHAKE-256 - quantum-secure. State is persisted per node in consensus_state.bin. Ed25519 = libp2p transport only.)"
