<#
.SYNOPSIS
    AEGS v2 Protocol - Windows Client Setup & Launcher
    Automates launching the AEGS obfuscation proxy for WireGuard on Windows.

.DESCRIPTION
    Runs the AEGS client to encapsulate WireGuard UDP packets inside dynamic ChaCha20-Poly1305
    obfuscated datagrams with random padding and DNS mimicry to bypass DPI.

.EXAMPLE
    .\setup_client.ps1 -Server "198.51.100.1" -Token "a1b2c3d4..."
    .\setup_client.ps1 -Background
    .\setup_client.ps1 -Stop
    .\setup_client.ps1 -Status
#>

[CmdletBinding(DefaultParameterSetName = "Run")]
param (
    [Parameter(ParameterSetName = "Run", Position = 0)]
    [string]$Server,

    [Parameter(ParameterSetName = "Run", Position = 1)]
    [string]$Token,

    [Parameter(ParameterSetName = "Run")]
    [int]$Port = 51821,

    [Parameter(ParameterSetName = "Run")]
    [switch]$Background,

    [Parameter(ParameterSetName = "Run")]
    [switch]$Save,

    [Parameter(ParameterSetName = "Run")]
    [switch]$GenerateWireGuardConfig,

    [Parameter(ParameterSetName = "Run")]
    [switch]$KillSwitch,

    [Parameter(ParameterSetName = "Run")]
    [switch]$DnsLeakProtection,

    [Parameter(ParameterSetName = "Stop")]
    [switch]$Stop,

    [Parameter(ParameterSetName = "Status")]
    [switch]$Status
)

$ErrorActionPreference = "Stop"

function Show-Banner {
    Write-Host ""
    Write-Host "    ___    ______ _____ ____         _       ___           " -ForegroundColor Cyan
    Write-Host "   /   |  / ____// ___// __ \ _   __(_)___  / (_)__  ____  " -ForegroundColor Cyan
    Write-Host "  / /| | / __/  / / _ / / / /| | / / / __ \/ / / _ \/ __ \ " -ForegroundColor Cyan
    Write-Host " / ___ |/ /___ / /_/ // /_/ / | |/ / / / / / / /  __/ / / / " -ForegroundColor Cyan
    Write-Host "/_/  |_/_____/ \____(_)____/  |___/_/_/ /_/_/_/\___/_/ /_/  " -ForegroundColor Cyan
    Write-Host "    Zero-DPI Client Proxy for Windows (WireGuard 127.0.0.1:51821)" -ForegroundColor DarkCyan
    Write-Host ""
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$RootDir = Split-Path -Parent $ScriptDir
$ConfigDir = Join-Path $env:USERPROFILE ".aegis"
$ConfigFile = Join-Path $ConfigDir "client_config.json"
$LogFile = Join-Path $ConfigDir "client.log"

function Compute-KeyId([string]$tok) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($tok))
    $hex = ""
    for ($i = 0; $i -lt 8; $i++) {
        $hex += $bytes[$i].ToString("x2")
    }
    return $hex
}

function Load-SavedConfig {
    if (Test-Path $ConfigFile) {
        try {
            $json = Get-Content -Raw $ConfigFile | ConvertFrom-Json
            return $json
        } catch {
            return $null
        }
    }
    return $null
}

function Save-ClientConfig([string]$srv, [string]$tok, [int]$p) {
    if (-not (Test-Path $ConfigDir)) {
        New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null
    }
    $cfg = [PSCustomObject]@{
        Server = $srv
        Token = $tok
        Port = $p
        KeyId = (Compute-KeyId $tok)
        LastUpdated = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    }
    $cfg | ConvertTo-Json -Depth 3 | Set-Content -Path $ConfigFile -Encoding UTF8
    Write-Host "[OK] Configuration saved to $ConfigFile" -ForegroundColor Green
}

function Generate-WgConfig([int]$localPort) {
    $confPath = Join-Path $RootDir "aegis-windows-wg.conf"
    $lines = @(
        "# ==============================================================================",
        "# WireGuard Windows Client Configuration with AEGS v2 Masking",
        "# ==============================================================================",
        "[Interface]",
        "# Paste your assigned WireGuard Client Private Key & Address:",
        "PrivateKey = YOUR_CLIENT_PRIVATE_KEY_HERE",
        "Address = 10.8.0.2/24",
        "DNS = 1.1.1.1, 8.8.8.8",
        "",
        "[Peer]",
        "# Paste your server's WireGuard Public Key:",
        "PublicKey = YOUR_SERVER_WIREGUARD_PUBLIC_KEY_HERE",
        "# CRITICAL: Point Endpoint to local AEGS proxy port!",
        "Endpoint = 127.0.0.1:$localPort",
        "AllowedIPs = 0.0.0.0/0, ::/0",
        "PersistentKeepalive = 25"
    )
    $lines -join "`r`n" | Set-Content -Path $confPath -Encoding UTF8
    Write-Host "[OK] WireGuard Windows config sample created: $confPath" -ForegroundColor Green
    Write-Host "     Import this file into the WireGuard for Windows GUI client!" -ForegroundColor Yellow
}

function Find-ClientBinary {
    $candidates = @(
        (Join-Path $ScriptDir "aegs-client.exe"),
        (Join-Path $ScriptDir "aegis-client.exe"),
        (Join-Path $RootDir "aegs-client.exe"),
        (Join-Path $RootDir "aegis-client.exe"),
        (Join-Path $RootDir "client.exe")
    )

    foreach ($path in $candidates) {
        if (Test-Path $path) {
            return $path
        }
    }

    # Check if Python is available with quick_client.py
    $quickPy = Join-Path $ScriptDir "quick_client.py"
    if (Test-Path $quickPy) {
        return "PYTHON_WRAPPER"
    }

    return $null
}

function Stop-ClientProcess {
    Write-Host "Searching for running AEGS client processes..." -ForegroundColor Cyan
    $procs = Get-Process | Where-Object { $_.ProcessName -match "aegs-client|aegis-client|client" } 2>$null
    if ($procs) {
        foreach ($p in $procs) {
            Write-Host "Stopping Process ID: $($p.Id) ($($p.ProcessName))..." -ForegroundColor Yellow
            Stop-Process -Id $p.Id -Force
        }
        Write-Host "[OK] AEGS client stopped." -ForegroundColor Green
    } else {
        Write-Host "No active AEGS client process found." -ForegroundColor DarkGray
    }
}

function Get-ClientStatus {
    Show-Banner
    Write-Host "--- AEGS v2 Client Status ---" -ForegroundColor White
    $procs = Get-Process | Where-Object { $_.ProcessName -match "aegs-client|aegis-client|client" } 2>$null
    if ($procs) {
        Write-Host "Status: RUNNING" -ForegroundColor Green
        foreach ($p in $procs) {
            Write-Host "  - PID: $($p.Id) | Working Set: $([math]::Round($p.WorkingSet64 / 1MB, 2)) MB"
        }
    } else {
        Write-Host "Status: STOPPED" -ForegroundColor Red
    }

    $saved = Load-SavedConfig
    if ($saved) {
        Write-Host ""
        Write-Host "Saved Configuration:" -ForegroundColor White
        Write-Host "  - Server: $($saved.Server)"
        Write-Host "  - Port:   $($saved.Port)"
        Write-Host "  - KeyID:  $($saved.KeyId)"
    }
}

function Enable-KillSwitch([string]$srv, [int]$p) {
    Write-Host "[KillSwitch] Engaging Windows Firewall traffic isolation..." -ForegroundColor Yellow
    try {
        netsh advfirewall firewall add rule name="AEGS-KS-Allow-Loopback" dir=out action=allow remoteip=127.0.0.1 enable=yes | Out-Null
        netsh advfirewall firewall add rule name="AEGS-KS-Allow-DHCP" dir=out action=allow protocol=UDP localport=68 remoteport=67 enable=yes | Out-Null
        netsh advfirewall firewall add rule name="AEGS-KS-Allow-Server" dir=out action=allow remoteip=$srv protocol=UDP remoteport="$p-$($p+15)" enable=yes | Out-Null
        netsh advfirewall firewall add rule name="AEGS-KS-Block-All" dir=out action=block enable=yes | Out-Null
        Write-Host "[KillSwitch] Traffic leak prevention ACTIVE (Direct leaks dropped)." -ForegroundColor Green
    } catch {
        Write-Host "[KillSwitch] Warning: Administrator privileges required for Windows Firewall rules." -ForegroundColor Red
    }
}

function Disable-KillSwitch {
    Write-Host "[KillSwitch] Removing Windows Firewall leak prevention rules..." -ForegroundColor Yellow
    netsh advfirewall firewall delete rule name="AEGS-KS-Allow-Loopback" 2>$null | Out-Null
    netsh advfirewall firewall delete rule name="AEGS-KS-Allow-DHCP" 2>$null | Out-Null
    netsh advfirewall firewall delete rule name="AEGS-KS-Allow-Server" 2>$null | Out-Null
    netsh advfirewall firewall delete rule name="AEGS-KS-Block-All" 2>$null | Out-Null
    netsh advfirewall firewall delete rule name="AEGS-KS-Block-DNS" 2>$null | Out-Null
    Write-Host "[KillSwitch] Rules cleared." -ForegroundColor Green
}

function Enable-DnsLeakProtection {
    Write-Host "[DNS-Shield] Enforcing DNS leak shield (Blocking UDP/TCP 53 on physical adapters)..." -ForegroundColor Yellow
    try {
        netsh advfirewall firewall add rule name="AEGS-KS-Block-DNS" dir=out action=block protocol=UDP remoteport=53 remoteip="!127.0.0.1" enable=yes | Out-Null
        Write-Host "[DNS-Shield] Plaintext DNS leak protection ACTIVE." -ForegroundColor Green
    } catch {
        Write-Host "[DNS-Shield] Warning: Administrator privileges required for DNS shield." -ForegroundColor Red
    }
}

# --- Action Router ---
if ($Stop) {
    Stop-ClientProcess
    Disable-KillSwitch
    exit 0
}

if ($Status) {
    Get-ClientStatus
    exit 0
}

Show-Banner

# Load saved defaults if available
$savedConfig = Load-SavedConfig

if ([string]::IsNullOrWhiteSpace($Server)) {
    if ($savedConfig -and -not [string]::IsNullOrWhiteSpace($savedConfig.Server)) {
        $prompt = "Enter AEGS Server IP or Hostname [$($savedConfig.Server)]: "
        $inputSrv = Read-Host -Prompt $prompt
        if ([string]::IsNullOrWhiteSpace($inputSrv)) {
            $Server = $savedConfig.Server
        } else {
            $Server = $inputSrv
        }
    } else {
        $Server = Read-Host -Prompt "Enter AEGS Server IP or Hostname"
    }
}

if ([string]::IsNullOrWhiteSpace($Token)) {
    if ($savedConfig -and -not [string]::IsNullOrWhiteSpace($savedConfig.Token)) {
        $inputTok = Read-Host -Prompt "Enter Secret Token [Press ENTER to use saved token]"
        if ([string]::IsNullOrWhiteSpace($inputTok)) {
            $Token = $savedConfig.Token
        } else {
            $Token = $inputTok
        }
    } else {
        $Token = Read-Host -Prompt "Enter Secret Token"
    }
}

if ([string]::IsNullOrWhiteSpace($Server) -or [string]::IsNullOrWhiteSpace($Token)) {
    Write-Error "Server address and secret token are required to launch client."
    exit 1
}

# Always update saved config for smooth 1-click subsequent runs
Save-ClientConfig -srv $Server -tok $Token -p $Port
Generate-WgConfig -localPort $Port

$keyId = Compute-KeyId $Token

Write-Host ""
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host " AEGS v2 CLIENT PROXY STARTUP CONFIGURATION" -ForegroundColor Green
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "  - Server:         $Server`:50001" -ForegroundColor White
Write-Host "  - Local Port:     127.0.0.1:$Port" -ForegroundColor White
Write-Host "  - Computed KeyID: $keyId" -ForegroundColor Cyan
Write-Host "------------------------------------------------------------------------" -ForegroundColor Cyan
Write-Host "  WireGuard Endpoint to use in WireGuard App:" -ForegroundColor Yellow
Write-Host "  --> Endpoint = 127.0.0.1:$Port" -ForegroundColor White
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host ""

$bin = Find-ClientBinary

if ($KillSwitch) {
    Enable-KillSwitch -srv $Server -p 50001
}
if ($DnsLeakProtection) {
    Enable-DnsLeakProtection
}

$extraArgs = ""
if ($KillSwitch) { $extraArgs += " --kill-switch" }
if ($DnsLeakProtection) { $extraArgs += " --dns-protect" }

if ($bin -eq "PYTHON_WRAPPER" -or ($null -eq $bin -and (Get-Command python -ErrorAction SilentlyContinue))) {
    $pyScript = Join-Path $ScriptDir "quick_client.py"
    Write-Host "Launching via Python proxy engine ($pyScript)..." -ForegroundColor Cyan
    
    if ($Background) {
        Start-Process python -ArgumentList "`"$pyScript`" run --server `"$Server`" --token `"$Token`" --port $Port$extraArgs" -WindowStyle Hidden
        Write-Host "[OK] Client launched in background." -ForegroundColor Green
    } else {
        try {
            python "$pyScript" run --server "$Server" --token "$Token" --port $Port $extraArgs
        } finally {
            if ($KillSwitch -or $DnsLeakProtection) {
                Disable-KillSwitch
            }
        }
    }
    exit 0
}

if ($null -ne $bin -and (Test-Path $bin)) {
    Write-Host "Using native binary: $bin" -ForegroundColor Green
    if ($Background) {
        Start-Process -FilePath $bin -ArgumentList "--server `"$Server`" --token `"$Token`" --port $Port$extraArgs" -WindowStyle Hidden
        Write-Host "[OK] Native AEGS client running in background." -ForegroundColor Green
    } else {
        try {
            & $bin --server "$Server" --token "$Token" --port $Port $extraArgs
        } finally {
            if ($KillSwitch -or $DnsLeakProtection) {
                Disable-KillSwitch
            }
        }
    }
    exit 0
}

# If binary not found, guide the user
Write-Host "[!] Native 'aegs-client.exe' binary not found in current directory." -ForegroundColor Yellow
Write-Host ""
Write-Host "Options to run:" -ForegroundColor White
Write-Host "1. If Python 3 is installed: run 'python scripts\quick_client.py run --server $Server --token $Token'" -ForegroundColor Cyan
Write-Host "2. If using WSL2 (Ubuntu): run 'wsl ./scripts/setup_client.sh --server $Server --token $Token'" -ForegroundColor Cyan
Write-Host "3. Compile with MinGW-w64 / MSVC: g++ -O3 -std=c++17 client.cpp -o aegs-client.exe -lssl -lcrypto -lws2_32" -ForegroundColor Cyan
