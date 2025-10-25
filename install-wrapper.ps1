#
# Wrapper script to download and execute install.ps1 with proper line endings
#

param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$ProxyUsername,
    
    [Parameter(Mandatory=$true, Position=1)]
    [string]$ProxyPassword
)

$ErrorActionPreference = "Stop"

# Download the main install script
$scriptUrl = "https://raw.githubusercontent.com/theguy000/augment-proxy-client/main/install.ps1"
$tempScript = "$env:TEMP\augment-install-$(Get-Date -Format 'yyyyMMddHHmmss').ps1"

try {
    Write-Host "Downloading installation script..." -ForegroundColor Cyan
    $content = (Invoke-WebRequest -Uri $scriptUrl -UseBasicParsing).Content
    
    # Normalize line endings to CRLF for Windows
    $content = $content -replace "`r`n", "`n" -replace "`n", "`r`n"
    
    # Save with proper encoding
    [System.IO.File]::WriteAllText($tempScript, $content, [System.Text.Encoding]::UTF8)
    
    Write-Host "Executing installation..." -ForegroundColor Cyan
    
    # Execute the script
    & $tempScript -ProxyUsername $ProxyUsername -ProxyPassword $ProxyPassword
    
} finally {
    # Cleanup
    if (Test-Path $tempScript) {
        Remove-Item $tempScript -Force -ErrorAction SilentlyContinue
    }
}

