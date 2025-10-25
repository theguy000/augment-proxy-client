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

    # Remove any non-ASCII characters (fixes corrupted UTF-8 issues)
    $content = $content -replace '[^\x00-\x7F]', ''

    # Normalize line endings to CRLF for Windows
    $content = $content -replace "`r`n", "`n" -replace "`n", "`r`n"

    # Save with proper encoding (UTF-8 without BOM)
    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($tempScript, $content, $utf8NoBom)

    Write-Host "Executing installation..." -ForegroundColor Cyan

    # Execute the script
    & $tempScript -ProxyUsername $ProxyUsername -ProxyPassword $ProxyPassword

} finally {
    # Cleanup
    if (Test-Path $tempScript) {
        Remove-Item $tempScript -Force -ErrorAction SilentlyContinue
    }
}

