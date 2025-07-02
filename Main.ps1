# Voicemod Uninstaller Script for Windows 11
# Run this PowerShell script as Administrator

Write-Host "Voicemod Uninstaller Script" -ForegroundColor Green
Write-Host "==============================" -ForegroundColor Green

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

if (-not $isAdmin) {
    Write-Host "Please run this script as Administrator!" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit
}

# Function to stop Voicemod processes
function Stop-VoicemodProcesses {
    Write-Host "Stopping processes..." -ForegroundColor Yellow
    $processes = @("voicemod", "voicemeeter", "VoicemodDesktop")
    
    foreach ($process in $processes) {
        try {
            Get-Process -Name $process -ErrorAction SilentlyContinue | Stop-Process -Force
            Write-Host "Stopped process: $process" -ForegroundColor Green
        }
        catch {
            Write-Host "Process $process not found or already stopped" -ForegroundColor Gray
        }
    }
}

# Function to uninstall via Windows Apps
function Uninstall-VoicemodApp {
    Write-Host "Attempting to uninstall Voicemod..." -ForegroundColor Yellow
    
    # Try to find and uninstall via Get-WmiObject
    $voicemodApp = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*Voicemod*" }
    
    if ($voicemodApp) {
        Write-Host "Found Voicemod installation. Uninstalling..." -ForegroundColor Green
        $voicemodApp.Uninstall()
        Write-Host "Voicemod has been uninstalled." -ForegroundColor Green
    }
    else {
        Write-Host "Voicemod not found in installed programs." -ForegroundColor Yellow
    }
}

# Function to remove leftover files and folders
function Remove-VoicemodFiles {
    Write-Host "Removing leftover files and folders..." -ForegroundColor Yellow
    
    $paths = @(
        "$env:ProgramFiles\Voicemod Desktop",
        "$env:ProgramFiles(x86)\Voicemod Desktop",
        "$env:LOCALAPPDATA\Voicemod",
        "$env:APPDATA\Voicemod",
        "$env:USERPROFILE\Documents\Voicemod"
    )
    
    foreach ($path in $paths) {
        if (Test-Path $path) {
            try {
                Remove-Item -Path $path -Recurse -Force
                Write-Host "Removed: $path" -ForegroundColor Green
            }
            catch {
                Write-Host "Could not remove: $path - $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        else {
            Write-Host "Path not found: $path" -ForegroundColor Gray
        }
    }
}

# Function to clean registry entries
function Clean-VoicemodRegistry {
    Write-Host "Cleaning registry entries..." -ForegroundColor Yellow
    
    $registryPaths = @(
        "HKCU:\Software\Voicemod",
        "HKLM:\Software\Voicemod",
        "HKLM:\Software\WOW6432Node\Voicemod"
    )
    
    foreach ($regPath in $registryPaths) {
        if (Test-Path $regPath) {
            try {
                Remove-Item -Path $regPath -Recurse -Force
                Write-Host "Removed registry key: $regPath" -ForegroundColor Green
            }
            catch {
                Write-Host "Could not remove registry key: $regPath - $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        else {
            Write-Host "Registry key not found: $regPath" -ForegroundColor Gray
        }
    }
}

# Main execution
try {
    Stop-VoicemodProcesses
    Start-Sleep -Seconds 2
    
    Uninstall-VoicemodApp
    Start-Sleep -Seconds 2
    
    Remove-VoicemodFiles
    Start-Sleep -Seconds 1
    
    Clean-VoicemodRegistry
    
    Write-Host "`Done!" -ForegroundColor Green
    Write-Host "Please restart your computer to complete the removal process." -ForegroundColor Yellow
}
catch {
    Write-Host "An error occurred: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`nPress Enter to exit..." -ForegroundColor Cyan
Read-Host
