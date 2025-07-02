# Damima Complete Removal Script for Windows 11
# Run this PowerShell script as Administrator
# This script performs a comprehensive removal

Write-Host "Damima Complete Removal Script" -ForegroundColor Green
Write-Host "=================================" -ForegroundColor Green

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

if (-not $isAdmin) {
    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
    Write-Host "Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit
}

# Function to stop all related processes
function Stop-AllProcesses {
    Write-Host "Terminating all related processes..." -ForegroundColor Yellow
    $processes = @("voicemod", "voicemoddesktop", "Voicemod Desktop", "voicemeeter", "voicemod.exe", "VoicemodDesktop.exe")
    
    foreach ($process in $processes) {
        try {
            $procs = Get-Process -Name $process -ErrorAction SilentlyContinue
            if ($procs) {
                $procs | Stop-Process -Force
                Write-Host "✓ Terminated: $process" -ForegroundColor Green
            }
        }
        catch {
            # Process not found or already stopped
        }
    }
    
    # Kill any process with voicemod in the path
    try {
        Get-WmiObject Win32_Process | Where-Object { $_.CommandLine -like "*voicemod*" } | ForEach-Object {
            Stop-Process -Id $_.ProcessId -Force
            Write-Host "✓ Terminated process with voicemod path: $($_.Name)" -ForegroundColor Green
        }
    }
    catch {
        # No additional processes found
    }
}

# Function to stop Windows services
function Stop-Services {
    Write-Host "Stopping related Windows services..." -ForegroundColor Yellow
    $services = @("VoicemodService", "Voicemod", "VoicemodDriver")
    
    foreach ($service in $services) {
        try {
            $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
            if ($svc) {
                if ($svc.Status -eq 'Running') {
                    Stop-Service -Name $service -Force
                    Write-Host "✓ Stopped service: $service" -ForegroundColor Green
                }
                # Try to disable the service
                Set-Service -Name $service -StartupType Disabled
                Write-Host "✓ Disabled service: $service" -ForegroundColor Green
            }
        }
        catch {
            # Service not found
        }
    }
}

# Function to uninstall via multiple methods
function Uninstall-Application {
    Write-Host "Attempting uninstallation via multiple methods..." -ForegroundColor Yellow
    
    # Method 1: Try built-in uninstaller
    $uninstallerPaths = @(
        "$env:ProgramFiles\Voicemod Desktop\unins000.exe",
        "$env:ProgramFiles(x86)\Voicemod Desktop\unins000.exe",
        "$env:ProgramFiles\Voicemod\unins000.exe",
        "$env:ProgramFiles(x86)\Voicemod\unins000.exe"
    )
    
    $uninstallerFound = $false
    foreach ($path in $uninstallerPaths) {
        if (Test-Path $path) {
            Write-Host "✓ Found built-in uninstaller: $path" -ForegroundColor Green
            try {
                Start-Process -FilePath $path -ArgumentList "/SILENT", "/NORESTART" -Wait -NoNewWindow
                Write-Host "✓ Built-in uninstaller completed" -ForegroundColor Green
                $uninstallerFound = $true
                break
            }
            catch {
                Write-Host "✗ Built-in uninstaller failed: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }
    
    # Method 2: WMI uninstall
    if (-not $uninstallerFound) {
        Write-Host "Trying WMI uninstall method..." -ForegroundColor Yellow
        try {
            $apps = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*Voicemod*" }
            foreach ($app in $apps) {
                Write-Host "✓ Found: $($app.Name)" -ForegroundColor Green
                $app.Uninstall()
                Write-Host "✓ WMI uninstall completed for: $($app.Name)" -ForegroundColor Green
            }
        }
        catch {
            Write-Host "✗ WMI uninstall failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    
    # Method 3: Registry-based uninstall
    Write-Host "Checking registry for uninstall strings..." -ForegroundColor Yellow
    $uninstallKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    
    foreach ($keyPath in $uninstallKeys) {
        try {
            $keys = Get-ItemProperty $keyPath -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "*Voicemod*" }
            foreach ($key in $keys) {
                if ($key.UninstallString) {
                    Write-Host "✓ Found registry uninstall string: $($key.DisplayName)" -ForegroundColor Green
                    $uninstallCmd = $key.UninstallString
                    if ($uninstallCmd -like "*msiexec*") {
                        $uninstallCmd = $uninstallCmd -replace "/I", "/X"
                        $uninstallCmd += " /quiet /norestart"
                    }
                    try {
                        cmd /c $uninstallCmd
                        Write-Host "✓ Registry uninstall completed" -ForegroundColor Green
                    }
                    catch {
                        Write-Host "✗ Registry uninstall failed: $($_.Exception.Message)" -ForegroundColor Red
                    }
                }
            }
        }
        catch {
            # Key not accessible
        }
    }
}

# Function to remove all files and folders
function Remove-AllFiles {
    Write-Host "Removing all files and folders..." -ForegroundColor Yellow
    
    $paths = @(
        "$env:ProgramFiles\Voicemod Desktop",
        "$env:ProgramFiles(x86)\Voicemod Desktop",
        "$env:ProgramFiles\Voicemod",
        "$env:ProgramFiles(x86)\Voicemod",
        "$env:LOCALAPPDATA\Voicemod",
        "$env:APPDATA\Voicemod",
        "$env:USERPROFILE\AppData\Local\Voicemod",
        "$env:USERPROFILE\AppData\Roaming\Voicemod",
        "$env:USERPROFILE\Documents\Voicemod",
        "$env:PROGRAMDATA\Voicemod",
        "$env:TEMP\Voicemod",
        "$env:WINDIR\System32\drivers\voicemod*",
        "$env:WINDIR\SysWOW64\drivers\voicemod*"
    )
    
    foreach ($path in $paths) {
        if (Test-Path $path) {
            try {
                # Remove read-only attributes first
                Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
                    $_.Attributes = 'Normal'
                }
                Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
                Write-Host "✓ Removed: $path" -ForegroundColor Green
            }
            catch {
                Write-Host "✗ Could not remove: $path - $($_.Exception.Message)" -ForegroundColor Red
                # Try using takeown and icacls for stubborn files
                try {
                    cmd /c "takeown /f `"$path`" /r /d y >nul 2>&1"
                    cmd /c "icacls `"$path`" /grant administrators:F /t >nul 2>&1"
                    Remove-Item -Path $path -Recurse -Force
                    Write-Host "✓ Force removed: $path" -ForegroundColor Green
                }
                catch {
                    Write-Host "✗ Force removal also failed: $path" -ForegroundColor Red
                }
            }
        }
    }
    
    # Remove any remaining voicemod files in Windows directory
    try {
        Get-ChildItem -Path "$env:WINDIR\System32\" -Filter "*voicemod*" -ErrorAction SilentlyContinue | Remove-Item -Force
        Get-ChildItem -Path "$env:WINDIR\SysWOW64\" -Filter "*voicemod*" -ErrorAction SilentlyContinue | Remove-Item -Force
    }
    catch {
        # Files not found or permission denied
    }
}

# Function to clean all registry entries
function Clean-AllRegistry {
    Write-Host "Cleaning all registry entries..." -ForegroundColor Yellow
    
    $registryPaths = @(
        "HKCU:\Software\Voicemod",
        "HKLM:\Software\Voicemod",
        "HKLM:\Software\WOW6432Node\Voicemod",
        "HKLM:\SYSTEM\CurrentControlSet\Services\Voicemod*",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*Voicemod*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*Voicemod*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*Voicemod*"
    )
    
    foreach ($regPath in $registryPaths) {
        try {
            if ($regPath -like "*\*Voicemod*") {
                # Handle wildcard paths
                $basePath = $regPath -replace "\\\*Voicemod\*$", ""
                $keys = Get-ChildItem -Path $basePath -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*Voicemod*" }
                foreach ($key in $keys) {
                    Remove-Item -Path $key.PSPath -Recurse -Force
                    Write-Host "✓ Removed registry key: $($key.Name)" -ForegroundColor Green
                }
            }
            else {
                if (Test-Path $regPath) {
                    Remove-Item -Path $regPath -Recurse -Force
                    Write-Host "✓ Removed registry key: $regPath" -ForegroundColor Green
                }
            }
        }
        catch {
            Write-Host "✗ Could not remove registry key: $regPath - $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    
    # Clean startup entries
    $startupPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    )
    
    foreach ($startupPath in $startupPaths) {
        try {
            $startupEntries = Get-ItemProperty -Path $startupPath -ErrorAction SilentlyContinue
            $startupEntries.PSObject.Properties | Where-Object { $_.Value -like "*voicemod*" } | ForEach-Object {
                Remove-ItemProperty -Path $startupPath -Name $_.Name -Force
                Write-Host "✓ Removed startup entry: $($_.Name)" -ForegroundColor Green
            }
        }
        catch {
            # No startup entries found
        }
    }
}

# Function to clean Windows audio devices
function Clean-AudioDevices {
    Write-Host "Cleaning audio device entries..." -ForegroundColor Yellow
    
    try {
        # Remove Voicemod virtual audio devices from registry
        $audioDevicePaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\*",
            "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceClasses\*"
        )
        
        foreach ($devicePath in $audioDevicePaths) {
            Get-ChildItem -Path $devicePath -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                $props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
                if ($props -and ($props | Get-Member -Name "*" | Where-Object { $_.Definition -like "*voicemod*" })) {
                    Remove-Item -Path $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Host "✓ Removed audio device entry" -ForegroundColor Green
                }
            }
        }
    }
    catch {
        # Audio device cleanup failed
    }
}

# Main execution
Write-Host "`nStarting complete removal process..." -ForegroundColor Cyan
Write-Host "This may take a few minutes..." -ForegroundColor Yellow

try {
    Stop-AllProcesses
    Start-Sleep -Seconds 3
    
    Stop-Services
    Start-Sleep -Seconds 2
    
    Uninstall-Application
    Start-Sleep -Seconds 3
    
    Remove-AllFiles
    Start-Sleep -Seconds 2
    
    Clean-AllRegistry
    Start-Sleep -Seconds 1
    
    Clean-AudioDevices
    
    Write-Host "`n" + "="*50 -ForegroundColor Green
    Write-Host "DAMIMA REMOVAL COMPLETED SUCCESSFULLY!" -ForegroundColor Green
    Write-Host "="*50 -ForegroundColor Green
    Write-Host "`nRecommendations:" -ForegroundColor Yellow
    Write-Host "1. Restart your computer to complete the removal" -ForegroundColor White
    Write-Host "2. Check your audio settings if needed" -ForegroundColor White
    Write-Host "3. Run Windows Audio troubleshooter if audio issues occur" -ForegroundColor White
    
}
catch {
    Write-Host "`nCRITICAL ERROR: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Some components may still remain on the system." -ForegroundColor Yellow
}

Write-Host "`nPress Enter to exit..." -ForegroundColor Cyan
Read-Host
