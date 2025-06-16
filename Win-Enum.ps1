<#
.SYNOPSIS
   Simple Enumeration Script 

.DESCRIPTION
    This PowerShell script collects comprehensive local system and network information
    to aid in situational awareness during red team assessments or internal audits.

    Features include:
    - System and user context discovery
    - Network configuration and interface details
    - Active connections and listening services
    - Domain and group membership enumeration
    - Local users, shares, scheduled tasks, and running services
    - Optional subnet ping sweep (can be skipped with -SkipSlow)
    - Logs errors and outputs to timestamped files

.PARAMETER Verbose
    Enables real-time output to the console.

.PARAMETER SkipSlow
    Skips slower recon steps like ping sweeps and full discovery.

.PARAMETER OutputDir
    Specifies the directory to save output and error logs. Defaults to $env:TEMP.

.OUTPUTS
    A text file with reconnaissance results and an optional error log file.

.EXAMPLE
    .\Win-Enum.ps1 -Verbose
    Performs full recon with console output.

.NOTES
    Author  : Jonathan Ennis
    Version : 1.0
    License : MIT
    Date    : 2025-06-15

#>

param(
    [switch]$Verbose,
    [switch]$SkipSlow,
    [string]$OutputDir = $env:TEMP
)

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$OutputFile = "$OutputDir\network_recon_$timestamp.txt"
$ErrorFile = "$OutputDir\recon_errors_$timestamp.txt"

Function Write-Log {
    param (
        [string]$sectionTitle,
        [switch]$NoNewline
    )
    $separator = if ($NoNewline) { "" } else { "`n" }
    "$separator==== $sectionTitle ====$separator" | Out-File -Append -FilePath $OutputFile
    if ($Verbose) { Write-Host "[+] $sectionTitle" -ForegroundColor Green }
}

Function Execute-Command {
    param (
        [string]$Command,
        [string]$Description,
        [switch]$IgnoreErrors
    )
    
    try {
        Write-Log $Description
        if ($Command -like "*|*") {
            # Handle piped commands
            Invoke-Expression $Command | Out-File -Append -FilePath $OutputFile
        } else {
            # Handle regular commands
            & cmd /c $Command 2>&1 | Out-File -Append -FilePath $OutputFile
        }
    }
    catch {
        $errorMsg = "ERROR in $Description`: $($_.Exception.Message)"
        $errorMsg | Out-File -Append -FilePath $ErrorFile
        if (!$IgnoreErrors) {
            $errorMsg | Out-File -Append -FilePath $OutputFile
        }
    }
}

Write-Host "[*] Starting Enhanced Network Reconnaissance..." -ForegroundColor Yellow
Write-Host "[*] Output file: $OutputFile" -ForegroundColor Cyan

# System Information
Write-Log "System Information"
systeminfo | Out-File -Append -FilePath $OutputFile

# Current User Context
Write-Log "Current User Context"
whoami /all | Out-File -Append -FilePath $OutputFile

# IP Configuration (Enhanced)
Execute-Command "ipconfig /all" "IP Configuration (ipconfig /all)"
Execute-Command "ipconfig /displaydns" "DNS Cache (ipconfig /displaydns)"

# Network Interfaces (PowerShell method for more detail)
Write-Log "Network Adapters (PowerShell)"
Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MacAddress, LinkSpeed | 
    Format-Table -AutoSize | Out-File -Append -FilePath $OutputFile

# Routing Information
Execute-Command "route print" "Routing Table (route print)"

# ARP Table
Execute-Command "arp -a" "ARP Table (arp -a)"

# Network Shares
Execute-Command "net share" "Network Shares (net share)"
Execute-Command "net use" "Mapped Drives (net use)"

# Active Connections
Execute-Command "netstat -ano" "Active Network Connections (netstat -ano)"
Execute-Command "netstat -rn" "Routing Table via netstat (netstat -rn)"

# Listening Services
Write-Log "Listening Services Analysis"
$listening = netstat -an | Where-Object { $_ -match "LISTENING" }
$listening | Out-File -Append -FilePath $OutputFile

# Process Analysis from netstat
Write-Log "Process Analysis from Network Connections"
try {
    $netstatData = netstat -ano | Where-Object { $_ -match "\d+\.\d+\.\d+\.\d+" }
    $pidCounts = @{}
    
    foreach ($line in $netstatData) {
        $parts = $line -split '\s+' | Where-Object { $_ -ne "" }
        if ($parts.Count -ge 5) {
            $pid = $parts[-1]
            if ($pid -match '^\d+$') {
                $pidCounts[$pid] = ($pidCounts[$pid] -as [int]) + 1
            }
        }
    }
    
    $topPIDs = $pidCounts.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10
    
    foreach ($pidEntry in $topPIDs) {
        "`nPID: $($pidEntry.Key) - Connection Count: $($pidEntry.Value)" | Out-File -Append -FilePath $OutputFile
        try {
            $process = Get-Process -Id $pidEntry.Key -ErrorAction SilentlyContinue
            if ($process) {
                "Process: $($process.ProcessName) - $($process.Path)" | Out-File -Append -FilePath $OutputFile
            }
        }
        catch {
            "Could not get process details for PID $($pidEntry.Key)" | Out-File -Append -FilePath $OutputFile
        }
    }
}
catch {
    "Error analyzing PIDs: $($_.Exception.Message)" | Out-File -Append -FilePath $OutputFile
}

# Windows Firewall Status
Execute-Command "netsh advfirewall show allprofiles" "Windows Firewall Status"

# Network Discovery
if (!$SkipSlow) {
    Write-Log "Network Discovery (This may take time...)"
    
    # Get network segments from routing table
    $routes = route print | Where-Object { $_ -match "^\s*\d+\.\d+\.\d+\.\d+" }
    
    # Ping sweep of local subnet (first 10 IPs only to avoid being too slow)
    $localIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notmatch "127\.|169\.254\." }).IPAddress | Select-Object -First 1
    if ($localIP) {
        $subnet = $localIP.Substring(0, $localIP.LastIndexOf('.'))
        "`nPing sweep of local subnet ($subnet.1-10):" | Out-File -Append -FilePath $OutputFile
        
        1..10 | ForEach-Object {
            $ip = "$subnet.$_"
            $ping = Test-Connection -ComputerName $ip -Count 1 -Quiet -ErrorAction SilentlyContinue
            if ($ping) {
                "$ip - ALIVE" | Out-File -Append -FilePath $OutputFile
            }
        }
    }
}

# Domain Information
Execute-Command "nltest /domain_trusts" "Domain Trust Information" -IgnoreErrors
Execute-Command "net group `"Domain Controllers`" /domain" "Domain Controllers" -IgnoreErrors
Execute-Command "net accounts /domain" "Domain Password Policy" -IgnoreErrors

# Local Groups and Users
Execute-Command "net localgroup" "Local Groups"
Execute-Command "net user" "Local Users"

# Scheduled Tasks (Security relevant ones)
Write-Log "Scheduled Tasks (Running as SYSTEM or Administrators)"
try {
    schtasks /query /fo csv /v | ConvertFrom-Csv | Where-Object { 
        $_.'Run As User' -match "(SYSTEM|Administrator)" -and $_.'Status' -eq "Running" 
    } | Select-Object TaskName, 'Run As User', Status, 'Task To Run' | 
    Format-Table -AutoSize | Out-File -Append -FilePath $OutputFile
}
catch {
    "Error querying scheduled tasks" | Out-File -Append -FilePath $OutputFile
}

# Services
Write-Log "Running Services"
Get-WmiObject Win32_Service | Where-Object { $_.State -eq "Running" } | 
    Select-Object Name, DisplayName, StartName | 
    Sort-Object Name | Format-Table -AutoSize | Out-File -Append -FilePath $OutputFile

# Environment Variables
Write-Log "Environment Variables"
Get-ChildItem env: | Sort-Object Name | Format-Table Name, Value -AutoSize | Out-File -Append -FilePath $OutputFile

# Host File
Write-Log "Host File Contents"
try {
    Get-Content C:\Windows\System32\drivers\etc\hosts | Out-File -Append -FilePath $OutputFile
}
catch {
    "Could not read hosts file" | Out-File -Append -FilePath $OutputFile
}

# Network Profiles
Write-Log "Network Location Profiles"
Get-NetConnectionProfile | Format-Table -AutoSize | Out-File -Append -FilePath $OutputFile

# Summary
"`n" + "="*50 | Out-File -Append -FilePath $OutputFile
"RECONNAISSANCE COMPLETE" | Out-File -Append -FilePath $OutputFile
"Timestamp: $(Get-Date)" | Out-File -Append -FilePath $OutputFile
"Output file: $OutputFile" | Out-File -Append -FilePath $OutputFile
if (Test-Path $ErrorFile) {
    "Error log: $ErrorFile" | Out-File -Append -FilePath $OutputFile
}
"="*50 | Out-File -Append -FilePath $OutputFile

Write-Host "`n[+] Reconnaissance Complete!" -ForegroundColor Green
Write-Host "[+] Output saved to: $OutputFile" -ForegroundColor Cyan
if (Test-Path $ErrorFile) {
    Write-Host "[!] Some errors occurred. Check: $ErrorFile" -ForegroundColor Yellow
}

# Optional: Open output file
$response = Read-Host "`nOpen output file? (y/n)"
if ($response -eq 'y' -or $response -eq 'Y') {
    notepad $OutputFile
}
