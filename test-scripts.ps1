# PSRP Complex Script Testing Suite for Windows
# Usage: .\test-scripts.ps1 -Transport [wsman|kerberos|hvsocket]
#
# For WSMan/Kerberos:
#   .\test-scripts.ps1 -Transport wsman -Server myserver -User "DOMAIN\user" -Password "pass"
#   .\test-scripts.ps1 -Transport kerberos -Server myserver -User user -Realm WIN.DOMAIN.COM -CCachePath /tmp/krb5cc
#
# For HVSocket:
#   .\test-scripts.ps1 -Transport hvsocket -VMID "12345678-..." -User admin -Password pass -Domain "."

param(
    [ValidateSet("wsman", "kerberos", "hvsocket")]
    [string]$Transport = "wsman",
    
    [string]$Server,
    [string]$User,
    [string]$Password,
    [string]$VMID,
    [string]$Domain = ".",
    [string]$Realm,
    [string]$CCachePath,
    [switch]$Insecure
)

$ErrorActionPreference = "Stop"
$PSRPClient = ".\psrp-client.exe"

# Build arguments based on transport
$CommonArgs = @()

switch ($Transport) {
    "hvsocket" {
        if (-not $VMID) { throw "VMID is required for HVSocket" }
        $CommonArgs = @("-hvsocket", "-vmid", $VMID, "-user", $User, "-domain", $Domain)
    }
    "kerberos" {
        if (-not $Server) { throw "Server is required for Kerberos" }
        if (-not $Realm) { throw "Realm is required for Kerberos" }
        $CommonArgs = @("-server", $Server, "-user", $User, "-kerberos", "-realm", $Realm, "-tls")
        if ($CCachePath) { $CommonArgs += @("-ccache", $CCachePath) }
        if ($Insecure) { $CommonArgs += "-insecure" }
    }
    default {
        if (-not $Server) { throw "Server is required for WSMan" }
        $CommonArgs = @("-server", $Server, "-user", $User, "-ntlm", "-tls")
        if ($Insecure) { $CommonArgs += "-insecure" }
    }
}

# Set password environment variable
if ($Password) {
    $env:PSRP_PASSWORD = $Password
}

function Run-Test {
    param(
        [string]$Name,
        [string]$Script,
        [bool]$ExpectError = $false
    )
    
    Write-Host "`n=== Test: $Name ===" -ForegroundColor Yellow
    Write-Host "Script: $Script"
    Write-Host "---"
    
    try {
        $output = & $PSRPClient @CommonArgs -script $Script 2>&1
        $exitCode = $LASTEXITCODE
        
        Write-Host $output
        
        if ($ExpectError) {
            if ($output -match "error|fail|exception") {
                Write-Host "✓ Expected error occurred" -ForegroundColor Green
            } else {
                Write-Host "✗ Expected error but got success" -ForegroundColor Red
            }
        } else {
            if ($exitCode -eq 0 -and $output -notmatch "^Error:") {
                Write-Host "✓ PASSED" -ForegroundColor Green
            } else {
                Write-Host "✗ FAILED (exit code: $exitCode)" -ForegroundColor Red
            }
        }
    } catch {
        Write-Host "✗ EXCEPTION: $_" -ForegroundColor Red
    }
}

Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "PSRP Complex Script Test Suite"
Write-Host "Transport: $Transport"
Write-Host "=====================================" -ForegroundColor Cyan

# Test 1: Simple command
Run-Test -Name "Simple Command" `
    -Script 'Get-Process | Select-Object -First 3 Name, Id'

# Test 2: Multi-line with variables
Run-Test -Name "Multi-line Script with Variables" `
    -Script '$x = 1 + 2; $y = "Hello"; @{Sum=$x; Message=$y} | ConvertTo-Json'

# Test 3: Pipeline with filtering
Run-Test -Name "Pipeline with Where-Object" `
    -Script 'Get-Process | Where-Object { $_.CPU -gt 0 } | Select-Object -First 5 Name, CPU | ConvertTo-Json'

# Test 4: Try/Catch error handling
Run-Test -Name "Try/Catch Error Handling" `
    -Script 'try { Get-Item "C:\NonExistent" -ErrorAction Stop } catch { @{Error=$_.Exception.Message} | ConvertTo-Json }'

# Test 5: Non-terminating error
Run-Test -Name "Non-Terminating Error" `
    -Script 'Get-Item "C:\NonExistent" -ErrorAction SilentlyContinue; "Continued after error"'

# Test 6: Terminating error (throw)
Run-Test -Name "Terminating Error (throw)" `
    -Script 'throw "Test terminating error"' `
    -ExpectError $true

# Test 7: Multiple output objects
Run-Test -Name "Multiple Output Objects" `
    -Script '1..5 | ForEach-Object { [PSCustomObject]@{Number=$_; Squared=$_*$_} } | ConvertTo-Json'

# Test 8: Hash table output
Run-Test -Name "Hashtable Output" `
    -Script '@{Name="Test"; Value=42; Nested=@{A=1;B=2}} | ConvertTo-Json -Depth 3'

# Test 9: Array output
Run-Test -Name "Array Output" `
    -Script '@("apple", "banana", "cherry") | ConvertTo-Json'

# Test 10: Date/Time handling
Run-Test -Name "DateTime Handling" `
    -Script '[PSCustomObject]@{Now=Get-Date; UTC=(Get-Date).ToUniversalTime()} | ConvertTo-Json'

# Test 11: Large output (stress test)
Run-Test -Name "Large Output (100 items)" `
    -Script 'Get-ChildItem C:\Windows\System32\*.dll -ErrorAction SilentlyContinue | Select-Object -First 100 Name, Length | ConvertTo-Json'

# Test 12: Environment variables
Run-Test -Name "Environment Variables" `
    -Script '@{ComputerName=$env:COMPUTERNAME; User=$env:USERNAME; OS=$env:OS} | ConvertTo-Json'

# Test 13: CIM Query
Run-Test -Name "CIM Query (System Info)" `
    -Script 'Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, OSArchitecture | ConvertTo-Json'

# Test 14: Service status
Run-Test -Name "Service Status Query" `
    -Script 'Get-Service | Where-Object Status -eq "Running" | Select-Object -First 5 Name, Status | ConvertTo-Json'

# Test 15: Nested objects
Run-Test -Name "Nested Complex Objects" `
    -Script 'Get-Process | Select-Object -First 2 Name, @{N="ThreadCount";E={$_.Threads.Count}}, @{N="ModuleCount";E={$_.Modules.Count}} | ConvertTo-Json'

Write-Host "`n=====================================" -ForegroundColor Cyan
Write-Host "Test Suite Complete"
Write-Host "=====================================" -ForegroundColor Cyan
