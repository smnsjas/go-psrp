#!/bin/bash
# PSRP Complex Script Testing Suite
# Usage: ./test-scripts.sh [wsman|hvsocket]
#
# For WSMan: Set these environment variables:
#   PSRP_SERVER - Target server hostname
#   PSRP_USER - Username (e.g., DOMAIN\user for NTLM)
#   PSRP_PASSWORD - Password
#
# For HVSocket: Set these environment variables:
#   PSRP_VMID - VM GUID
#   PSRP_USER - Username
#   PSRP_PASSWORD - Password
#   PSRP_DOMAIN - Domain (use "." for local accounts)

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

TRANSPORT=${1:-wsman}
PSRP_CLIENT="./psrp-client"

# Build common args based on transport
if [ "$TRANSPORT" = "hvsocket" ]; then
    if [ -z "$PSRP_VMID" ]; then
        echo "Error: PSRP_VMID is required for HVSocket"
        exit 1
    fi
    COMMON_ARGS="-hvsocket -vmid $PSRP_VMID -user $PSRP_USER -domain ${PSRP_DOMAIN:-.}"

elif [ "$TRANSPORT" = "kerberos" ]; then
    # Kerberos authentication (using credential cache from kinit)
    if [ -z "$PSRP_SERVER" ]; then
        echo "Error: PSRP_SERVER is required for Kerberos"
        exit 1
    fi
    if [ -z "$PSRP_REALM" ]; then
        echo "Error: PSRP_REALM is required for Kerberos (e.g., WIN.DOMAIN.COM)"
        exit 1
    fi
    # Use ccache from environment or explicit path
    CCACHE_ARG=""
    if [ -n "$PSRP_CCACHE" ]; then
        CCACHE_ARG="-ccache $PSRP_CCACHE"
    elif [ -n "$KRB5CCNAME" ]; then
        CCACHE_ARG="-ccache $KRB5CCNAME"
    fi
    COMMON_ARGS="-server $PSRP_SERVER -user $PSRP_USER -kerberos -realm $PSRP_REALM $CCACHE_ARG -tls -insecure"

else
    # Default: WSMan with NTLM
    if [ -z "$PSRP_SERVER" ]; then
        echo "Error: PSRP_SERVER is required for WSMan"
        exit 1
    fi
    COMMON_ARGS="-server $PSRP_SERVER -user $PSRP_USER -tls -insecure -ntlm"
fi

run_test() {
    local name="$1"
    local script="$2"
    local expect_error="${3:-false}"
    
    echo -e "\n${YELLOW}=== Test: $name ===${NC}"
    echo "Script: $script"
    echo "---"
    
    set +e
    output=$($PSRP_CLIENT $COMMON_ARGS -script "$script" 2>&1)
    exit_code=$?
    set -e
    
    echo "$output"
    
    if [ "$expect_error" = "true" ]; then
        if echo "$output" | grep -qi "error\|fail\|exception"; then
            echo -e "${GREEN}✓ Expected error occurred${NC}"
        else
            echo -e "${RED}✗ Expected error but got success${NC}"
        fi
    else
        if [ $exit_code -eq 0 ] && ! echo "$output" | grep -qi "^Error:"; then
            echo -e "${GREEN}✓ PASSED${NC}"
        else
            echo -e "${RED}✗ FAILED (exit code: $exit_code)${NC}"
        fi
    fi
}

echo "====================================="
echo "PSRP Complex Script Test Suite"
echo "Transport: $TRANSPORT"
echo "====================================="

# Test 1: Simple command
run_test "Simple Command" \
    'Get-Process | Select-Object -First 3 Name, Id'

# Test 2: Multi-line with variables
run_test "Multi-line Script with Variables" \
    '$x = 1 + 2; $y = "Hello"; @{Sum=$x; Message=$y} | ConvertTo-Json'

# Test 3: Pipeline with filtering
run_test "Pipeline with Where-Object" \
    'Get-Process | Where-Object { $_.CPU -gt 0 } | Select-Object -First 5 Name, CPU | ConvertTo-Json'

# Test 4: Try/Catch error handling
run_test "Try/Catch Error Handling" \
    'try { Get-Item "C:\NonExistent" -ErrorAction Stop } catch { @{Error=$_.Exception.Message} | ConvertTo-Json }'

# Test 5: Non-terminating error (should continue)
run_test "Non-Terminating Error" \
    'Get-Item "C:\NonExistent" -ErrorAction SilentlyContinue; "Continued after error"'

# Test 6: Terminating error (throw)
run_test "Terminating Error (throw)" \
    'throw "Test terminating error"' \
    true

# Test 7: Multiple output objects
run_test "Multiple Output Objects" \
    '1..5 | ForEach-Object { [PSCustomObject]@{Number=$_; Squared=$_*$_} } | ConvertTo-Json'

# Test 8: Hash table output
run_test "Hashtable Output" \
    '@{Name="Test"; Value=42; Nested=@{A=1;B=2}} | ConvertTo-Json -Depth 3'

# Test 9: Array output
run_test "Array Output" \
    '@("apple", "banana", "cherry") | ConvertTo-Json'

# Test 10: Date/Time handling
run_test "DateTime Handling" \
    '[PSCustomObject]@{Now=Get-Date; UTC=(Get-Date).ToUniversalTime()} | ConvertTo-Json'

# Test 11: Large output (stress test)
run_test "Large Output (100 items)" \
    'Get-ChildItem C:\Windows\System32\*.dll -ErrorAction SilentlyContinue | Select-Object -First 100 Name, Length | ConvertTo-Json'

# Test 12: Environment variables
run_test "Environment Variables" \
    '@{ComputerName=$env:COMPUTERNAME; User=$env:USERNAME; OS=$env:OS} | ConvertTo-Json'

# Test 13: WMI/CIM Query
run_test "CIM Query (System Info)" \
    'Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, OSArchitecture | ConvertTo-Json'

# Test 14: Service status
run_test "Service Status Query" \
    'Get-Service | Where-Object Status -eq "Running" | Select-Object -First 5 Name, Status | ConvertTo-Json'

# Test 15: Nested objects
run_test "Nested Complex Objects" \
    'Get-Process | Select-Object -First 2 Name, @{N="ThreadCount";E={$_.Threads.Count}}, @{N="ModuleCount";E={$_.Modules.Count}} | ConvertTo-Json'

echo -e "\n${YELLOW}====================================="
echo "Test Suite Complete"
echo "=====================================${NC}"
