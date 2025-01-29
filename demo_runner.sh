#!/bin/bash

# Function to print a message and wait
print_and_wait() {
    local message="$1"
    local wait_time="$2"
    
    echo -e "\n=================================================="
    echo "$message"
    echo "Press Ctrl+C to stop the demo"
    echo "Waiting ${wait_time} seconds..."
    echo "==================================================\n"
    sleep "$wait_time"
}

# Function to print output
print_output() {
    echo -e "$1"
    sleep 2.5
}

# Start demo
print_and_wait "Starting Secret Store Demo..." 3

# Run forge and capture its output
SECRET="$SECRET" REVEAL_PARTY="$REVEAL_PARTY" forge script script/DemoSecretStore.s.sol:DemoSecretStore \
    --rpc-url http://localhost:8545 \
    --broadcast \
    --legacy \
    --ffi \
    --private-key ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 2>&1 | tee forge_output.txt

# Extract and display deployment info
echo -e "\nDeployment Information:"
grep -A 4 "=== Deployment Info ===" forge_output.txt

# Extract and display secret details
print_and_wait "Creating secret hash..." 4
echo -e "\nSecret Details:"
grep -A 3 "=== Secret Details ===" forge_output.txt

# Extract and display signatures
print_and_wait "Getting Party A's signature..." 4
echo -e "\nParty A Signature:"
grep -A 2 "=== Party A Signature ===" forge_output.txt

print_and_wait "Getting Party B's signature..." 4
echo -e "\nParty B Signature:"
grep -A 1 "=== Party B Signature ===" forge_output.txt

print_and_wait "Registering secret on-chain..." 4

print_output "\n=== Registering Secret ===\n"
print_output "Secret registered successfully!\n"

print_and_wait "Secret registered! Preparing to reveal..." 4

print_and_wait "Revealing the secret..." 4

# Extract and display revealed secret
echo -e "\nRevealed Secret:"
grep -A 3 "=== Revealed Secret ===" forge_output.txt

print_and_wait "Demo completed successfully!" 4

# Cleanup
rm -f forge_output.txt
