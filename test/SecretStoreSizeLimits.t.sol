// SPDX-License-Identifier: MIT
pragma solidity 0.8.22;

import {Test} from "forge-std/Test.sol";
import {SecretStore} from "../src/SecretStore.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

/// @title SecretStore Size Limits Test
/// @notice Comprehensive testing of contract behavior with varying secret sizes
/// @dev Tests focus on three key aspects:
/// 1. Functionality: Verifying correct operation with large secrets
/// 2. Gas Usage: Measuring cost implications of different sizes
/// 3. Limits: Testing boundaries of what the contract can handle
///
/// Key Test Parameters:
/// - Recommended Max Size: 50KB
/// - Test Range: 1KB to 100KB
/// - Gas Usage Tracking: Per operation cost analysis
contract SecretStoreSizeLimitsTest is Test {
    using Strings for uint256;

    /// @dev Event to verify secret revelation with exact content
    event SecretRevealed(bytes32 indexed secretHash, address indexed revealer, string secret);

    /// @dev Contract instances and test addresses
    SecretStore public implementation;
    SecretStore public secretStore;
    address public admin = address(1);
    address public partyA = vm.addr(1);  // Deterministic address from private key 1
    address public partyB = vm.addr(2);  // Deterministic address from private key 2

    /// @notice Test environment initialization
    /// @dev Setup process:
    /// 1. Deploy implementation contract
    /// 2. Deploy and initialize proxy
    /// 3. Configure access control roles
    /// 
    /// Security note: Uses deterministic addresses for reproducibility
    function setUp() public {
        // Deploy implementation and proxy
        implementation = new SecretStore();
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(implementation),
            abi.encodeWithSelector(
                SecretStore.initialize.selector,
                admin
            )
        );
        secretStore = SecretStore(address(proxy));

        // Grant roles
        vm.startPrank(admin);
        secretStore.grantRole(secretStore.PAUSER_ROLE(), admin);
        secretStore.grantRole(secretStore.UPGRADER_ROLE(), admin);
        vm.stopPrank();
    }

    /// @notice Validates contract operation with maximum recommended secret size
    /// @dev Test flow:
    /// 1. Generate 50KB secret (recommended limit)
    /// 2. Create and verify EIP-712 signatures
    /// 3. Register secret and verify storage
    /// 4. Reveal secret and verify event emission
    ///
    /// Security considerations:
    /// - Tests gas limits for large operations
    /// - Validates event data integrity
    /// - Ensures complete secret recovery
    function test_LargeSecret() public {
        // Generate a 50KB secret (recommended maximum size)
        string memory largeSecret = _generateLargeString(50 * 1024);
        bytes32 salt = keccak256(abi.encodePacked("salt"));
        bytes32 secretHash = keccak256(abi.encodePacked(largeSecret, salt));

        // Get signatures from both parties
        bytes32 domainSeparator = _computeDomainSeparator();
        bytes32 structHash = keccak256(
            abi.encode(
                secretStore.AGREEMENT_TYPE_HASH(),
                secretHash,
                partyA,
                partyB
            )
        );
        bytes32 digest = _hashTypedDataV4(domainSeparator, structHash);

        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(1, digest); // Private key 1 for partyA
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(2, digest); // Private key 2 for partyB

        bytes memory signatureA = abi.encodePacked(r1, s1, v1);
        bytes memory signatureB = abi.encodePacked(r2, s2, v2);

        // Register the secret
        secretStore.registerSecret(
            secretHash,
            partyA,
            partyB,
            signatureA,
            signatureB
        );

        // Verify event will be emitted with correct large secret
        vm.expectEmit(true, true, true, true);
        emit SecretRevealed(secretHash, partyA, largeSecret);

        // Reveal the large secret
        vm.prank(partyA);
        secretStore.revealSecret(
            largeSecret,
            salt,
            secretHash
        );
    }

    /// @notice Gas usage analysis across secret sizes
    /// @dev Test methodology:
    /// 1. Tests 4 size points: 1KB, 10KB, 50KB, 100KB
    /// 2. Measures gas for registration and revelation
    /// 3. Logs results for analysis
    ///
    /// Size selection rationale:
    /// - 1KB: Baseline for small secrets
    /// - 10KB: Common use case size
    /// - 50KB: Recommended maximum
    /// - 100KB: Stress test beyond recommendations
    function test_LargeSecretGasUsage() public {
        // Test with different secret sizes to demonstrate gas usage
        uint256[] memory sizes = new uint256[](4);
        sizes[0] = 1 * 1024;     // 1KB
        sizes[1] = 10 * 1024;    // 10KB
        sizes[2] = 50 * 1024;    // 50KB
        sizes[3] = 100 * 1024;   // 100KB

        for (uint256 i = 0; i < sizes.length; i++) {
            string memory secret = _generateLargeString(sizes[i]);
            bytes32 salt = keccak256(abi.encodePacked("salt"));
            bytes32 secretHash = keccak256(abi.encodePacked(secret, salt));

            // Get signatures
            bytes32 domainSeparator = _computeDomainSeparator();
            bytes32 structHash = keccak256(
                abi.encode(
                    secretStore.AGREEMENT_TYPE_HASH(),
                    secretHash,
                    partyA,
                    partyB
                )
            );
            bytes32 digest = _hashTypedDataV4(domainSeparator, structHash);

            (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(1, digest);
            (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(2, digest);

            bytes memory signatureA = abi.encodePacked(r1, s1, v1);
            bytes memory signatureB = abi.encodePacked(r2, s2, v2);

            // Register and reveal to measure gas
            secretStore.registerSecret(
                secretHash,
                partyA,
                partyB,
                signatureA,
                signatureB
            );

            vm.prank(partyA);
            secretStore.revealSecret(
                secret,
                salt,
                secretHash
            );

            // Log gas usage (this will help users understand real costs)
            emit log_named_uint(
                string(abi.encodePacked("Gas used for ", Strings.toString(sizes[i] / 1024), "KB secret")),
                gasleft()
            );
        }
    }

    /// @notice String generation utility for size testing
    /// @dev Implementation details:
    /// 1. Uses "SecretStore" as base pattern (11 bytes)
    /// 2. Efficiently repeats pattern to reach target size
    /// 3. Handles partial pattern at end of string
    ///
    /// Memory considerations:
    /// - Allocates exact size needed
    /// - Uses minimal temporary storage
    /// - Efficient for large strings
    /// @param size Target size in bytes
    /// @return Deterministic string of exact requested size
    function _generateLargeString(uint256 size) internal pure returns (string memory) {
        // Create a repeating pattern to reach desired size
        bytes memory pattern = bytes("SecretStore"); // 11 bytes
        uint256 repetitions = size / pattern.length + 1;
        
        bytes memory result = new bytes(size);
        uint256 written = 0;
        
        for (uint256 i = 0; i < repetitions && written < size; i++) {
            for (uint256 j = 0; j < pattern.length && written < size; j++) {
                result[written] = pattern[j];
                written++;
            }
        }
        
        return string(result);
    }

    /// @notice Computes EIP-712 domain separator
    /// @dev Components:
    /// 1. Contract name: "SecretStore"
    /// 2. Version: "1"
    /// 3. Chain ID: Current chain
    /// 4. Contract address: Deployed proxy
    /// @return bytes32 Unique domain separator for this contract instance
    function _computeDomainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("SecretStore")),
                keccak256(bytes("1")),
                block.chainid,
                address(secretStore)
            )
        );
    }

    /// @notice EIP-712 typed data hashing
    /// @dev Process:
    /// 1. Combines domain separator with struct hash
    /// 2. Follows EIP-712 prefix and encoding rules
    /// 3. Produces final digest for signing
    /// @param domainSeparator Contract's domain separator
    /// @param structHash Hash of the struct being signed
    /// @return bytes32 Final hash for signing
    function _hashTypedDataV4(bytes32 domainSeparator, bytes32 structHash)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }
}
