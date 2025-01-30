// SPDX-License-Identifier: MIT
pragma solidity 0.8.22;

import {Test} from "forge-std/Test.sol";
import {SecretStore} from "../src/SecretStore.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

/// @title SecretStore Size Limits Test
/// @notice Test suite for verifying SecretStore's behavior with secrets of various sizes
/// @dev Tests include verification of recommended size limits and gas usage measurements
contract SecretStoreSizeLimitsTest is Test {
    using Strings for uint256;

    event SecretRevealed(bytes32 indexed secretHash, address indexed revealer, string secret);

    SecretStore public implementation;
    SecretStore public secretStore;
    address public admin = address(1);
    address public partyA = vm.addr(1);  // Use vm.addr to get address from private key
    address public partyB = vm.addr(2);  // Use vm.addr to get address from private key

    /// @notice Set up the test environment with a fresh SecretStore instance
    /// @dev Deploys implementation and proxy, sets up roles
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

    /// @notice Test the contract's ability to handle a large secret (50KB)
    /// @dev Verifies registration and revelation of a 50KB secret, which is our recommended maximum size
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

    /// @notice Test gas usage with secrets of different sizes
    /// @dev Tests secrets from 1KB to 100KB and logs gas usage for each size
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

    /// @notice Generate a string of specified size using a repeating pattern
    /// @dev Creates a string by repeating "SecretStore" until reaching desired size
    /// @param size The desired size in bytes
    /// @return A string of the specified size
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

    /// @notice Compute the EIP-712 domain separator
    /// @dev Copied from SecretStore contract for testing
    /// @return The domain separator hash
    function _computeDomainSeparator() internal view returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    keccak256(
                        abi.encodePacked(
                            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                        )
                    ),
                    keccak256(abi.encodePacked("SecretStore")),
                    keccak256(abi.encodePacked("1")),
                    block.chainid,
                    address(secretStore)
                )
            );
    }

    /// @notice Compute the EIP-712 hash
    /// @dev Copied from SecretStore contract for testing
    /// @param domainSeparator The domain separator hash
    /// @param structHash The hash of the struct being signed
    /// @return The final EIP-712 hash
    function _hashTypedDataV4(bytes32 domainSeparator, bytes32 structHash)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }
}
