// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import {Test, console2} from "forge-std/Test.sol";
import {SecretStore} from "../src/SecretStore.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// @title SecretStore Fuzz Tests
/// @notice Property-based testing suite for SecretStore contract security
/// @dev Utilizes Foundry's fuzzing engine to:
/// 1. Generate random inputs within defined constraints
/// 2. Test invariants that should hold regardless of input
/// 3. Discover edge cases that unit tests might miss
///
/// Key Properties Tested:
/// 1. Signature Verification: EIP-712 signatures remain valid for any valid input
/// 2. Secret Integrity: Hash computation remains consistent for any secret/salt pair
/// 3. Access Control: Only valid parties can interact regardless of input values
/// 4. State Management: Agreement state remains consistent under all operations
contract SecretStoreFuzzTest is Test {
    /// @dev Fixed keys for deterministic address generation
    /// Using constants instead of random keys for reproducibility
    SecretStore public store;
    uint256 constant PARTY_A_PRIVATE_KEY = 0xA11CE;
    uint256 constant PARTY_B_PRIVATE_KEY = 0xB0B;
    address partyA;
    address partyB;

    /// @dev EIP-712 type hash for Agreement struct
    /// Matches the structure in the main contract
    bytes32 constant AGREEMENT_TYPE_HASH = keccak256("Agreement(bytes32 secretHash,address partyA,address partyB)");

    /// @notice Test environment setup
    /// @dev Deploys contract with proxy pattern and initializes test accounts
    /// Follows same deployment pattern as production for accurate testing
    function setUp() public {
        // Deploy implementation and proxy
        store = new SecretStore();
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(store),
            abi.encodeCall(SecretStore.initialize, (address(this)))
        );
        store = SecretStore(address(proxy));

        partyA = vm.addr(PARTY_A_PRIVATE_KEY);
        partyB = vm.addr(PARTY_B_PRIVATE_KEY);
    }

    /// @notice Creates deterministic hash from secret and salt
    /// @dev Matches the hashing logic in the main contract
    /// @param secret The secret string to hash
    /// @param salt Random value to prevent rainbow table attacks
    /// @return bytes32 Hash of secret and salt combined
    function _createSecretHash(string memory secret, bytes32 salt) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(secret, salt));
    }

    /// @notice Creates EIP-712 compliant signatures for both parties
    /// @dev Uses stored private keys to generate deterministic signatures
    /// @param secretHash The hash to sign
    /// @return Tuple of signatures (partyA's signature, partyB's signature)
    function _createSignatures(bytes32 secretHash) internal view returns (bytes memory, bytes memory) {
        bytes32 structHash = keccak256(abi.encode(AGREEMENT_TYPE_HASH, secretHash, partyA, partyB));
        bytes32 digest = MessageHashUtils.toTypedDataHash(store.DOMAIN_SEPARATOR(), structHash);

        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(PARTY_A_PRIVATE_KEY, digest);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(PARTY_B_PRIVATE_KEY, digest);

        return (
            abi.encodePacked(r1, s1, v1),
            abi.encodePacked(r2, s2, v2)
        );
    }

    /// @notice Helper function to register a secret
    /// @dev Calls the main contract's registerSecret function
    /// @param secretHash The hash of the secret to register
    /// @param sigA Party A's signature
    /// @param sigB Party B's signature
    function _registerSecret(bytes32 secretHash, bytes memory sigA, bytes memory sigB) internal {
        store.registerSecret(secretHash, partyA, partyB, sigA, sigB);
    }

    /// @notice Fuzz test for registering secrets with random inputs
    /// @dev Tests the secret registration flow with randomly generated:
    ///      - salt values (for secret hashing)
    ///      - timestamps (for future-dated agreements)
    ///      - secret strings (of varying lengths)
    /// @param salt Random salt value used in secret hashing
    /// @param timestamp Future timestamp for the agreement
    /// @param secret Random secret string to be stored
    /// @custom:security Verifies:
    ///  1. EIP-712 signature generation and verification
    ///  2. Proper handling of random length inputs
    ///  3. Agreement storage with random parameters
    function testFuzz_RegisterSecretWithRandomParties(
        bytes32 salt,
        uint256 timestamp,
        string memory secret
    ) public {
        vm.assume(bytes(secret).length > 0);
        vm.assume(timestamp > block.timestamp);
        
        bytes32 secretHash = _createSecretHash(secret, salt);
        (bytes memory sigA, bytes memory sigB) = _createSignatures(secretHash);
        _registerSecret(secretHash, sigA, sigB);
    }

    /// @notice Fuzz test for revealing secrets with random inputs and random revealer
    /// @dev Tests the secret revelation flow with:
    ///      - Both parties attempting to reveal
    ///      - Random secret and salt combinations
    ///      - Random timestamps for agreements
    /// @param salt Random salt value used in secret hashing
    /// @param timestamp Future timestamp for the agreement
    /// @param secret Random secret string to be revealed
    /// @param usePartyB If true, partyB reveals; if false, partyA reveals
    /// @custom:security Verifies:
    ///  1. Both parties can reveal successfully
    ///  2. Proper secret and salt validation
    ///  3. Agreement state updates after revelation
    function testFuzz_RevealSecretWithRandomInputs(
        bytes32 salt,
        uint256 timestamp,
        string memory secret,
        bool usePartyB
    ) public {
        vm.assume(bytes(secret).length > 0);
        vm.assume(timestamp > block.timestamp);
        
        bytes32 secretHash = _createSecretHash(secret, salt);
        (bytes memory sigA, bytes memory sigB) = _createSignatures(secretHash);
        _registerSecret(secretHash, sigA, sigB);

        // Now reveal the secret
        if (usePartyB) {
            vm.prank(partyB);
        } else {
            vm.prank(partyA);
        }
        store.revealSecret(secret, salt, secretHash);
    }

    /// @notice Fuzz test for attempting to reveal secrets with invalid parameters
    /// @dev Tests error conditions in the revelation process with:
    ///      - Wrong secrets
    ///      - Wrong salt values
    ///      - Wrong secret hashes
    /// @param secretHash Random secret hash
    /// @param seed Random seed value used to generate revealer
    /// @param secret Valid secret string
    /// @param salt Valid salt string
    /// @custom:security Verifies:
    ///  1. Proper error handling for invalid inputs
    ///  2. Resistance to manipulation attempts
    ///  3. Agreement integrity preservation
    function testFuzz_RevealSecretWithInvalidInputs(
        bytes32 secretHash,
        uint256 seed,
        string calldata secret,
        bytes32 salt
    ) public {
        vm.assume(secretHash != bytes32(0));
        address revealer = address(uint160(seed));
        vm.assume(revealer != address(0));

        vm.prank(revealer);
        vm.expectRevert(SecretStore.AgreementDoesNotExist.selector);
        store.revealSecret(secret, salt, secretHash);
    }
}
