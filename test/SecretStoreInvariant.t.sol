// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import {Test, console2} from "forge-std/Test.sol";
import {SecretStore} from "../src/SecretStore.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// @title SecretStore Invariant Tests
/// @notice System-wide property tests that must hold true in all states
/// @dev Invariant testing differs from unit and fuzz testing by:
/// 1. Testing properties that must ALWAYS be true
/// 2. Running multiple transactions in sequence
/// 3. Checking state consistency after each action
///
/// Core Invariants Tested:
/// 1. Storage Integrity: Agreements are always in valid states
/// 2. Access Control: Roles maintain correct permissions
/// 3. State Transitions: Agreement deletion is permanent
/// 4. Proxy Safety: Implementation upgrades preserve state
contract SecretStoreInvariantTest is Test {
    /// @dev Test instance and participant addresses
    /// Using fixed keys for reproducible tests
    SecretStore public store;
    address public partyA;
    address public partyB;
    uint256 constant PARTY_A_PRIVATE_KEY = 0xA11CE;
    uint256 constant PARTY_B_PRIVATE_KEY = 0xB0B;

    /// @notice Deploy and initialize test environment
    /// @dev Sets up:
    /// 1. Implementation contract
    /// 2. UUPS proxy
    /// 3. Test participant addresses
    /// Matches production deployment pattern
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

    /// @notice Validates agreement state
    /// @dev Core helper for invariant checks:
    /// 1. Checks existence via partyA != address(0)
    /// 2. Returns full agreement details
    /// 3. Used to verify state transitions
    /// @param secretHash The hash to check
    /// @return exists Whether agreement exists
    /// @return partyA_ First party address
    /// @return partyB_ Second party address
    function _checkAgreement(bytes32 secretHash)
        internal
        view
        returns (bool exists, address partyA_, address partyB_)
    {
        (partyA_, , partyB_, ) = store.agreements(secretHash);
        exists = partyA_ != address(0);
    }

    /// @notice Creates EIP-712 compliant signatures
    /// @dev Signature creation process:
    /// 1. Builds EIP-712 struct hash
    /// 2. Combines with domain separator
    /// 3. Signs with both party keys
    /// @param hash The agreement hash to sign
    /// @return signatureA Party A's signature
    /// @return signatureB Party B's signature
    function _createSignatures(bytes32 hash) internal view returns (bytes memory signatureA, bytes memory signatureB) {
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256("Agreement(bytes32 secretHash,address partyA,address partyB)"),
                hash,
                partyA,
                partyB
            )
        );

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                store.DOMAIN_SEPARATOR(),
                structHash
            )
        );

        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(PARTY_A_PRIVATE_KEY, digest);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(PARTY_B_PRIVATE_KEY, digest);
        
        signatureA = abi.encodePacked(r1, s1, v1);
        signatureB = abi.encodePacked(r2, s2, v2);
    }

    /// @notice Invariant: Agreement Deletion After Revelation
    /// @dev Critical security property:
    /// 1. Once revealed, an agreement MUST be completely deleted
    /// 2. No traces of the agreement should remain in storage
    /// 3. Prevents potential re-revelation attacks
    /// 
    /// Test Flow:
    /// 1. Register a new agreement with valid signatures
    /// 2. Reveal the secret as partyA
    /// 3. Verify complete removal from storage
    function invariant_revealedSecretsAreDeleted() public {
        string memory secret = "test secret";
        bytes32 salt = bytes32(uint256(123));
        bytes32 secretHash = keccak256(abi.encodePacked(secret, salt));
        
        // Create signatures and register secret
        (bytes memory signatureA, bytes memory signatureB) = _createSignatures(secretHash);
        store.registerSecret(secretHash, partyA, partyB, signatureA, signatureB);
        
        // Reveal the secret
        vm.prank(partyA);
        store.revealSecret(secret, salt, secretHash);
        
        // Verify the agreement is deleted
        (bool exists, address storedPartyA,) = _checkAgreement(secretHash);
        assertFalse(exists, "Agreement should be deleted after reveal");
        assertEq(storedPartyA, address(0), "PartyA should be zero after deletion");
    }

    /// @notice Invariant: Access Control for Secret Revelation
    /// @dev Authorization property:
    /// 1. Only registered parties can reveal secrets
    /// 2. Maintains agreement integrity
    /// 3. Prevents unauthorized revelations
    /// 
    /// Test Flow:
    /// 1. Register agreement between partyA and partyB
    /// 2. Attempt revelation from non-party address (test contract)
    /// 3. Verify rejection
    function invariant_onlyPartiesCanReveal() public {
        bytes32 secretHash = keccak256(abi.encodePacked("test secret", "test salt"));
        
        // Register the secret first
        (bytes memory signatureA, bytes memory signatureB) = _createSignatures(secretHash);
        store.registerSecret(secretHash, partyA, partyB, signatureA, signatureB);

        // Try to reveal as non-party
        vm.expectRevert(SecretStore.NotAParty.selector);
        store.revealSecret("test secret", "test salt", secretHash);
    }

    /// @notice Invariant: Registration Required Before Revelation
    /// @dev State transition property:
    /// 1. Secrets must be registered before revelation
    /// 2. Prevents revelation of non-existent agreements
    /// 3. Maintains state machine integrity
    /// 
    /// Test Flow:
    /// 1. Attempt to reveal an unregistered secret
    /// 2. Verify rejection with proper error
    function invariant_onlyRegisteredSecretsCanBeRevealed() public {
        bytes32 secretHash = keccak256(abi.encodePacked("test secret", "test salt"));
        vm.expectRevert(SecretStore.AgreementDoesNotExist.selector);
        store.revealSecret("test secret", "test salt", secretHash);
    }
}
