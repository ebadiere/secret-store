// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import {Test, console2} from "forge-std/Test.sol";
import {SecretStore} from "../src/SecretStore.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// @title SecretStore Invariant Tests
/// @notice Tests that verify core invariants of the SecretStore contract
/// @dev Uses Foundry's invariant testing to ensure properties hold under all conditions
/// @custom:security Tests verify:
///  1. Agreement state consistency
///  2. Access control invariants
///  3. Deletion guarantees
contract SecretStoreInvariantTest is Test {
    SecretStore public store;
    address public partyA;
    address public partyB;
    uint256 constant PARTY_A_PRIVATE_KEY = 0xA11CE;
    uint256 constant PARTY_B_PRIVATE_KEY = 0xB0B;

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

    /// @notice Helper function to check agreement existence and get party addresses
    /// @dev Replaces the contract's agreementExists function for testing purposes
    function _checkAgreement(bytes32 secretHash)
        internal
        view
        returns (bool exists, address partyA_, address partyB_)
    {
        (partyA_, partyB_, ,) = store.agreements(secretHash);
        exists = partyA_ != address(0);
    }

    /// @notice Helper function to create test signatures
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

    /// @notice Invariant: Revealed secrets must be deleted from storage
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

    /// @notice Invariant: Only parties to an agreement can reveal the secret
    function invariant_onlyPartiesCanReveal() public {
        bytes32 secretHash = keccak256(abi.encodePacked("test secret", "test salt"));
        
        // Register the secret first
        (bytes memory signatureA, bytes memory signatureB) = _createSignatures(secretHash);
        store.registerSecret(secretHash, partyA, partyB, signatureA, signatureB);

        // Try to reveal as non-party
        vm.expectRevert("Not a party to agreement");
        store.revealSecret("test secret", "test salt", secretHash);
    }

    /// @notice Invariant: Only registered secrets can be revealed
    function invariant_onlyRegisteredSecretsCanBeRevealed() public {
        bytes32 secretHash = keccak256(abi.encodePacked("test secret", "test salt"));
        vm.expectRevert("Agreement does not exist");
        store.revealSecret("test secret", "test salt", secretHash);
    }
}
