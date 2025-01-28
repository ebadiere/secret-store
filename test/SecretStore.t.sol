// SPDX-License-Identifier: MIT
pragma solidity 0.8.22;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "../src/SecretStore.sol";

contract SecretStoreTest is Test {
    using MessageHashUtils for bytes32;

    SecretStore store;
    SecretStore implementation;
    
    address admin = address(1);
    address partyA;
    address partyB;
    address nonParticipant = address(4);
    
    uint256 partyAKey;
    uint256 partyBKey;
    
    string constant TEST_SECRET = "my secret";
    bytes32 constant TEST_SECRET_HASH = keccak256(abi.encodePacked("my secret"));

    // EIP-712 type hashes
    bytes32 constant DOMAIN_TYPE_HASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 constant AGREEMENT_TYPE_HASH =
        keccak256("Agreement(bytes32 secretHash,address partyA,address partyB)");

    event Debug_Signature(
        bytes32 structHash,
        bytes32 digest,
        address recovered,
        address expected
    );

    function setUp() public {
        // Deploy implementation and proxy
        implementation = new SecretStore();
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(implementation),
            abi.encodeWithSelector(SecretStore.initialize.selector)
        );
        store = SecretStore(address(proxy));

        // Setup accounts
        partyAKey = 0x1234;
        partyBKey = 0x5678;
        partyA = vm.addr(partyAKey);
        partyB = vm.addr(partyBKey);
        
        vm.deal(partyA, 1 ether);
        vm.deal(partyB, 1 ether);
        vm.label(partyA, "Party A");
        vm.label(partyB, "Party B");
    }

    function testInitialization() public {
        assertTrue(store.hasRole(store.DEFAULT_ADMIN_ROLE(), address(this)));
        assertTrue(store.hasRole(store.PAUSER_ROLE(), address(this)));
        assertTrue(store.hasRole(store.UPGRADER_ROLE(), address(this)));
    }

    function testRegisterSecret() public {
        (bytes memory signatureA, bytes memory signatureB) = _createSignaturesHelper(TEST_SECRET_HASH);

        vm.expectEmit(true, true, true, true);
        emit SecretStore.SecretRegistered(
            TEST_SECRET_HASH,
            partyA,
            partyB,
            block.timestamp,
            block.number
        );

        store.registerSecret(
            TEST_SECRET_HASH,
            partyA,
            partyB,
            signatureA,
            signatureB
        );

        (
            address storedPartyA,
            address storedPartyB,
            uint256 storedTimestamp,
            uint256 storedBlockNumber,
            bool isRevealed
        ) = store.agreements(TEST_SECRET_HASH);

        assertEq(storedPartyA, partyA);
        assertEq(storedPartyB, partyB);
        assertEq(storedBlockNumber, block.number);
        assertEq(storedTimestamp, block.timestamp);
        assertEq(isRevealed, false);
    }

    function testRevealSecret() public {
        // First register the secret
        (bytes memory signatureA, bytes memory signatureB) = _createSignaturesHelper(TEST_SECRET_HASH);
        store.registerSecret(TEST_SECRET_HASH, partyA, partyB, signatureA, signatureB);

        // Reveal the secret as partyA
        vm.prank(partyA);
        vm.expectEmit(true, true, true, true);
        emit SecretStore.SecretRevealed(
            TEST_SECRET_HASH,
            TEST_SECRET,
            partyA,
            block.timestamp,
            block.number
        );

        store.revealSecret(TEST_SECRET, TEST_SECRET_HASH);

        // Verify agreement is deleted
        (address storedPartyA,,,,) = store.agreements(TEST_SECRET_HASH);
        assertEq(storedPartyA, address(0), "Agreement should be deleted");
    }

    function testRevealSecretByPartyB() public {
        // First register the secret
        (bytes memory signatureA, bytes memory signatureB) = _createSignaturesHelper(TEST_SECRET_HASH);
        store.registerSecret(TEST_SECRET_HASH, partyA, partyB, signatureA, signatureB);

        // Reveal the secret as partyB
        vm.prank(partyB);
        vm.expectEmit(true, true, true, true);
        emit SecretStore.SecretRevealed(
            TEST_SECRET_HASH,
            TEST_SECRET,
            partyB,
            block.timestamp,
            block.number
        );

        store.revealSecret(TEST_SECRET, TEST_SECRET_HASH);

        // Verify agreement is deleted
        (address storedPartyA,,,,) = store.agreements(TEST_SECRET_HASH);
        assertEq(storedPartyA, address(0), "Agreement should be deleted");
    }

    function testCannotRevealByNonParticipant() public {
        // First register the secret
        (bytes memory signatureA, bytes memory signatureB) = _createSignaturesHelper(TEST_SECRET_HASH);
        store.registerSecret(TEST_SECRET_HASH, partyA, partyB, signatureA, signatureB);

        // Try to reveal as non-participant
        vm.prank(nonParticipant);
        vm.expectRevert("Only participants can reveal");
        store.revealSecret(TEST_SECRET, TEST_SECRET_HASH);
    }

    function testCannotRevealWithWrongSecret() public {
        // First register the secret
        (bytes memory signatureA, bytes memory signatureB) = _createSignaturesHelper(TEST_SECRET_HASH);
        store.registerSecret(TEST_SECRET_HASH, partyA, partyB, signatureA, signatureB);

        // Try to reveal with wrong secret
        vm.prank(partyA);
        vm.expectRevert("Invalid secret");
        store.revealSecret("wrong secret", TEST_SECRET_HASH);
    }

    function testCannotRegisterSameSecretTwice() public {
        (bytes memory signatureA, bytes memory signatureB) = _createSignaturesHelper(TEST_SECRET_HASH);
        store.registerSecret(TEST_SECRET_HASH, partyA, partyB, signatureA, signatureB);

        vm.expectRevert("Secret already registered");
        store.registerSecret(TEST_SECRET_HASH, partyA, partyB, signatureA, signatureB);
    }

    function testCannotRevealTwice() public {
        // First register and reveal
        (bytes memory signatureA, bytes memory signatureB) = _createSignaturesHelper(TEST_SECRET_HASH);
        store.registerSecret(TEST_SECRET_HASH, partyA, partyB, signatureA, signatureB);
        
        vm.prank(partyA);
        store.revealSecret(TEST_SECRET, TEST_SECRET_HASH);

        // Try to reveal again
        vm.prank(partyB);
        vm.expectRevert("Only participants can reveal");
        store.revealSecret(TEST_SECRET, TEST_SECRET_HASH);
    }

    // Helper functions
    function _createSignaturesHelper(bytes32 hash) 
        internal 
        returns (bytes memory signatureA, bytes memory signatureB) 
    {
        bytes32 structHash = keccak256(
            abi.encode(
                AGREEMENT_TYPE_HASH,
                hash,
                partyA,
                partyB
            )
        );

        bytes32 domainSeparator = store.DOMAIN_SEPARATOR();
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", domainSeparator, structHash)
        );

        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(partyAKey, digest);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(partyBKey, digest);

        signatureA = abi.encodePacked(r1, s1, v1);
        signatureB = abi.encodePacked(r2, s2, v2);

        emit Debug_Signature(structHash, digest, ecrecover(digest, v1, r1, s1), partyA);
        emit Debug_Signature(structHash, digest, ecrecover(digest, v2, r2, s2), partyB);
    }
}
