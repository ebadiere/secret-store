// SPDX-License-Identifier: MIT
pragma solidity 0.8.22;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "../src/SecretStore.sol";

contract SecretStoreTest is Test {
    using MessageHashUtils for bytes32;

    SecretStore public store;
    
    string constant TEST_SECRET = "my secret message";
    bytes32 constant TEST_SALT = bytes32(uint256(123)); // Random salt for testing
    bytes32 constant TEST_SECRET_HASH = keccak256(abi.encodePacked(TEST_SECRET, TEST_SALT));
    
    uint256 constant PARTY_A_PRIVATE_KEY = 0x1234;
    uint256 constant PARTY_B_PRIVATE_KEY = 0x5678;
    
    address partyA;
    address partyB;

    function setUp() public {
        // Deploy implementation and proxy
        SecretStore implementation = new SecretStore();
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(implementation),
            abi.encodeCall(SecretStore.initialize, ())
        );
        store = SecretStore(address(proxy));

        // Set up test addresses
        partyA = vm.addr(PARTY_A_PRIVATE_KEY);
        partyB = vm.addr(PARTY_B_PRIVATE_KEY);
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

        store.registerSecret(TEST_SECRET_HASH, partyA, partyB, signatureA, signatureB);

        (address storedPartyA, address storedPartyB,,,) = store.agreements(TEST_SECRET_HASH);
        assertEq(storedPartyA, partyA);
        assertEq(storedPartyB, partyB);
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

        store.revealSecret(TEST_SECRET, TEST_SALT, TEST_SECRET_HASH);

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

        store.revealSecret(TEST_SECRET, TEST_SALT, TEST_SECRET_HASH);

        // Verify agreement is deleted
        (address storedPartyA,,,,) = store.agreements(TEST_SECRET_HASH);
        assertEq(storedPartyA, address(0), "Agreement should be deleted");
    }

    function testCannotRevealByNonParticipant() public {
        // First register the secret
        (bytes memory signatureA, bytes memory signatureB) = _createSignaturesHelper(TEST_SECRET_HASH);
        store.registerSecret(TEST_SECRET_HASH, partyA, partyB, signatureA, signatureB);

        // Try to reveal as non-participant
        vm.prank(address(4));
        vm.expectRevert("Only participants can reveal");
        store.revealSecret(TEST_SECRET, TEST_SALT, TEST_SECRET_HASH);
    }

    function testCannotRevealWithWrongSecret() public {
        // First register the secret
        (bytes memory signatureA, bytes memory signatureB) = _createSignaturesHelper(TEST_SECRET_HASH);
        store.registerSecret(TEST_SECRET_HASH, partyA, partyB, signatureA, signatureB);

        // Try to reveal with wrong secret
        vm.prank(partyA);
        vm.expectRevert("Invalid secret or salt");
        store.revealSecret("wrong secret", TEST_SALT, TEST_SECRET_HASH);
    }

    function testCannotRevealWithWrongSalt() public {
        // First register the secret
        (bytes memory signatureA, bytes memory signatureB) = _createSignaturesHelper(TEST_SECRET_HASH);
        store.registerSecret(TEST_SECRET_HASH, partyA, partyB, signatureA, signatureB);

        // Try to reveal with wrong salt
        vm.prank(partyA);
        vm.expectRevert("Invalid secret or salt");
        store.revealSecret(TEST_SECRET, bytes32(uint256(456)), TEST_SECRET_HASH);
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
        store.revealSecret(TEST_SECRET, TEST_SALT, TEST_SECRET_HASH);

        // Try to reveal again
        vm.prank(partyB);
        vm.expectRevert("Only participants can reveal");
        store.revealSecret(TEST_SECRET, TEST_SALT, TEST_SECRET_HASH);
    }

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

        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(PARTY_A_PRIVATE_KEY, digest);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(PARTY_B_PRIVATE_KEY, digest);

        signatureA = abi.encodePacked(r1, s1, v1);
        signatureB = abi.encodePacked(r2, s2, v2);

        emit Debug_Signature(structHash, digest, ecrecover(digest, v1, r1, s1), partyA);
        emit Debug_Signature(structHash, digest, ecrecover(digest, v2, r2, s2), partyB);
    }
}
