// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// @title SecretStore
/// @notice A contract for securely storing and revealing secrets between two parties
contract SecretStore is
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable
{
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    // Roles
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    // Structs
    struct Agreement {
        bytes32 secretHash;
        address partyA;
        address partyB;
        uint256 timestamp;
    }

    // State variables
    mapping(bytes32 => Agreement) public agreements;

    // Events
    event SecretRegistered(
        address indexed partyA,
        address indexed partyB,
        bytes32 secretHash
    );

    event SecretRevealed(
        bytes32 indexed agreementId,
        address indexed revealer,
        string secret,
        bytes salt
    );

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initialize the contract
    /// @param owner Address that will have admin rights
    function initialize(address owner) public initializer {
        __UUPSUpgradeable_init();
        __AccessControl_init();
        __Pausable_init();
        __ReentrancyGuard_init();

        _grantRole(DEFAULT_ADMIN_ROLE, owner);
        _grantRole(PAUSER_ROLE, owner);
        _grantRole(UPGRADER_ROLE, owner);
    }

    /// @notice Register a new secret agreement
    /// @param secretHash Hash of the secret with salt
    /// @param partyA First participant address
    /// @param partyB Second participant address
    /// @param signatureA Signature from partyA
    /// @param signatureB Signature from partyB
    function registerSecret(
        bytes32 secretHash,
        address partyA,
        address partyB,
        bytes memory signatureA,
        bytes memory signatureB
    ) external whenNotPaused nonReentrant {
        bytes32 messageHash = getMessageHash(secretHash, partyA, partyB);
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        
        require(
            ethSignedMessageHash.recover(signatureA) == partyA,
            "Invalid signature from partyA"
        );
        require(
            ethSignedMessageHash.recover(signatureB) == partyB,
            "Invalid signature from partyB"
        );

        bytes32 agreementId = keccak256(
            abi.encodePacked(secretHash, partyA, partyB, block.timestamp)
        );

        agreements[agreementId] = Agreement({
            secretHash: secretHash,
            partyA: partyA,
            partyB: partyB,
            timestamp: block.timestamp
        });

        emit SecretRegistered(partyA, partyB, secretHash);
    }

    /// @notice Reveal a previously registered secret
    /// @param secret The original secret
    /// @param salt The salt used in the hash
    /// @param agreementId The ID of the agreement
    function revealSecret(
        string memory secret,
        bytes memory salt,
        bytes32 agreementId
    ) external whenNotPaused nonReentrant {
        Agreement memory agreement = agreements[agreementId];
        require(
            msg.sender == agreement.partyA || msg.sender == agreement.partyB,
            "Only participants can reveal"
        );

        bytes32 computedHash = keccak256(abi.encodePacked(secret, salt));
        require(computedHash == agreement.secretHash, "Invalid secret or salt");

        delete agreements[agreementId];

        emit SecretRevealed(agreementId, msg.sender, secret, salt);
    }

    /// @notice Get message hash for signing
    /// @param secretHash Hash of the secret with salt
    /// @param partyA First participant address
    /// @param partyB Second participant address
    function getMessageHash(
        bytes32 secretHash,
        address partyA,
        address partyB
    ) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(secretHash, partyA, partyB));
    }

    /// @notice Pause the contract
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /// @notice Unpause the contract
    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    /// @notice Implementation of UUPS authorization
    function _authorizeUpgrade(address newImplementation)
        internal
        override
        onlyRole(UPGRADER_ROLE)
    {}
}
