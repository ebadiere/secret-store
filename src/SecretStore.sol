// SPDX-License-Identifier: MIT
pragma solidity 0.8.22;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// @title SecretStore
/// @notice A contract for securely storing and revealing secrets between two parties
/// @dev This contract implements a secure way to store and reveal secrets between two consenting parties.
///      Each agreement is recorded with its block number to provide on-chain proof of when parties agreed.
/// @custom:security-contact security@yourproject.com
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
        address partyA;
        address partyB;
        uint256 timestamp;
        uint256 blockNumber;
    }

    // State variables
    mapping(bytes32 => Agreement) public agreements;

    // Events
    /// @notice Emitted when a new secret agreement is registered
    /// @param partyA The address of the first participant
    /// @param partyB The address of the second participant
    /// @param secretHash The hash of the secret
    /// @param blockNumber The block number when the agreement was registered
    event SecretRegistered(
        address indexed partyA,
        address indexed partyB,
        bytes32 indexed secretHash,
        uint256 blockNumber
    );

    /// @notice Emitted when a secret is revealed by one of the parties
    /// @param secretHash The hash that was used to store the secret
    /// @param revealer The address of the party revealing the secret
    /// @param secret The revealed secret string
    /// @param registeredBlockNumber The block number when the agreement was registered
    /// @param revealedBlockNumber The block number when the secret was revealed
    event SecretRevealed(
        bytes32 indexed secretHash,
        address indexed revealer,
        string secret,
        uint256 registeredBlockNumber,
        uint256 revealedBlockNumber
    );

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initialize the contract with the initial admin
    /// @dev Sets up the contract with required roles and initializes inherited contracts
    /// @param owner Address that will have admin, pauser, and upgrader roles
    function initialize(address owner) public initializer {
        __UUPSUpgradeable_init();
        __AccessControl_init();
        __Pausable_init();
        __ReentrancyGuard_init();

        _grantRole(DEFAULT_ADMIN_ROLE, owner);
        _grantRole(PAUSER_ROLE, owner);
        _grantRole(UPGRADER_ROLE, owner);
    }

    /// @notice Register a new secret agreement between two parties
    /// @dev Both parties must sign the secretHash. The secret should be hashed off-chain.
    ///      The agreement is stored with the current block number for timing verification.
    /// @param secretHash Hash of the secret (keccak256(abi.encodePacked(secret)))
    /// @param partyA Address of the first participant
    /// @param partyB Address of the second participant
    /// @param signatureA EIP-712 signature from partyA
    /// @param signatureB EIP-712 signature from partyB
    function registerSecret(
        bytes32 secretHash,
        address partyA,
        address partyB,
        bytes memory signatureA,
        bytes memory signatureB
    ) external whenNotPaused nonReentrant {
        bytes32 ethSignedMessageHash = secretHash.toEthSignedMessageHash();
        
        require(
            ethSignedMessageHash.recover(signatureA) == partyA,
            "Invalid signature from partyA"
        );
        require(
            ethSignedMessageHash.recover(signatureB) == partyB,
            "Invalid signature from partyB"
        );

        agreements[secretHash] = Agreement({
            partyA: partyA,
            partyB: partyB,
            timestamp: block.timestamp,
            blockNumber: block.number
        });

        emit SecretRegistered(partyA, partyB, secretHash, block.number);
    }

    /// @notice Reveal a previously registered secret
    /// @dev Only participants of the agreement can reveal the secret. Agreement is deleted after revelation.
    ///      Both the registration and revelation block numbers are included in the emitted event.
    /// @param secret The original secret string
    /// @param secretHash The hash of the secret used in registration
    function revealSecret(
        string memory secret,
        bytes32 secretHash
    ) external whenNotPaused nonReentrant {
        Agreement memory agreement = agreements[secretHash];
        require(
            msg.sender == agreement.partyA || msg.sender == agreement.partyB,
            "Only participants can reveal"
        );

        require(
            keccak256(abi.encodePacked(secret)) == secretHash,
            "Invalid secret"
        );

        uint256 registeredBlockNumber = agreement.blockNumber;
        delete agreements[secretHash];

        emit SecretRevealed(
            secretHash,
            msg.sender,
            secret,
            registeredBlockNumber,
            block.number
        );
    }

    /// @notice Pause all contract operations
    /// @dev Only callable by accounts with PAUSER_ROLE
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /// @notice Unpause all contract operations
    /// @dev Only callable by accounts with PAUSER_ROLE
    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    /// @notice Authorizes an upgrade to a new implementation
    /// @dev Only callable by accounts with UPGRADER_ROLE. Part of UUPS pattern
    /// @param newImplementation Address of the new implementation contract
    function _authorizeUpgrade(address newImplementation)
        internal
        override
        onlyRole(UPGRADER_ROLE)
    {}
}
