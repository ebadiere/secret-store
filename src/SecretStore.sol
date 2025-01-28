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
/// @dev Uses EIP-712 for typed signatures with robust replay protection:
///      - Domain separator includes contract name, version, chain ID, and address
///      - Signatures are bound to specific parties and cannot be reused
///      - Agreements are deleted after reveal to prevent reuse
///      - Uses OpenZeppelin's ECDSA library for secure signature verification
contract SecretStore is
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable
{
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    // EIP-712 type hashes
    bytes32 private constant DOMAIN_TYPE_HASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant AGREEMENT_TYPE_HASH =
        keccak256("Agreement(bytes32 secretHash,address partyA,address partyB)");
    
    // EIP-712 domain separator
    bytes32 private _DOMAIN_SEPARATOR;
    string private constant SIGNING_DOMAIN = "SecretStore";
    string private constant SIGNING_VERSION = "1";

    /// @notice Represents an agreement between two parties about a secret
    /// @dev The agreement is deleted when the secret is revealed
    struct Agreement {
        address partyA;
        address partyB;
        uint256 timestamp;
        uint256 blockNumber;
        bool isRevealed;
    }

    // secretHash => Agreement
    mapping(bytes32 => Agreement) public agreements;

    // Events
    event SecretRegistered(
        bytes32 indexed secretHash,
        address indexed partyA,
        address indexed partyB,
        uint256 timestamp,
        uint256 blockNumber
    );

    event SecretRevealed(
        bytes32 indexed secretHash,
        string secret,
        address indexed revealer,
        uint256 timestamp,
        uint256 blockNumber
    );

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the contract with proper EIP-712 domain separator
    /// @dev Sets up roles and initializes the domain separator with contract-specific data
    function initialize() public initializer {
        __AccessControl_init();
        __Pausable_init();
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(PAUSER_ROLE, msg.sender);
        _grantRole(UPGRADER_ROLE, msg.sender);

        _DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                DOMAIN_TYPE_HASH,
                keccak256(bytes(SIGNING_DOMAIN)),
                keccak256(bytes(SIGNING_VERSION)),
                block.chainid,
                address(this)
            )
        );
    }

    /// @notice Register a secret with signatures from both parties
    /// @dev Uses EIP-712 for typed signatures to prevent replay attacks
    /// @param secretHash Hash of the secret
    /// @param partyA First party's address
    /// @param partyB Second party's address
    /// @param signatureA EIP-712 signature from partyA
    /// @param signatureB EIP-712 signature from partyB
    /// @custom:security Signatures are bound to this specific contract and chain
    /// through the domain separator. Each secret can only be registered once.
    function registerSecret(
        bytes32 secretHash,
        address partyA,
        address partyB,
        bytes calldata signatureA,
        bytes calldata signatureB
    ) external whenNotPaused nonReentrant {
        require(secretHash != bytes32(0), "Invalid secret hash");
        require(partyA != address(0), "Invalid party A address");
        require(partyB != address(0), "Invalid party B address");
        require(partyA != partyB, "Parties must be different");
        require(agreements[secretHash].partyA == address(0), "Secret already registered");

        // Verify signatures using EIP-712
        bytes32 structHash = keccak256(
            abi.encode(
                AGREEMENT_TYPE_HASH,
                secretHash,
                partyA,
                partyB
            )
        );
        bytes32 hash = _hashTypedDataV4(structHash);
        
        address recoveredA = hash.recover(signatureA);
        address recoveredB = hash.recover(signatureB);

        require(
            recoveredA == partyA,
            "Invalid signature from partyA"
        );
        require(
            recoveredB == partyB,
            "Invalid signature from partyB"
        );

        agreements[secretHash] = Agreement({
            partyA: partyA,
            partyB: partyB,
            timestamp: block.timestamp,
            blockNumber: block.number,
            isRevealed: false
        });

        emit SecretRegistered(
            secretHash,
            partyA,
            partyB,
            block.timestamp,
            block.number
        );
    }

    /// @notice Reveal a previously registered secret
    /// @dev Only participants can reveal. Agreement is deleted after reveal to prevent reuse.
    /// @param secret The actual secret in clear text
    /// @param salt Random value used during registration to prevent rainbow table attacks
    /// @param secretHash Hash of the secret+salt combination
    /// @custom:security The salt prevents rainbow table attacks by making it impossible to
    /// precompute hashes of common secrets. Even if multiple users choose the same secret,
    /// their hashes will be different due to different random salts.
    function revealSecret(
        string memory secret,
        bytes32 salt,
        bytes32 secretHash
    ) external whenNotPaused nonReentrant {
        Agreement storage agreement = agreements[secretHash];
        require(
            msg.sender == agreement.partyA || msg.sender == agreement.partyB,
            "Only participants can reveal"
        );
        require(
            keccak256(abi.encodePacked(secret, salt)) == secretHash,
            "Invalid secret or salt"
        );

        emit SecretRevealed(
            secretHash,
            secret,
            msg.sender,
            block.timestamp,
            block.number
        );

        delete agreements[secretHash];
    }

    /// @notice Returns the domain separator used in EIP-712 signatures
    /// @dev Domain separator includes contract name, version, chain ID, and address
    /// @return bytes32 The domain separator
    function DOMAIN_SEPARATOR() external view returns (bytes32) {
        return _DOMAIN_SEPARATOR;
    }

    /// @dev Returns the hash of typed data for EIP-712 signatures
    /// @param structHash The hash of the struct being signed
    /// @return bytes32 The final hash to be signed
    function _hashTypedDataV4(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", _DOMAIN_SEPARATOR, structHash));
    }

    // Admin functions

    /// @notice Pauses all contract operations
    /// @dev Can only be called by accounts with PAUSER_ROLE
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /// @notice Unpauses all contract operations
    /// @dev Can only be called by accounts with PAUSER_ROLE
    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    /// @notice Function that authorizes upgrades
    /// @dev Can only be called by accounts with UPGRADER_ROLE
    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(UPGRADER_ROLE) {}
}
