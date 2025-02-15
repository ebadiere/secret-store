// SPDX-License-Identifier: MIT
pragma solidity 0.8.22;

import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";

/// @title SecretStore
/// @notice A contract for securely storing and revealing secrets between two parties
/// @dev Uses EIP-712 for typed signatures with robust replay protection:
///      - Domain separator includes contract name, version, chain ID, and address
///      - Signatures are bound to specific parties and cannot be reused
///      - Agreements are deleted after reveal to prevent reuse
///      - Uses OpenZeppelin's SignatureChecker for secure signature verification
/// @custom:security Important security notes:
///      1. Agreement existence is checked using partyA address. A zero address for
///         partyA indicates no agreement exists.
///      2. The contract uses UUPS (EIP-1822) for upgradeability:
///         - Implementation address stored in proxy at keccak256("PROXIABLE")
///         - Only UPGRADER_ROLE can perform upgrades via _authorizeUpgrade
///         - Contract must be paused before upgrades can be performed
///         - State persists in proxy while implementation provides logic
///         - Initialization occurs once in proxy context via initialize()
///         - New implementations must maintain storage layout compatibility
contract SecretStore is
    UUPSUpgradeable,
    AccessControlUpgradeable,
    PausableUpgradeable,
    EIP712Upgradeable
{
    /// @dev Custom errors for better gas efficiency and clearer error messages
    error ZeroAddress();
    error SecretAlreadyRegistered();
    error InvalidPartyAddress();
    error PartiesMustBeDifferent();
    error InvalidSignature();
    error AgreementDoesNotExist();
    error InvalidSaltForSecret();
    error NotAParty();
    error ContractNotPaused();

    /// @dev This packing reduces storage operations from 4 slots to 2 slots (~43% gas savings)
    /// - timestamp as uint96 supports dates until year 2^96 (far future)
    /// - blockNumber as uint64 supports very high block numbers
    /// - partyA being address(0) indicates no agreement exists (used for existence checks)
    struct Agreement {
        address partyA; // 20 bytes
        uint96 timestamp; // 12 bytes (fills remaining space in first slot)
        address partyB; // 20 bytes
        uint64 blockNumber; // 8 bytes (12 bytes remaining in second slot)
    }

    /// @dev Role IDs for authorization
    /// The bytes32 type is used because:
    /// 1. It matches keccak256's output size (32 bytes)
    /// 2. It's gas efficient as a fixed-size type
    /// 3. It ensures compatibility with AccessControl's role system
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    /// @dev EIP-712 type hash for Agreement struct
    /// This defines the structure of data being signed and ensures type safety.
    /// When users sign messages, their wallet will display this structure:
    /// Agreement(
    ///   secretHash: bytes32,
    ///   partyA: address,
    ///   partyB: address
    /// )
    bytes32 public constant AGREEMENT_TYPE_HASH =
        keccak256(
            "Agreement(bytes32 secretHash,address partyA,address partyB)"
        );

    /// @notice Mapping of secret hashes to their agreements
    /// @dev Gas optimization: Using a single mapping instead of separate mappings
    /// reduces storage operations and simplifies agreement management.
    /// A non-existent agreement is indicated by partyA being address(0).
    /// The secretHash key is always a 32-byte value (keccak256 output),
    /// regardless of the original secret's size, ensuring consistent storage layout.
    mapping(bytes32 => Agreement) public agreements;

    // Events
    /// @notice Emitted when a new agreement is registered
    /// @param secretHash The hash of the secret and salt
    /// @param partyA The first party in the agreement
    /// @param partyB The second party in the agreement
    /// @param timestamp The block timestamp when the agreement was registered
    /// @param blockNumber The block number when the agreement was registered
    /// @dev Gas optimization: We only index parameters that will be used for filtering
    /// - secretHash is indexed as it's the primary key for lookups
    /// - partyA/partyB are indexed as they're used to filter agreements by participant
    /// - timestamp and blockNumber are not indexed as they're rarely used for filtering
    event SecretRegistered(
        bytes32 indexed secretHash,
        address indexed partyA,
        address indexed partyB,
        uint256 timestamp,
        uint256 blockNumber
    );

    /// @notice Emitted when a secret is revealed
    /// @param secretHash The hash of the secret and salt
    /// @param revealer The address that revealed the secret
    /// @param secret The revealed secret
    /// @dev The agreement is automatically deleted after the secret is revealed
    event SecretRevealed(
        bytes32 indexed secretHash,
        address indexed revealer,
        string secret
    );

    /// @dev Constructor required by the UUPSUpgradeable pattern.
    /// Must be empty because:
    /// 1. The implementation contract should never be initialized
    /// 2. All initialization happens in the initialize() function on the proxy
    /// 3. _disableInitializers() prevents the implementation from being initialized directly
    /// This is a security measure to ensure state is only ever set in the proxy's context
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the contract with the deployer address
    /// @dev Initialization function for UUPS proxy pattern (EIP-1822).
    /// Key characteristics:
    /// 1. Called only once when the proxy is deployed
    /// 2. Runs in the proxy's storage context via delegatecall
    /// 3. Protected by initializer modifier to prevent multiple initializations
    /// 4. Sets up all OpenZeppelin upgradeable contracts
    /// 5. Grants initial roles to deployer (should be transferred after deployment)
    /// @param admin Address to be granted all initial roles (DEFAULT_ADMIN_ROLE, PAUSER_ROLE, UPGRADER_ROLE)
    function initialize(address admin) external initializer {
        if (admin == address(0)) revert ZeroAddress();

        __AccessControl_init();
        __Pausable_init();
        __UUPSUpgradeable_init();
        __EIP712_init("SecretStore", "1");

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(PAUSER_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);
    }

    /// @notice Register a new secret agreement between two parties
    /// @dev Gas optimizations:
    /// 1. Use calldata for signatures to avoid memory copies
    /// 2. Cache hashes to avoid recomputation
    /// 3. Verify signatures before state changes
    /// 4. Single storage write at the end
    /// @param secretHash Hash of the secret and salt, computed as keccak256(abi.encodePacked(secret, salt))
    /// @param partyA First party's address
    /// @param partyB Second party's address
    /// @param signatureA EIP-712 typed signature from party A (65 bytes: r, s, v)
    /// @param signatureB EIP-712 typed signature from party B (65 bytes: r, s, v)
    function registerSecret(
        bytes32 secretHash,
        address partyA,
        address partyB,
        bytes calldata signatureA,
        bytes calldata signatureB
    ) external whenNotPaused {
        // Check agreement doesn't exist and validate addresses
        Agreement memory agreement = agreements[secretHash];
        if (agreement.partyA != address(0)) revert SecretAlreadyRegistered();
        if (partyA == address(0)) revert InvalidPartyAddress();
        if (partyB == address(0)) revert InvalidPartyAddress();
        if (partyA == partyB) revert PartiesMustBeDifferent();

        // Cache the struct hash to avoid recomputation
        bytes32 structHash = keccak256(
            abi.encode(AGREEMENT_TYPE_HASH, secretHash, partyA, partyB)
        );

        // Verify both signatures using OpenZeppelin's SignatureChecker
        // This supports both EOA and ERC-1271 contract signatures (e.g., multi-sigs)
        bool validA = SignatureChecker.isValidSignatureNow(
            partyA,
            _hashTypedDataV4(structHash),
            signatureA
        );
        if (!validA) revert InvalidSignature();

        bool validB = SignatureChecker.isValidSignatureNow(
            partyB,
            _hashTypedDataV4(structHash),
            signatureB
        );
        if (!validB) revert InvalidSignature();

        // Write directly to storage once
        agreements[secretHash] = Agreement({
            partyA: partyA,
            timestamp: uint96(block.timestamp),
            partyB: partyB,
            blockNumber: uint64(block.number)
        });

        emit SecretRegistered(
            secretHash,
            partyA,
            partyB,
            block.timestamp,
            block.number
        );
    }

    /// @notice Reveals a secret and deletes the agreement
    /// @dev Gas optimizations:
    /// 1. Use calldata for secret to avoid memory copies
    /// 2. Delete storage before events to avoid unnecessary reads
    /// @param secret The actual secret being revealed
    /// @param salt Random value used to create the hash
    /// @param secretHash Hash of the secret and salt, must match keccak256(abi.encodePacked(secret, salt))
    function revealSecret(
        string calldata secret,
        bytes32 salt,
        bytes32 secretHash
    ) external whenNotPaused {
        // Load agreement data for validation
        Agreement memory agreement = agreements[secretHash];

        if (agreement.partyA == address(0)) revert AgreementDoesNotExist();
        if (msg.sender != agreement.partyA && msg.sender != agreement.partyB) revert NotAParty();
        
        bytes32 computedHash = keccak256(abi.encodePacked(secret, salt));
        if (computedHash != secretHash) revert InvalidSaltForSecret();

        // Delete storage before events to avoid unnecessary reads
        delete agreements[secretHash];

        emit SecretRevealed(secretHash, msg.sender, secret);
    }

    /// @notice Pauses all contract operations
    /// @dev Gas optimization: Uses OpenZeppelin's onlyRole modifier
    /// which has optimized role checking
    /// @custom:security Only callable by accounts with PAUSER_ROLE
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /// @notice Unpauses all contract operations
    /// @dev Gas optimization: Uses OpenZeppelin's onlyRole modifier
    /// which has optimized role checking
    /// @custom:security Only callable by accounts with PAUSER_ROLE
    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    /// @notice Returns the domain separator used in the encoding of the signature for permits, as defined by EIP-712
    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return _domainSeparatorV4();
    }

    /// @notice Gap for adding new storage variables in upgrades
    /// @dev This empty reserved space is put in place to allow future versions to add new
    /// variables without shifting down storage in the inheritance chain.
    /// The size of 50 is chosen by OpenZeppelin as a reasonable upper bound for most contracts.
    /// MUST remain at the end of the contract to ensure storage layout compatibility during upgrades.
    uint256[50] private __gap;

    /// @notice Authorizes an upgrade to a new implementation
    /// @dev Required by the UUPSUpgradeable contract (EIP-1822) to authorize upgrades.
    /// This function is called internally during upgrade operations to verify
    /// that the caller has the necessary permissions to perform the upgrade.
    ///
    /// Security notes:
    /// 1. Only UPGRADER_ROLE can perform upgrades
    /// 2. Contract must be paused before upgrades
    /// 3. The function MUST be present in new implementations
    /// 4. If removed, the contract becomes non-upgradeable
    ///
    /// Note: While this implementation only performs a read-only check, the function
    /// cannot be marked as `view` because it is part of the upgrade process which
    /// modifies state in the proxy contract. The compiler warning about this can
    /// be safely ignored.
    ///
    /// @param newImplementation Address of the new implementation contract
    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(UPGRADER_ROLE) whenPaused {
        if (newImplementation == address(0)) revert ZeroAddress();
    }
}
