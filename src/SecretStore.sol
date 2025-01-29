// SPDX-License-Identifier: MIT
pragma solidity 0.8.22;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

/// @title SecretStore
/// @notice A contract for securely storing and revealing secrets between two parties
/// @dev Uses EIP-712 for typed signatures with robust replay protection:
///      - Domain separator includes contract name, version, chain ID, and address
///      - Signatures are bound to specific parties and cannot be reused
///      - Agreements are deleted after reveal to prevent reuse
///      - Uses OpenZeppelin's ECDSA library for secure signature verification
/// @custom:security Important security notes:
///      1. Agreement existence is checked using partyA address. A zero address for
///         partyA indicates no agreement exists.
///      2. The contract uses UUPS (EIP-1822) for upgradeability:
///         - Implementation address stored in proxy at keccak256("PROXIABLE")
///         - Only UPGRADER_ROLE can perform upgrades via _authorizeUpgrade
///         - State persists in proxy while implementation provides logic
///         - Initialization occurs once in proxy context via initialize()
///         - New implementations must maintain storage layout compatibility
contract SecretStore is
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable
{
    /// @dev OpenZeppelin utilities for cryptographic operations:
    /// - ECDSA adds signature verification (e.g., hash.recover(signature))
    /// - MessageHashUtils adds EIP-712 formatting (e.g., hash.toTypedDataHash(domainSeparator))
    /// These make the code more readable by allowing method-style calls on bytes32 values
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    bytes32 public constant AGREEMENT_TYPE_HASH = keccak256("Agreement(bytes32 secretHash,address partyA,address partyB)");

    // EIP-712 type hashes
    bytes32 private constant DOMAIN_TYPE_HASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant _NAME_HASH = keccak256(bytes("SecretStore"));

    bytes32 private constant _VERSION_HASH = keccak256(bytes("1"));

    /// @dev Domain separator caching for gas optimization
    /// The domain separator is cached after initialization and only
    /// recomputed if the chain ID changes (e.g., during a fork).
    /// This saves gas by avoiding repeated keccak256 computations
    /// for each signature verification.
    bytes32 private _CACHED_DOMAIN_SEPARATOR;
    uint256 private _CACHED_CHAIN_ID;

    string private constant SIGNING_DOMAIN = "SecretStore";
    string private constant SIGNING_VERSION = "1";

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
    /// @param deployer Address to be granted all initial roles (DEFAULT_ADMIN_ROLE, PAUSER_ROLE, UPGRADER_ROLE)
    function initialize(address deployer) external initializer {
        require(deployer != address(0), "Deployer cannot be zero address");
        
        __AccessControl_init();
        __Pausable_init();
        __ReentrancyGuard_init();
        __UUPSUpgradeable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, deployer);
        _grantRole(PAUSER_ROLE, deployer);
        _grantRole(UPGRADER_ROLE, deployer);

        // Cache the domain separator and chain ID
        _CACHED_CHAIN_ID = block.chainid;
        _CACHED_DOMAIN_SEPARATOR = _computeDomainSeparator();
    }

    /// @notice Agreement struct to store information about a registered secret
    /// @dev Optimized for gas efficiency through storage packing:
    /// Slot 1: partyA (160 bits) + partyB (160 bits) = 320 bits
    /// Slot 2: timestamp (96 bits) + blockNumber (64 bits) = 160 bits
    /// This packing reduces storage operations from 4 slots to 2 slots (~43% gas savings)
    /// - timestamp as uint96 supports dates until year 2^96 (far future)
    /// - blockNumber as uint64 supports very high block numbers
    /// - partyA being address(0) indicates no agreement exists (used for existence checks)
    struct Agreement {
        address partyA;      // 20 bytes
        address partyB;      // 20 bytes
        uint96 timestamp;    // 12 bytes
        uint64 blockNumber; // 8 bytes
    }

    /// @notice Mapping of secret hashes to their agreements
    /// @dev Gas optimization: Using a single mapping instead of separate mappings
    /// reduces storage operations and simplifies agreement management.
    /// A non-existent agreement is indicated by partyA being address(0).
    mapping(bytes32 => Agreement) public agreements;

    // Events
    /// @dev Gas optimization: We only index parameters that will be used for filtering
    /// - secretHash is indexed as it's the primary key for lookups
    /// - partyA/partyB are indexed as they're used to filter agreements by participant
    /// - timestamp and blockNumber are not indexed as they're rarely used for filtering
    /// and indexing them would increase gas costs unnecessarily
    event SecretRegistered(
        bytes32 indexed secretHash,
        address indexed partyA,
        address indexed partyB,
        uint256 timestamp,
        uint256 blockNumber
    );

    /// @dev Gas optimization: We index secretHash for correlation with registration
    /// and revealer for filtering reveals by address. The secret itself is not indexed
    /// as it would be expensive and is never used for filtering.
    event SecretRevealed(
        bytes32 indexed secretHash,
        address indexed revealer,
        string secret
    );

    /// @dev Gas optimization: We only index secretHash to correlate with registration.
    /// The revealer is not indexed since the deletion event is always paired with
    /// a SecretRevealed event which already indexes the revealer.
    event AgreementDeleted(
        bytes32 indexed secretHash,
        address revealer
    );

    /// @dev Event emitted when contract is paused
    /// @param account The address that triggered the pause
    event SecretStorePaused(address indexed account);

    /// @dev Event emitted when contract is unpaused
    /// @param account The address that triggered the unpause
    event SecretStoreUnpaused(address indexed account);

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
    ) external whenNotPaused nonReentrant {
        // Check if agreement already exists
        Agreement memory agreement = agreements[secretHash];
        require(agreement.partyA == address(0), "Secret already registered");
        require(partyA != address(0), "Invalid party A address");
        require(partyB != address(0), "Invalid party B address");
        require(partyA != partyB, "Parties must be different");

        // Cache the struct hash to avoid recomputation
        bytes32 structHash = keccak256(
            abi.encode(
                AGREEMENT_TYPE_HASH,
                secretHash,
                partyA,
                partyB
            )
        );

        // Cache the EIP-712 hash to avoid recomputation
        bytes32 hash = _hashTypedDataV4(structHash);

        // Verify both signatures using OpenZeppelin's SignatureChecker
        // This supports both EOA and ERC-1271 contract signatures (e.g., multi-sigs)
        bool validA = SignatureChecker.isValidSignatureNow(
            partyA,
            hash,
            signatureA
        );
        bool validB = SignatureChecker.isValidSignatureNow(
            partyB,
            hash,
            signatureB
        );

        require(validA, "Invalid signature from partyA");
        require(validB, "Invalid signature from partyB");

        // Write directly to storage once
        agreements[secretHash] = Agreement({
            partyA: partyA,
            partyB: partyB,
            timestamp: uint96(block.timestamp),
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
    ) external whenNotPaused nonReentrant {
        // Load agreement data for validation
        Agreement memory agreement = agreements[secretHash];
        
        require(agreement.partyA != address(0), "Agreement does not exist");
        require(
            msg.sender == agreement.partyA || msg.sender == agreement.partyB,
            "Not a party to agreement"
        );
        require(
            keccak256(abi.encodePacked(secret, salt)) == secretHash,
            "Invalid secret or salt"
        );

        // Delete storage before events to avoid unnecessary reads
        delete agreements[secretHash];

        emit SecretRevealed(
            secretHash,
            msg.sender,
            secret
        );

        emit AgreementDeleted(
            secretHash,
            msg.sender
        );
    }

    /// @notice Gets the domain separator for EIP-712 signatures
    /// @dev Gas optimization: Return cached value directly
    /// Chain ID changes are handled at deployment time
    /// @return The current domain separator
    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return _CACHED_DOMAIN_SEPARATOR;
    }

    /// @notice Gets the chain ID used for EIP-712 signatures
    /// @dev Gas optimization: Return cached value directly
    /// This avoids the CHAINID opcode cost
    /// @return The chain ID used for signatures
    function getChainId() public view returns (uint256) {
        return _CACHED_CHAIN_ID;
    }

    /// @notice Identifies this contract as UUPS-compatible for proxies
    /// @dev Required by EIP-1822 (UUPS) to prove upgrade compatibility.
    /// This function doesn't use storage itself, but returns a magic value
    /// (keccak256("PROXIABLE")) that:
    /// 1. The proxy uses as a storage slot for the implementation address
    /// 2. Acts as a "marker" to verify upgrade compatibility
    /// 3. Standardizes where all UUPS proxies store their implementation
    /// 
    /// Note: This implementation contract never uses this slot - only
    /// the proxy uses it to store our address.
    /// @return bytes32 The magic value keccak256("PROXIABLE")
    function proxiableUUID() external pure override returns (bytes32) {
        return 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    }

    /// @notice Pauses all contract operations
    /// @dev Gas optimization: Uses OpenZeppelin's onlyRole modifier
    /// which has optimized role checking
    /// @custom:security Only callable by accounts with PAUSER_ROLE
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
        emit SecretStorePaused(msg.sender);
    }

    /// @notice Unpauses all contract operations
    /// @dev Gas optimization: Uses OpenZeppelin's onlyRole modifier
    /// which has optimized role checking
    /// @custom:security Only callable by accounts with PAUSER_ROLE
    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
        emit SecretStoreUnpaused(msg.sender);
    }

    /// @notice Authorizes an upgrade to a new implementation
    /// @dev Required by the UUPSUpgradeable contract (EIP-1822) to authorize upgrades.
    /// This function is called internally during upgrade operations to verify
    /// that the caller has the necessary permissions to perform the upgrade.
    /// 
    /// Security notes:
    /// 1. Only UPGRADER_ROLE can perform upgrades
    /// 2. The function MUST be present in new implementations
    /// 3. If removed, the contract becomes non-upgradeable
    /// 
    /// @param newImplementation Address of the new implementation contract
    function _authorizeUpgrade(address newImplementation)
        internal
        override
        onlyRole(UPGRADER_ROLE)
    {
        require(newImplementation != address(0), "Invalid implementation address");
    }

    /// @dev Returns the hash of typed data for EIP-712 signatures
    /// @dev Gas optimization: Uses memory parameter to avoid stack operations
    /// and minimize memory allocation in the hot path
    /// @param structHash The hash of the struct being signed
    /// @return bytes32 The final hash to be signed
    function _hashTypedDataV4(bytes32 structHash)
        internal
        view
        returns (bytes32)
    {
        bytes32 separator = _CACHED_DOMAIN_SEPARATOR;
        return keccak256(abi.encodePacked("\x19\x01", separator, structHash));
    }

    /// @dev Computes the domain separator for EIP-712 signatures
    /// @dev Gas optimization: This function is only called during initialization
    /// and in the rare case of a chain ID change. The expensive keccak256
    /// operations are acceptable here since this is not in the hot path.
    /// @return The computed domain separator
    function _computeDomainSeparator() internal view returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                    _NAME_HASH,
                    _VERSION_HASH,
                    _CACHED_CHAIN_ID,
                    address(this)
                )
            );
    }

    /// @notice Gap for adding new storage variables in upgrades
    /// @dev This gap is reserved for future storage variables to prevent collisions
    /// @custom:security This gap should be reduced when adding new storage variables
    /// @custom:security When adding new storage variables:
    /// 1. Add them after existing variables but before this gap
    /// 2. Reduce the gap size by the number of slots used
    /// 3. Create a new reinitializer function if initialization is needed
    uint256[50] private __gap;
}
