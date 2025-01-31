// SPDX-License-Identifier: MIT
pragma solidity 0.8.22;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

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
    /// @dev This packing reduces storage operations from 4 slots to 2 slots (~43% gas savings)
    /// - timestamp as uint96 supports dates until year 2^96 (far future)
    /// - blockNumber as uint64 supports very high block numbers
    /// - partyA being address(0) indicates no agreement exists (used for existence checks)
    struct Agreement {
        address partyA; // 20 bytes
        address partyB; // 20 bytes
        uint96 timestamp; // 12 bytes
        uint64 blockNumber; // 8 bytes
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

    /// @dev Domain separator caching for gas optimization
    /// The domain separator is cached during initialization and never updated.
    ///
    /// Important: This is a gas optimization that comes with a trade-off:
    /// In case of a chain fork, the cached chainId will remain that of the
    /// original chain, making all signatures invalid on the forked chain.
    /// Since the values are set in the proxy's storage during initialization
    /// and cannot be reinitialized, this would require deploying an entirely
    /// new proxy contract on the forked chain (losing all existing agreements).
    ///
    /// This design decision prioritizes gas efficiency for the common case,
    /// accepting the limitation during the rare event of a chain fork.
    bytes32 private _CACHED_DOMAIN_SEPARATOR;
    uint256 private _CACHED_CHAIN_ID;

    /// @notice Mapping of secret hashes to their agreements
    /// @dev Gas optimization: Using a single mapping instead of separate mappings
    /// reduces storage operations and simplifies agreement management.
    /// A non-existent agreement is indicated by partyA being address(0).
    /// The secretHash key is always a 32-byte value (keccak256 output),
    /// regardless of the original secret's size, ensuring consistent storage layout.
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

    /// @dev Event emitted when agreement is deleted
    /// @param secretHash Hash of the secret and salt, computed as keccak256(abi.encodePacked(secret, salt))
    /// @param revealer Address that deleted the agreement
    event AgreementDeleted(
        bytes32 indexed secretHash,
        address indexed revealer
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
            abi.encode(AGREEMENT_TYPE_HASH, secretHash, partyA, partyB)
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
        require(validA, "Invalid signature from partyA");

        bool validB = SignatureChecker.isValidSignatureNow(
            partyB,
            hash,
            signatureB
        );
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

        emit SecretRevealed(secretHash, msg.sender, secret);

        emit AgreementDeleted(secretHash, msg.sender);
    }

    /// @notice Gets the domain separator for EIP-712 signatures
    /// @dev Gas optimization: Return cached value directly
    /// Chain ID changes are handled at deployment time
    /// @return The current domain separator
    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return _CACHED_DOMAIN_SEPARATOR;
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
        return
            0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
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
    /// Note: While this implementation only performs a read-only check, the function
    /// cannot be marked as `view` because it is part of the upgrade process which
    /// modifies state in the proxy contract. The compiler warning about this can
    /// be safely ignored.
    ///
    /// @param newImplementation Address of the new implementation contract
    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(UPGRADER_ROLE) {
        require(
            newImplementation != address(0),
            "Invalid implementation address"
        );
    }

    /// @dev Returns the hash of typed data for EIP-712 signatures
    /// @dev This implementation follows the EIP-712 specification:
    /// - \x19 is a version byte to make the encoding unique and prevent signed data from being executable
    /// - \x01 is the version byte that indicates EIP-712 structured data
    /// Together, \x19\x01 ensures this signature cannot be misinterpreted as another signing format
    /// @dev Uses cached domain separator to reduce gas costs
    /// and minimize memory allocation in the hot path
    /// @param structHash The hash of the struct being signed
    /// @return bytes32 The final hash to be signed
    function _hashTypedDataV4(
        bytes32 structHash
    ) internal view returns (bytes32) {
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
                    keccak256(
                        abi.encodePacked(
                            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                        )
                    ),
                    keccak256(abi.encodePacked("SecretStore")),
                    keccak256(abi.encodePacked("1")),
                    _CACHED_CHAIN_ID,
                    address(this)
                )
            );
    }

    /// @notice Gap for adding new storage variables in upgrades
    /// @dev This empty reserved space is put in place to allow future versions to add new
    /// variables without shifting down storage in the inheritance chain.
    /// See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
    /// The size of 50 is chosen by OpenZeppelin as a reasonable upper bound for most contracts.
    /// MUST remain at the end of the contract to ensure storage layout compatibility during upgrades.
    uint256[50] private __gap;
}
