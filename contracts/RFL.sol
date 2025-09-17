// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title  VibeRFL - Referral-Enabled, Collateral-Backed ERC-721
 * @notice Non-fungible "RFL" tokens that can:
 *         • lock an arbitrary ERC-20 as collateral,
 *         • be flagged as "OG" to unlock early-referral rights,
 *         • appoint a single active token per owner (tokenInUse),
 *         • forward referrals once global referrals open.
 *
 * @dev    Upgrade-safe, Pausable, Access-controlled, Reentrancy-guarded.
 *         Inherits from several OpenZeppelin upgradeable extensions.
 *
 */

import "@openzeppelin/contracts-upgradeable/token/ERC721/extensions/ERC721EnumerableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC721/extensions/ERC721BurnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/extensions/AccessControlEnumerableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/interfaces/IERC20.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

contract RFL is
    Initializable,
    ERC721EnumerableUpgradeable,
    ERC721BurnableUpgradeable,
    AccessControlEnumerableUpgradeable,
    ReentrancyGuardUpgradeable,
    PausableUpgradeable
{
    using SafeERC20 for IERC20;

    /* ─────────────────────────────── Roles ─────────────────────────────── */

    /// @notice Role that can mint standard (non-OG) RFL tokens.
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    /// @notice Role that may set protocol-level config such as collateral token.
    bytes32 public constant SETTER_ROLE = keccak256("SETTER_ROLE");

    /// @notice Role that can pause or un-pause transfers (but not other ops).
    bytes32 public constant TRANSFER_PAUSE_MANAGER_ROLE =
        keccak256("TRANSFER_PAUSE_MANAGER_ROLE");

    /// @notice Role that can fully pause / unpause the contract.
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    /* ───────────────────────── Referral States ───────────────────────── */

    /// @notice Sum of all `lockedTokens`—helps external indexers.
    uint256 public totalLockedTokens;

    /// @notice Unix timestamp after which *any* RFL NFT qualifies as referrer.
    uint256 public referralOpenTimestamp;

    /// @notice ERC-20 token accepted as collateral (can be swapped once).
    address public collateral;

    /// @notice If true, `transferInterceptor` reverts on non-mint.
    bool public isTransferPaused;

    /* ─────────────────────── Per Token States ─────────────────────── */

    /// @notice Amount of collateral current owner has locked for the token.
    mapping(uint256 => uint256) public lockedTokens;

    /// @notice Human-readable referral code ↔ tokenId conversion.
    mapping(uint256 => string) public tokenIdCode; // tokenId → code
    mapping(string => uint256) public codeTokenId; // code → tokenId

    /// @notice Flag indicating genesis ("OG") tokens—always valid referrers.
    mapping(uint256 => bool) public isOg;

    /// @notice Each owner may declare exactly one active token at a time.
    mapping(address => uint256) public tokenInUse;

    /// @notice tokenId → tokenId of the referrer NFT.
    mapping(uint256 => uint256) public referrer;

    /* ─────────────────────────────── Events ─────────────────────────────── */

    /// @notice Emitted when `amount` collateral is added to `tokenId`.
    event CollateralLocked(
        uint256 indexed tokenId,
        uint256 increasedAmount,
        uint256 totalLocked
    );

    /// @notice Emitted when `amount` collateral is removed from `tokenId`.
    event CollateralUnlocked(
        uint256 indexed tokenId,
        uint256 decreasedAmount,
        uint256 totalLocked
    );

    /// @notice Collateral ERC-20 was changed via `setCollateral`.
    event CollateralUpdated(address oldAddress, address newAddress);

    /// @notice Owner set `tokenId` as their active "token in use".
    event SetTokenInUse(uint256 indexed tokenId, address indexed account);

    /// @notice `tokenId` appointed `referrerTokenId` as its referrer.
    event SetReferrer(uint256 indexed tokenId, uint256 indexed referrerTokenId);

    /// @notice The global referral-open time changed.
    event ReferralOpenTimestampUpdated(
        uint256 oldTimestamp,
        uint256 newTimestamp
    );

    /// @notice Transfers were paused or unpaused by `sender`.
    event TransfersPaused(address sender);
    event TransfersUnpaused(address sender);

    /// @notice The OG status of `tokenId` was set to `isOg`.
    event SetOg(uint256 indexed tokenId, bool isOg);

    /* ─────────────────────────────── Errors ─────────────────────────────── */

    error InactiveReferrer(); // chosen referrer not active
    error NotNftOwner(); // caller not owner
    error ReferrerAlreadySet(); // cannot overwrite
    error InvalidTokenIdForUser(); // user does not own this id
    error CantBurnTokenWithLockedBalance(); // must unlock first
    error AlreadyLockedCollateralToken(); // collateral swap blocked
    error TransfersIsPaused(); // transfer attempted while paused
    error ZeroAmount(); // amount parameter == 0
    error InsufficientLockedCollateral(); // unlock > balance
    error NonOgReferralNotYetAllowed(); // referrals not open for non-OG
    error CodeUsed(); // chosen referral code already in use
    error AlreadyMint(); // (unused) consider deletion
    error InvalidCode(); // code does not exist

    /* ─────────────────────────── Initialization ─────────────────────────── */

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initialize the upgradeable proxy.
     * @param _admin                      Receives DEFAULT_ADMIN + SETTER etc.
     * @param _minter                     Address allowed to mint regular NFTs.
     * @param _collateral                 ERC-20 accepted for locking.
     * @param _referralOpenTimestamp      Time when any NFT becomes referrable.
     */
    function initialize(
        address _admin,
        address _minter,
        address _collateral,
        uint256 _referralOpenTimestamp
    ) public initializer {
        __ERC721Enumerable_init();
        __ERC721_init("VibeRFL", "RFL");
        __ERC721Burnable_init();
        __AccessControlEnumerable_init();
        __ReentrancyGuard_init();
        __Pausable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(SETTER_ROLE, _admin);
        _grantRole(MINTER_ROLE, _minter);
        _grantRole(TRANSFER_PAUSE_MANAGER_ROLE, _admin);
        _grantRole(PAUSER_ROLE, _admin);

        collateral = _collateral;
        referralOpenTimestamp = _referralOpenTimestamp;
    }

    /* ────────────────────────── Public Views ────────────────────────── */

    /**
     * @notice Deterministically derive a tokenId from a referral code
     *         *before* the token has been minted.
     * @dev    tokenId = uint256(keccak256(abi.encodePacked(code))).
     * @return tokenId The ID your code will map to if/when minted.
     */
    function getTokenId(string memory code) public pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(code)));
    }

    /**
     * @notice Check whether `tokenId` is currently eligible to act as referrer.
     * @dev    All OG tokens are *always* active; non-OG become active after
     *         `referralOpenTimestamp`.
     */
    function isTokenActiveReferrer(uint256 tokenId) public view returns (bool) {
        // Check if token exists first - _ownerOf returns address(0) for non-existent tokens
        if (_ownerOf(tokenId) == address(0)) return false;

        if (isOg[tokenId]) return true;
        return block.timestamp >= referralOpenTimestamp;
    }

    /**
     * @notice Convenience wrapper for `codeTokenId[code]`.
     */
    function isCodeActiveReferrer(
        string memory code
    ) public view returns (bool) {
        return isTokenActiveReferrer(codeTokenId[code]);
    }

    /**
     * @notice Enumerate the owner's tokens and return the index of `tokenId`.
     * @dev    Reverts with `InvalidTokenIdForUser` if not owned by `user`.
     */
    function getIndexOfTokenForUser(
        address user,
        uint256 tokenId
    ) public view returns (uint256) {
        for (uint256 i = 0; i < balanceOf(user); ++i) {
            if (tokenOfOwnerByIndex(user, i) == tokenId) return i;
        }
        revert InvalidTokenIdForUser();
    }

    /* ───────────────────────── External Methods ───────────────────────── */

    /**
     * @notice Mint a new RFL NFT with `code`.
     * @dev    Reverts if `code` already used. Sets token-in-use automatically
     *         if this is the owner's first RFL.
     */
    function safeMint(
        string memory code
    ) external whenNotPaused returns (uint256) {
        return __safeMint(msg.sender, code);
    }

    /**
     * @notice Mint a new RFL NFT with `code` for a specific user.
     * @dev    Only callable by MINTER_ROLE. Allows minting on behalf of another address.
     * @param user The address that will receive the NFT.
     * @param code Unique referral code for the new NFT.
     * @return tokenId The ID of the newly minted token.
     */
    function safeMintFor(
        address user,
        string memory code
    ) external onlyRole(MINTER_ROLE) whenNotPaused returns (uint256) {
        return __safeMint(user, code);
    }

    /**
     * @notice Mint with an immediate referrer assignment.
     * @param referrerTokenId Token ID of the referrer NFT.
     * @param code            Unique referral code for the new NFT.
     */
    function safeMintWithReferrer(
        uint256 referrerTokenId,
        string memory code
    ) external whenNotPaused returns (uint256 tokenId) {
        tokenId = __safeMint(msg.sender, code);
        _setReferer(tokenId, referrerTokenId);
    }

    /**
     * @notice Mint a new RFL NFT for a specific user with an immediate referrer assignment.
     * @dev    Only callable by MINTER_ROLE. Allows minting on behalf of another address.
     * @param user             The address that will receive the NFT.
     * @param referrerTokenId  Token ID of the referrer NFT.
     * @param code             Unique referral code for the new NFT.
     * @return tokenId The ID of the newly minted token.
     */
    function safeMintWithReferrerFor(
        address user,
        uint256 referrerTokenId,
        string memory code
    ) external onlyRole(MINTER_ROLE) whenNotPaused returns (uint256 tokenId) {
        tokenId = __safeMint(user, code);
        _setReferer(tokenId, referrerTokenId);
    }

    /**
     * @notice Assign a referrer by token ID (one-time action).
     */
    function setReferrerTokenId(
        uint256 tokenId,
        uint256 referrerTokenId
    ) external whenNotPaused onlyNftOwner(tokenId) {
        _setReferer(tokenId, referrerTokenId);
    }

    /**
     * @notice Assign a referrer by the referrer's code string.
     */
    function setReferrerCode(
        uint256 tokenId,
        string memory referrerCode
    ) external whenNotPaused onlyNftOwner(tokenId) {
        _setReferer(tokenId, codeTokenId[referrerCode]);
    }

    /**
     * @notice Mark one of the caller's NFTs as the active "token in use".
     * @dev    Passing tokenId==0 effectively clears the active token.
     */
    function setTokenInUse(
        address user,
        uint256 tokenId
    ) external whenNotPaused onlyNftOwner(tokenId) {
        _setTokenInUse(user, tokenId);
    }

    /**
     * @notice Lock additional collateral behind `tokenId`.
     * @param amount ERC-20 amount to transfer from caller → contract.
     */
    function increaseLockedCollateral(
        uint256 tokenId,
        uint256 amount
    ) external whenNotPaused onlyNftOwner(tokenId) nonReentrant {
        if (amount == 0) revert ZeroAmount();

        IERC20(collateral).safeTransferFrom(msg.sender, address(this), amount);
        uint256 newTotal = lockedTokens[tokenId] + amount;
        lockedTokens[tokenId] = newTotal;
        totalLockedTokens += amount;
        emit CollateralLocked(tokenId, amount, newTotal);
    }

    /**
     * @notice Unlock and withdraw collateral from `tokenId`.
     * @dev    Reverts if collateral insufficient.
     */
    function decreaseLockedCollateral(
        uint256 tokenId,
        uint256 amount
    ) external whenNotPaused onlyNftOwner(tokenId) nonReentrant {
        if (amount == 0) revert ZeroAmount();
        if (lockedTokens[tokenId] < amount)
            revert InsufficientLockedCollateral();

        uint256 newTotal = lockedTokens[tokenId] - amount;
        lockedTokens[tokenId] = newTotal;
        totalLockedTokens -= amount;
        IERC20(collateral).safeTransfer(msg.sender, amount);
        emit CollateralUnlocked(tokenId, amount, newTotal);
    }

    /* ────────────────────────── Admin Functions ────────────────────────── */

    /**
     * @notice Mint an "OG" NFT—permanent early-referrer privilege.
     * @dev    Only callable by MINTER_ROLE, not DEFAULT_ADMIN.
     */
    function ogMint(
        address user,
        string memory code
    ) public onlyRole(MINTER_ROLE) returns (uint256 tokenId) {
        tokenId = __safeMint(user, code);
        isOg[tokenId] = true;
    }

    /**
     * @notice Set the OG status of `code`.
     * @dev    Only callable by MINTER_ROLE.
     */
    function setOg(
        string memory code,
        bool _isOg
    ) external onlyRole(MINTER_ROLE) {
        uint256 tokenId = codeTokenId[code];
        if (tokenId == 0) revert InvalidCode();
        isOg[tokenId] = _isOg;
        emit SetOg(tokenId, _isOg);
    }

    /**
     * @notice Replace the ERC-20 accepted as collateral.
     * @dev    Only possible *before* any collateral is locked.
     */
    function setCollateral(address _collateral) external onlyRole(SETTER_ROLE) {
        if (totalLockedTokens > 0) revert AlreadyLockedCollateralToken();
        emit CollateralUpdated(collateral, _collateral);
        collateral = _collateral;
    }

    /**
     * @notice Update the time at which referrals open to all NFTs.
     * @dev    Useful for delaying the public-referral phase.
     */
    function setReferralOpenTimestamp(
        uint256 newReferralOpenTimestamp
    ) external onlyRole(SETTER_ROLE) {
        emit ReferralOpenTimestampUpdated(
            referralOpenTimestamp,
            newReferralOpenTimestamp
        );
        referralOpenTimestamp = newReferralOpenTimestamp;
    }

    /// @notice Pause *only* transfers (mint/burn unaffected).
    function pauseTransfers() external onlyRole(TRANSFER_PAUSE_MANAGER_ROLE) {
        isTransferPaused = true;
        emit TransfersPaused(msg.sender);
    }

    /// @notice Resume transfers.
    function unpauseTransfers() external onlyRole(TRANSFER_PAUSE_MANAGER_ROLE) {
        isTransferPaused = false;
        emit TransfersUnpaused(msg.sender);
    }

    /// @notice Pause *all* critical operations (mint, lock, transfer, etc.).
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /// @notice Unpause completely.
    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    /* ───────────────────────── Internal Helpers ───────────────────────── */

    /**
     * @dev Internal mint helper with referral-code uniqueness checks.
     */
    function __safeMint(
        address user,
        string memory code
    ) internal returns (uint256 tokenId) {
        if (codeTokenId[code] != 0) revert CodeUsed();

        tokenId = getTokenId(code);
        tokenIdCode[tokenId] = code;
        codeTokenId[code] = tokenId;

        _safeMint(user, tokenId);
    }

    /**
     * @dev Write-once referrer setter with liveness checks.
     */
    function _setReferer(uint256 tokenId, uint256 referrerTokenId) internal {
        if (referrer[tokenId] != 0) revert ReferrerAlreadySet();

        if (!isTokenActiveReferrer(referrerTokenId)) {
            if (
                !isOg[referrerTokenId] &&
                block.timestamp < referralOpenTimestamp
            ) revert NonOgReferralNotYetAllowed();
            revert InactiveReferrer();
        }

        referrer[tokenId] = referrerTokenId;
        emit SetReferrer(tokenId, referrerTokenId);
    }

    /**
     * @dev Update the active token-in-use for an owner.
     *      Setting `tokenId` to 0 clears the active token.
     */
    function _setTokenInUse(address user, uint256 tokenId) internal {
        tokenInUse[user] = tokenId;
        emit SetTokenInUse(tokenId, user);
    }

    /* ────────────────── Transfer Interception Logic ────────────────── */

    /**
     * @dev Runs on every transfer / mint / burn.
     *      Enforces pause rules, active-token housekeeping, burn safety.
     */
    function transferInterceptor(
        address from,
        address to,
        uint256 tokenId
    ) internal {
        if (isTransferPaused && from != address(0) && to != address(0))
            revert TransfersIsPaused();

        // Clear sender's active token if they just sent it away
        if (from != address(0) && tokenInUse[from] == tokenId) {
            _setTokenInUse(from, 0);
        }

        // Auto-select token for receiver if they have none
        if (to != address(0)) {
            if (tokenInUse[to] == 0) _setTokenInUse(to, tokenId);
        } else {
            // === Burning ===
            if (lockedTokens[tokenId] > 0)
                revert CantBurnTokenWithLockedBalance();

            // Clean up mappings to free storage
            referrer[tokenId] = 0;
            codeTokenId[tokenIdCode[tokenId]] = 0;
            tokenIdCode[tokenId] = "";
            isOg[tokenId] = false;
        }
    }

    /* ─────────────────────────────── Modifiers ─────────────────────────────── */

    /// @notice Restricts to *current* token owner.
    modifier onlyNftOwner(uint256 tokenId) {
        if (ownerOf(tokenId) != msg.sender) revert NotNftOwner();
        _;
    }

    /* ──────────────── Solidity-Required Override Glue ──────────────── */

    function supportsInterface(
        bytes4 interfaceId
    )
        public
        view
        override(
            AccessControlEnumerableUpgradeable,
            ERC721EnumerableUpgradeable,
            ERC721Upgradeable
        )
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }

    /**
     * @inheritdoc ERC721Upgradeable
     */
    function _update(
        address to,
        uint256 tokenId,
        address auth
    )
        internal
        override(ERC721EnumerableUpgradeable, ERC721Upgradeable)
        whenNotPaused
        returns (address)
    {
        address from = super._ownerOf(tokenId);
        transferInterceptor(from, to, tokenId);
        return super._update(to, tokenId, auth);
    }

    /**
     * @inheritdoc ERC721Upgradeable
     */
    function _increaseBalance(
        address account,
        uint128 amount
    ) internal override(ERC721EnumerableUpgradeable, ERC721Upgradeable) {
        super._increaseBalance(account, amount);
    }
}
