// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title  Rakeback
 * @notice Handles rakeback distribution and referral rewards for RFL NFT holders.
 *         Supports both trading rewards and referral commissions with signature-based
 *         authorization and automatic fee collection from multiple FeeCollectors.
 *
 * @dev    Upgrade-safe, Access-controlled, Reentrancy-guarded.
 *         Integrates with Symmio, MultiAccount, RFL NFTs, and multiple FeeCollector contracts.
 */

import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/interfaces/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import "@openzeppelin/contracts-upgradeable/access/extensions/AccessControlEnumerableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import "./interfaces/IRFL.sol";
import "./interfaces/ISymmio.sol";
import "./interfaces/IMultiAccount.sol";
import "./interfaces/IFeeCollector.sol";

contract Rakeback is
    AccessControlEnumerableUpgradeable,
    ReentrancyGuardUpgradeable
{
    using SafeERC20 for IERC20;
    using EnumerableSet for EnumerableSet.AddressSet;

    /* ─────────────────────────────── Roles ─────────────────────────────── */

    /// @notice Role that can update contract configuration and addresses.
    bytes32 public constant SETTER_ROLE = keccak256("SETTER_ROLE");

    /// @notice Role that can claim vibe fees on behalf of the protocol.
    bytes32 public constant VIBE_COLLECTOR_ROLE =
        keccak256("VIBE_COLLECTOR_ROLE");

    /* ────────────────────────── Constants ────────────────────────── */

    /// @notice Claim type identifier for trading rewards.
    uint8 public constant TRADING_CLAIM = 1;

    /// @notice Claim type identifier for referral commissions.
    uint8 public constant REFERRAL_CLAIM = 2;

    /* ──────────────────────── Storage Variables ──────────────────────── */

    /// @notice DEPRECATED: kept for storage compatibility.
    /// @notice Symmio protocol contract address for depositing rewards.
    address public symmio_deprecated;

    /// @notice MultiAccount contract for managing account ownership.
    address public multiAccount;

    /// @notice RFL NFT contract address for referral system.
    address public rfl;

    /// @notice DEPRECATED: kept for storage compatibility.
    /// @dev Use feeCollectors set instead. This variable is maintained for upgrade compatibility.
    address public feeCollector_deprecated;

    /// @notice ERC-20 token used for rakeback payments (derived from Symmio).
    address public rakebackToken;

    /// @notice Address authorized to sign claim authorizations.
    address public vibeSigner;

    /// @notice Recipient address for vibe fee distributions.
    address public vibeFeeReceiver;

    /// @notice Time window (in seconds) for signature validity.
    uint256 public signatureValidTime;

    /// @notice Tracks cumulative claimed amounts per claim type and token ID.
    mapping(uint8 => mapping(uint256 => uint256)) public claimedAmounts; // claimType => tokenId => amount

    /// @notice Total amount claimed through vibe fee collection.
    uint256 public vibeClaimedAmount;

    /// @notice Set of FeeCollector contracts for claiming protocol fees.
    EnumerableSet.AddressSet private feeCollectors;

    /* ─────────────────────────────── Events ─────────────────────────────── */

    /// @notice Emitted when a fee collector is added to the list.
    event FeeCollectorAdded(address indexed feeCollector);

    /// @notice Emitted when a fee collector is removed from the list.
    event FeeCollectorRemoved(address indexed feeCollector);

    /// @notice Emitted when fees are collected from a specific fee collector.
    event FeesCollected(address indexed feeCollector, uint256 amount);

    /// @notice Emitted when the vibe signer address is updated.
    event VibeSignerUpdated(
        address indexed oldSigner,
        address indexed newSigner
    );

    /// @notice Emitted when the vibe fee receiver address is updated.
    event VibeFeeReceiverUpdated(
        address indexed oldReceiver,
        address indexed newReceiver
    );

    /// @notice Emitted when the signature validity time window is updated.
    event SignatureValidTimeUpdated(uint256 oldTime, uint256 newTime);

    /// @notice Emitted when the MultiAccount contract address is updated.
    event MultiAccountAddressUpdated(
        address indexed oldAddr,
        address indexed newAddr
    );

    /// @notice Emitted when the RFL contract address is updated.
    event RflAddressUpdated(address indexed oldAddr, address indexed newAddr);

    /// @notice Emitted when a user successfully claims trading or referral rewards.
    event ClaimProcessed(
        address indexed user,
        address account,
        uint256 indexed tokenId,
        uint256 amount,
        uint256 sigTimestamp,
        uint8 claimType
    );

    /// @notice Emitted when vibe fees are successfully claimed by the protocol.
    event VibeClaimProcessed(
        address indexed receiver,
        uint256 amount,
        uint256 sigTimestamp
    );

    /// @notice Emitted when the rakeback token address is updated.
    event RakebackTokenUpdated(
        address indexed oldAddr,
        address indexed newAddr
    );

    /* ─────────────────────────────── Errors ─────────────────────────────── */

    error InvalidSignature(); // signature verification failed
    error SignatureExpired(); // signature outside valid time window
    error AlreadyClaimed(); // requested amount already claimed
    error InsufficientFundInTheContract(); // contract lacks sufficient balance
    error InvalidVibeFeeReceiver(); // vibe fee receiver is zero address
    error NotAccountOwner(); // account owner doesn't match NFT owner
    error NotNftOwner(); // caller doesn't own the specified NFT
    error NotAllowedToClaim(); // NFT is not allowed to claim
    error ZeroAddress(); // Zero address provided where not allowed
    error FeeCollectorAlreadyExists(); // Fee collector already in the list
    error FeeCollectorDoesNotExist(); // Fee collector not in the list
    error NoFeeCollectors(); // No fee collectors configured

    /* ─────────────────────────── Initialization ─────────────────────────── */

    /**
     * @notice Initialize the upgradeable proxy.
     * @param _admin                 Receives DEFAULT_ADMIN + SETTER roles.
     * @param _symmio               Symmio protocol contract address.
     * @param _multiAccount         MultiAccount contract for ownership verification.
     * @param _rfl                  RFL NFT contract address.
     * @param _feeCollector         FeeCollector contract for claiming fees.
     * @param _vibeSigner           Address authorized to sign claim requests.
     * @param _vibeFeeReceiver      Recipient for vibe fee distributions.
     * @param _signatureValidTime   Time window for signature validity (seconds).
     */
    function initialize(
        address _admin,
        address _symmio,
        address _multiAccount,
        address _rfl,
        address _feeCollector,
        address _vibeSigner,
        address _vibeFeeReceiver,
        uint256 _signatureValidTime
    ) public initializer {
        __AccessControlEnumerable_init();
        __ReentrancyGuard_init();

        symmio_deprecated = _symmio;
        multiAccount = _multiAccount;
        rfl = _rfl;
        feeCollector_deprecated = _feeCollector;
        vibeSigner = _vibeSigner;
        vibeFeeReceiver = _vibeFeeReceiver;
        signatureValidTime = _signatureValidTime;
        rakebackToken = address(0);

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(SETTER_ROLE, _admin);
    }

    /* ───────────────────────── Internal Helpers ───────────────────────── */

    /**
     * @dev Generate Ethereum signed message hash from data hash.
     */
    function _ethHash(bytes32 message) private pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked("\x19Ethereum Signed Message:\n32", message)
            );
    }

    /**
     * @dev Verify signature timestamp is within valid window.
     */
    function _checkSigWindow(uint256 sigTimestamp) private view {
        if (block.timestamp < sigTimestamp) revert InvalidSignature();
        if (block.timestamp > sigTimestamp + signatureValidTime)
            revert SignatureExpired();
    }

    /**
     * @notice Verify signature against the configured vibe signer.
     * @param ethHash   Ethereum signed message hash.
     * @param signature Signature bytes to verify.
     * @return bool     True if signature is valid.
     */
    function checkSignature(
        bytes32 ethHash,
        bytes calldata signature
    ) public view returns (bool) {
        return
            SignatureChecker.isValidSignatureNow(
                vibeSigner,
                ethHash,
                signature
            );
    }

    /**
     * @dev Internal signature verification that reverts on failure.
     */
    function _checkSignature(
        bytes32 ethHash,
        bytes calldata signature
    ) private view {
        if (!checkSignature(ethHash, signature)) revert InvalidSignature();
    }

    /**
     * @notice Generate signature hashes for vibe fee claims.
     * @param amount       Amount to claim (18 decimals).
     * @param sigTimestamp Signature timestamp.
     * @return dataHash    Raw data hash.
     * @return ethHash     Ethereum signed message hash.
     */
    function vibeClaimSignatureHash(
        uint256 amount,
        uint256 sigTimestamp
    ) public view returns (bytes32 dataHash, bytes32 ethHash) {
        dataHash = keccak256(
            abi.encode(block.chainid, address(this), amount, sigTimestamp)
        );
        ethHash = _ethHash(dataHash);
    }

    /**
     * @notice Generate signature hashes for trading/referral claims.
     * @param tokenId      RFL token ID.
     * @param account      Symmio account address.
     * @param amount       Amount to claim (18 decimals).
     * @param sigTimestamp Signature timestamp.
     * @param claimType    TRADING_CLAIM or REFERRAL_CLAIM.
     * @return dataHash    Raw data hash.
     * @return ethHash     Ethereum signed message hash.
     */
    function claimSignatureHash(
        uint256 tokenId,
        address account,
        uint256 amount,
        uint256 sigTimestamp,
        uint8 claimType
    ) public view returns (bytes32 dataHash, bytes32 ethHash) {
        dataHash = keccak256(
            abi.encode(
                block.chainid,
                address(this),
                tokenId,
                account,
                amount,
                sigTimestamp,
                claimType
            )
        );
        ethHash = _ethHash(dataHash);
    }

    /**
     * @dev Calculate unclaimed amount, reverting if already fully claimed.
     */
    function _unclaimed(
        uint256 requested,
        uint256 alreadyClaimed
    ) private pure returns (uint256) {
        if (alreadyClaimed >= requested) revert AlreadyClaimed();
        return requested - alreadyClaimed;
    }

    /**
     * @dev Scale 18-decimal accounting amount to the rakeback token's decimals.
     */
    function _scale(uint256 amount) private view returns (uint256) {
        uint8 diff = 18 - IERC20Metadata(rakebackToken).decimals();
        return diff == 0 ? amount : amount / (10 ** diff);
    }

    /**
     * @dev Collect fees from fee collectors if contract balance is insufficient.
     */
    function _collectFeesAndVerifyBalance(uint256 withdrawable) private {
        uint256 currentBalance = IERC20(rakebackToken).balanceOf(address(this));

        if (currentBalance < withdrawable) {
            // Use multiple fee collectors if migrated
            uint256 collectorCount = feeCollectors.length();
            if (collectorCount == 0) revert NoFeeCollectors();

            // Collect from all fee collectors
            for (uint256 i = 0; i < collectorCount; i++) {
                address collector = feeCollectors.at(i);
                uint256 balanceBefore = IERC20(rakebackToken).balanceOf(
                    address(this)
                );

                // Try to claim from this fee collector
                try IFeeCollector(collector).claimAllFee() {
                    uint256 collected = IERC20(rakebackToken).balanceOf(
                        address(this)
                    ) - balanceBefore;
                    if (collected > 0) {
                        emit FeesCollected(collector, collected);
                    }
                } catch {
                    // Continue to next collector if this one fails
                    continue;
                }

                // Check if we have enough after this collection
                currentBalance = IERC20(rakebackToken).balanceOf(address(this));
                if (currentBalance >= withdrawable) {
                    return; // We have enough, can stop collecting
                }
            }

            // Final check after trying all collectors
            if (IERC20(rakebackToken).balanceOf(address(this)) < withdrawable) {
                revert InsufficientFundInTheContract();
            }
        }
    }

    /* ──────────────────────── Claim Core Logic ──────────────────────── */

    /**
     * @dev Core claim processing logic for both trading and referral claims.
     * @param tokenId      RFL token ID for the claim.
     * @param account      Symmio account to deposit rewards into.
     * @param amount       Total authorized amount (18 decimals).
     * @param sigTimestamp Signature timestamp.
     * @param signature    Authorization signature.
     * @param claimType    TRADING_CLAIM or REFERRAL_CLAIM.
     */
    function _processClaim(
        uint256 tokenId,
        address account,
        uint256 amount,
        uint256 sigTimestamp,
        bytes calldata signature,
        uint8 claimType
    ) private nonReentrant {
        _checkSigWindow(sigTimestamp);

        if (IRFL(rfl).referrer(tokenId) == 0 && !IRFL(rfl).isOg(tokenId))
            revert NotAllowedToClaim();

        (, bytes32 ethHash) = claimSignatureHash(
            tokenId,
            account,
            amount,
            sigTimestamp,
            claimType
        );
        _checkSignature(ethHash, signature);

        uint256 unclaimed = _unclaimed(
            amount,
            claimedAmounts[claimType][tokenId]
        );
        uint256 withdrawable = _scale(unclaimed);

        address tokenOwner = IRFL(rfl).ownerOf(tokenId);
        address accountOwner = IMultiAccount(multiAccount).owners(account);
        if (tokenOwner != accountOwner) revert NotAccountOwner();

        _collectFeesAndVerifyBalance(withdrawable);

        claimedAmounts[claimType][tokenId] += unclaimed;

        IMultiAccount.VibeAccount memory vibeAccount = IMultiAccount(
            multiAccount
        ).getVibeAccount(account);

        IERC20(rakebackToken).approve(
            vibeAccount.data.symmioAddress,
            withdrawable
        );
        ISymmio(vibeAccount.data.symmioAddress).depositFor(
            account,
            withdrawable
        );

        emit ClaimProcessed(
            msg.sender,
            account,
            tokenId,
            unclaimed,
            sigTimestamp,
            claimType
        );
    }

    /* ───────────────────────── External Functions ───────────────────────── */

    /**
     * @notice Claim trading rewards for an RFL token.
     * @param tokenId      RFL token ID owned by caller.
     * @param account      Symmio account to deposit rewards into.
     * @param amount       Total authorized trading reward amount.
     * @param sigTimestamp Signature timestamp.
     * @param signature    Authorization signature from vibe signer.
     */
    function tradingClaim(
        uint256 tokenId,
        address account,
        uint256 amount,
        uint256 sigTimestamp,
        bytes calldata signature
    ) external onlyNftOwner(tokenId) {
        _processClaim(
            tokenId,
            account,
            amount,
            sigTimestamp,
            signature,
            TRADING_CLAIM
        );
    }

    /**
     * @notice Claim referral commissions for an RFL token.
     * @param tokenId      RFL token ID owned by caller.
     * @param account      Symmio account to deposit rewards into.
     * @param amount       Total authorized referral commission amount.
     * @param sigTimestamp Signature timestamp.
     * @param signature    Authorization signature from vibe signer.
     */
    function referralClaim(
        uint256 tokenId,
        address account,
        uint256 amount,
        uint256 sigTimestamp,
        bytes calldata signature
    ) external onlyNftOwner(tokenId) {
        _processClaim(
            tokenId,
            account,
            amount,
            sigTimestamp,
            signature,
            REFERRAL_CLAIM
        );
    }

    /**
     * @notice Claim vibe fees for the protocol (VIBE_COLLECTOR_ROLE only).
     * @param amount       Total authorized vibe fee amount.
     * @param sigTimestamp Signature timestamp.
     * @param signature    Authorization signature from vibe signer.
     */
    function vibeClaim(
        uint256 amount,
        uint256 sigTimestamp,
        bytes calldata signature
    ) external onlyRole(VIBE_COLLECTOR_ROLE) nonReentrant {
        _checkSigWindow(sigTimestamp);

        (, bytes32 ethHash) = vibeClaimSignatureHash(amount, sigTimestamp);
        _checkSignature(ethHash, signature);

        uint256 unclaimed = _unclaimed(amount, vibeClaimedAmount);
        uint256 withdrawable = _scale(unclaimed);

        if (vibeFeeReceiver == address(0)) revert InvalidVibeFeeReceiver();

        _collectFeesAndVerifyBalance(withdrawable);

        vibeClaimedAmount += unclaimed;
        IERC20(rakebackToken).safeTransfer(vibeFeeReceiver, withdrawable);

        emit VibeClaimProcessed(vibeFeeReceiver, unclaimed, sigTimestamp);
    }

    /**
     * @notice Manually trigger fee collection from all fee collectors.
     * Can be called by anyone to ensure fees are collected.
     */
    function collectAllFees() external {
        uint256 collectorCount = feeCollectors.length();
        if (collectorCount == 0) revert NoFeeCollectors();

        for (uint256 i = 0; i < collectorCount; i++) {
            address collector = feeCollectors.at(i);
            uint256 balanceBefore = IERC20(rakebackToken).balanceOf(
                address(this)
            );

            try IFeeCollector(collector).claimAllFee() {
                uint256 collected = IERC20(rakebackToken).balanceOf(
                    address(this)
                ) - balanceBefore;
                if (collected > 0) {
                    emit FeesCollected(collector, collected);
                }
            } catch {
                // Continue to next collector if this one fails
                continue;
            }
        }
    }

    /* ────────────────────────── Admin Functions ────────────────────────── */

    /**
     * @notice Add a new fee collector to the list.
     * @dev Only works after migration to multi-collector setup.
     * @param _feeCollector The fee collector contract address to add.
     */
    function addFeeCollector(
        address _feeCollector
    ) external onlyRole(SETTER_ROLE) {
        if (_feeCollector == address(0)) revert ZeroAddress();
        if (!feeCollectors.add(_feeCollector))
            revert FeeCollectorAlreadyExists();
        emit FeeCollectorAdded(_feeCollector);
    }

    /**
     * @notice Remove a fee collector from the list.
     * @dev Only works after migration to multi-collector setup.
     * @param _feeCollector The fee collector contract address to remove.
     */
    function removeFeeCollector(
        address _feeCollector
    ) external onlyRole(SETTER_ROLE) {
        if (!feeCollectors.remove(_feeCollector))
            revert FeeCollectorDoesNotExist();
        emit FeeCollectorRemoved(_feeCollector);
    }

    /**
     * @notice Get all fee collector addresses.
     * @return collectors Array of fee collector contract addresses.
     */
    function getFeeCollectors()
        external
        view
        returns (address[] memory collectors)
    {
        uint256 length = feeCollectors.length();
        collectors = new address[](length);
        for (uint256 i = 0; i < length; i++) {
            collectors[i] = feeCollectors.at(i);
        }
    }

    /// @notice Update signature validity time window.
    function setSignatureValidTime(
        uint256 newTime
    ) external onlyRole(SETTER_ROLE) {
        emit SignatureValidTimeUpdated(signatureValidTime, newTime);
        signatureValidTime = newTime;
    }

    /// @notice Update vibe signer address for claim authorization.
    function setVibeSigner(address newSigner) external onlyRole(SETTER_ROLE) {
        emit VibeSignerUpdated(vibeSigner, newSigner);
        vibeSigner = newSigner;
    }

    /// @notice Update vibe fee receiver address.
    function setVibeFeeReceiver(
        address newReceiver
    ) external onlyRole(SETTER_ROLE) {
        emit VibeFeeReceiverUpdated(vibeFeeReceiver, newReceiver);
        vibeFeeReceiver = newReceiver;
    }

    /// @notice Update MultiAccount contract address.
    function setMultiAccountAddress(
        address newMultiAccount
    ) external onlyRole(SETTER_ROLE) {
        emit MultiAccountAddressUpdated(multiAccount, newMultiAccount);
        multiAccount = newMultiAccount;
    }

    /// @notice Update RFL contract address.
    function setRflAddress(address newRfl) external onlyRole(SETTER_ROLE) {
        emit RflAddressUpdated(rfl, newRfl);
        rfl = newRfl;
    }

    /// @notice Update rakeback token address.
    function setRakebackToken(
        address newRakebackToken
    ) external onlyRole(SETTER_ROLE) {
        emit RakebackTokenUpdated(rakebackToken, newRakebackToken);
        rakebackToken = newRakebackToken;
    }

    /* ─────────────────────────────── Modifiers ─────────────────────────────── */

    /// @notice Restricts function access to the owner of the specified NFT.
    modifier onlyNftOwner(uint256 tokenId) {
        if (IERC721(rfl).ownerOf(tokenId) != msg.sender) revert NotNftOwner();
        _;
    }
}
