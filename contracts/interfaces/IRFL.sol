// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IRFL {
    // =========================== View Functions ===========================

    function getTokenId(string memory code) external pure returns (uint256);

    function isActiveReferrer(uint256 tokenId) external view returns (bool);

    function getIndexOfTokenForUser(
        address user,
        uint256 tokenId
    ) external view returns (uint256);

    // =========================== Public Mutative Functions ===========================

    function safeMint(string memory code) external returns (uint256);

    function safeMintFor(
        address user,
        string memory code
    ) external returns (uint256 tokenId);

    function safeMintWithReferrer(
        uint256 referrerTokenId,
        string memory code
    ) external returns (uint256);

    function safeMintWithReferrerFor(
        address user,
        uint256 referrerTokenId,
        string memory code
    ) external returns (uint256 tokenId);

    function setReferrer(uint256 tokenId, uint256 referrerTokenId) external;

    function setTokenInUse(address user, uint256 tokenId) external;

    function increaseLockedCollateral(uint256 tokenId, uint256 amount) external;

    function decreaseLockedCollateral(uint256 tokenId, uint256 amount) external;

    // =========================== Admin Functions ===========================

    function ogMint(
        address user,
        string memory code
    ) external returns (uint256);

    function setCollateral(address _collateral) external;

    function setLockThreshold(uint256 newLockThreshold) external;

    function setReferralOpenTimestamp(
        uint256 newReferralOpenTimestamp
    ) external;

    function pauseTransfers() external;

    function unpauseTransfers() external;

    function pause() external;

    function unpause() external;

    // =========================== Getters ===========================

    function lockThreshold() external view returns (uint256);

    function totalLockedTokens() external view returns (uint256);

    function referralOpenTimestamp() external view returns (uint256);

    function collateral() external view returns (address);

    function isTransferPaused() external view returns (bool);

    function lockedTokens(uint256 tokenId) external view returns (uint256);

    function tokenIdCode(uint256 tokenId) external view returns (string memory);

    function codeTokenId(string memory code) external view returns (uint256);

    function isOg(uint256 tokenId) external view returns (bool);

    function tokenInUse(address owner) external view returns (uint256);

    function referrer(uint256 tokenId) external view returns (uint256);

    function ownerOf(uint256 tokenId) external view returns (address);
}
