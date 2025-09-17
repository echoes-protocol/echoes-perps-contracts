// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ISymmio {
    function depositFor(address user, uint256 amount) external;

    function getCollateral() external view returns (address);
}
