// SPDX-License-Identifier: SYMM-Core-Business-Source-License-1.1
// This contract is licensed under the SYMM Core Business Source License 1.1
// Copyright (c) 2023 Symmetry Labs AG
// For more information, see https://docs.symm.io/legal-disclaimer/license
pragma solidity >=0.8.18;

interface IMultiAccount {
    struct SchnorrSign {
        uint256 signature;
        address owner;
        address nonce;
    }

    struct PublicKey {
        uint256 x;
        uint8 parity;
    }

    struct SingleUpnlAndPriceSig {
        bytes reqId;
        uint256 timestamp;
        int256 upnl;
        uint256 price;
        bytes gatewaySignature;
        SchnorrSign sigs;
    }

    struct Account {
        address accountAddress;
        string name;
    }

    struct VibeAccountData {
        address boundPartyB; // The PartyB address bound to this account (address(0) if not bound)
        address symmioAddress; // The Symmio address of the account
    }

    struct VibeAccount {
        address accountAddress;
        string name;
        VibeAccountData data;
    }

    struct AccountCreationParams {
        string name;
        address partyB;
        string rflCode;
        uint256 referrerTokenId;
        address symmioAddress;
    }

    event SetAccountImplementation(bytes oldAddress, bytes newAddress);
    event SetAccountsAdmin(address oldAddress, address newAddress);
    event SetVibeRflAddress(address oldAddress, address newAddress);
    event DeployContract(address sender, address contractAddress);
    event AddAccount(address user, address account, string name);
    event EditAccountName(address user, address account, string newName);
    event DepositForAccount(address user, address account, uint256 amount);
    event AllocateForAccount(address user, address account, uint256 amount);
    event WithdrawFromAccount(address user, address account, uint256 amount);
    event Call(
        address user,
        address account,
        bytes _callData,
        bool _success,
        bytes _resultData
    );
    event DelegateAccess(
        address account,
        address target,
        bytes4 selector,
        bool state
    );
    event DelegateAccesses(
        address account,
        address target,
        bytes4[] selector,
        bool state
    );
    event ProposeToRevokeAccesses(
        address account,
        address target,
        bytes4[] selector
    );
    event SetRevokeCooldown(uint256 oldCooldown, uint256 newCooldown);
    event BindToPartyB(address account, address partyB);
    event WithdrawalsPaused(address indexed account, address indexed pausedBy);
    event WithdrawalsUnpaused(
        address indexed account,
        address indexed unpausedBy
    );

    function owners(address account) external view returns (address);

    function getVibeAccount(
        address account
    ) external view returns (VibeAccount memory);
}
