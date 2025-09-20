// SPDX-License-Identifier: SYMM-Core-Business-Source-License-1.1
// This contract is licensed under the SYMM Core Business Source License 1.1
// Copyright (c) 2023 Symmetry Labs AG
// For more information, see https://docs.symm.io/legal-disclaimer/license
pragma solidity >=0.8.18;

/**
 * @title  MultiAccount
 * @notice Manages multiple accounts per user on the Symmio protocol.
 *         Users can create sub-accounts, delegate trading permissions, and bind accounts
 *         to specific PartyB addresses for controlled trading access.
 *
 * @dev    Core features include:
 *         • Account creation with CREATE2 for deterministic addresses
 *         • Batch account creation with flexible options
 *         • Granular permission delegation with cooldown-based revocation
 *         • PartyB binding for account-specific counterparty restrictions
 *         • Integrated deposits, withdrawals, and allocations
 *         • Selective withdrawal and deposit pausing for specific accounts
 *         • Pause functionality and role-based access control
 */

import "@openzeppelin/contracts/interfaces/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";

import "./interfaces/IRFL.sol";
import "./interfaces/ISymmio.sol";
import "./interfaces/ISymmioPartyA.sol";
import "./interfaces/IMultiAccount.sol";

contract MultiAccount is
    IMultiAccount,
    Initializable,
    PausableUpgradeable,
    AccessControlUpgradeable
{
    using SafeERC20 for IERC20;
    /* ────────────────────── Function Selectors ────────────────────── */

    /// @dev Function selector for sendQuote in Symmio protocol.
    bytes4 constant SELECTOR_SEND_QUOTE = 0x7f2755b2;

    /// @dev Function selector for sendQuoteWithAffiliate in Symmio protocol.
    bytes4 constant SELECTOR_SEND_QUOTE_WITH_AFFILIATE = 0x40f1310c;

    /// @dev Function selector for deallocate in Symmio protocol.
    bytes4 constant SELECTOR_DEALLOCATE = 0xea002a7b;

    /// @dev Function selector for allocate in Symmio protocol.
    bytes4 constant SELECTOR_ALLOCATE = 0x90ca796b;

    /// @dev Function selector for transferAllocation in Symmio protocol.
    bytes4 constant SELECTOR_TRANSFER_ALLOCATION = 0x3e7ba166;

    /* ─────────────────────────────── Roles ─────────────────────────────── */

    /// @notice Role that can update contract configuration and addresses.
    bytes32 public constant SETTER_ROLE = keccak256("SETTER_ROLE");

    /// @notice Role that can pause contract operations.
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    /// @notice Role that can unpause contract operations.
    bytes32 public constant UNPAUSER_ROLE = keccak256("UNPAUSER_ROLE");

    /* ──────────────────────── Storage Variables ──────────────────────── */

    /// @notice Mapping from user addresses to their array of accounts.
    mapping(address => Account[]) public accounts;

    /// @notice Mapping from account address to its VibeAccountData.
    mapping(address => VibeAccountData) public vibeAccountData;

    /// @notice Mapping from account address to its index in the owner's accounts array.
    mapping(address => uint256) public indexOfAccount;

    /// @notice Mapping from account address to its owner address.
    mapping(address => address) public owners;

    /// @notice Admin address for the account contracts (receives admin role on deployed accounts).
    address public accountsAdmin;

    /// @notice Counter for generating unique CREATE2 salts for account deployment.
    uint256 public saltCounter;

    /// @notice Bytecode of the account implementation contract.
    bytes public accountImplementation;

    /// @notice Triple mapping for delegated access permissions: account => delegate => selector => enabled.
    mapping(address => mapping(address => mapping(bytes4 => bool)))
        public delegatedAccesses;

    /// @notice Cooldown period (in seconds) required before revoking delegated access.
    uint256 public revokeCooldown;

    /// @notice Triple mapping tracking revoke proposal timestamps: account => delegate => selector => timestamp.
    mapping(address => mapping(address => mapping(bytes4 => uint256)))
        public revokeProposalTimestamp;

    /// @notice Address of the VibeRFL contract for referral system integration.
    address public vibeRfl;

    /// @notice Mapping from account address to withdrawal pause status.
    mapping(address => bool) public withdrawalsPaused;

    /// @notice Mapping from account address to deposit pause status.
    mapping(address => bool) public depositsPaused;

    /* ─────────────────────────── Initialization ─────────────────────────── */

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initialize the upgradeable proxy.
     * @param admin                     Receives all admin roles (DEFAULT_ADMIN, SETTER, PAUSER, UNPAUSER).
     * @param accountImplementation_    Bytecode of the account implementation contract.
     */
    function initialize(
        address admin,
        bytes memory accountImplementation_
    ) public initializer {
        __Pausable_init();
        __AccessControl_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(PAUSER_ROLE, admin);
        _grantRole(UNPAUSER_ROLE, admin);
        _grantRole(SETTER_ROLE, admin);
        accountsAdmin = admin;
        accountImplementation = accountImplementation_;
    }

    /* ───────────────────── Withdrawal Pause Management ───────────────────── */

    /**
     * @notice Pause withdrawals for multiple accounts.
     * @param accountsToPause Array of account addresses to pause withdrawals for.
     */
    function pauseWithdrawalsForAccounts(
        address[] calldata accountsToPause
    ) external onlyRole(PAUSER_ROLE) {
        for (uint256 i = 0; i < accountsToPause.length; i++) {
            address account = accountsToPause[i];
            require(
                owners[account] != address(0),
                "MultiAccount: Account doesn't exist"
            );

            if (!withdrawalsPaused[account]) {
                withdrawalsPaused[account] = true;
                emit WithdrawalsPaused(account, msg.sender);
            }
        }
    }

    /**
     * @notice Unpause withdrawals for multiple accounts.
     * @param accountsToUnpause Array of account addresses to unpause withdrawals for.
     */
    function unpauseWithdrawalsForAccounts(
        address[] calldata accountsToUnpause
    ) external onlyRole(PAUSER_ROLE) {
        for (uint256 i = 0; i < accountsToUnpause.length; i++) {
            address account = accountsToUnpause[i];

            if (withdrawalsPaused[account]) {
                withdrawalsPaused[account] = false;
                emit WithdrawalsUnpaused(account, msg.sender);
            }
        }
    }

    /* ───────────────────── Deposit Pause Management ───────────────────── */

    /**
     * @notice Pause deposits for multiple accounts.
     * @param accountsToPause Array of account addresses to pause deposits for.
     */
    function pauseDepositsForAccounts(
        address[] calldata accountsToPause
    ) external onlyRole(PAUSER_ROLE) {
        for (uint256 i = 0; i < accountsToPause.length; i++) {
            address account = accountsToPause[i];
            require(
                owners[account] != address(0),
                "MultiAccount: Account doesn't exist"
            );

            if (!depositsPaused[account]) {
                depositsPaused[account] = true;
                emit DepositsPaused(account, msg.sender);
            }
        }
    }

    /**
     * @notice Unpause deposits for multiple accounts.
     * @param accountsToUnpause Array of account addresses to unpause deposits for.
     */
    function unpauseDepositsForAccounts(
        address[] calldata accountsToUnpause
    ) external onlyRole(PAUSER_ROLE) {
        for (uint256 i = 0; i < accountsToUnpause.length; i++) {
            address account = accountsToUnpause[i];

            if (depositsPaused[account]) {
                depositsPaused[account] = false;
                emit DepositsUnpaused(account, msg.sender);
            }
        }
    }

    /* ───────────────────── Access Control & Delegation ───────────────────── */

    /**
     * @notice Grant delegated access to a specific function on a target address.
     * @param account   Account address to grant access for.
     * @param target    Target address to delegate to.
     * @param selector  Function selector to grant access to.
     * @param state     Must be true (access grant only - revocation requires separate flow).
     */
    function delegateAccess(
        address account,
        address target,
        bytes4 selector,
        bool state
    ) external onlyOwner(account, msg.sender) {
        require(
            target != msg.sender && target != account,
            "MultiAccount: Invalid target"
        );
        require(state, "MultiAccount: Invalid state");
        emit DelegateAccess(account, target, selector, state);
        delegatedAccesses[account][target][selector] = state;
    }

    /**
     * @notice Grant delegated access to multiple function selectors on a target address.
     * @param account   Account address to grant access for.
     * @param target    Target address to delegate to.
     * @param selector  Array of function selectors to grant access to.
     * @param state     Must be true (access grant only).
     */
    function delegateAccesses(
        address account,
        address target,
        bytes4[] memory selector,
        bool state
    ) external onlyOwner(account, msg.sender) {
        require(
            target != msg.sender && target != account,
            "MultiAccount: Invalid target"
        );
        require(state, "MultiAccount: Invalid state");
        for (uint256 i = selector.length; i != 0; i--) {
            delegatedAccesses[account][target][selector[i - 1]] = state;
        }
        emit DelegateAccesses(account, target, selector, state);
    }

    /**
     * @notice Propose to revoke delegated access (starts cooldown period).
     * @param account   Account address to revoke access from.
     * @param target    Target address.
     * @param selector  Array of function selectors to propose revoking.
     */
    function proposeToRevokeAccesses(
        address account,
        address target,
        bytes4[] memory selector
    ) external onlyOwner(account, msg.sender) {
        require(
            target != msg.sender && target != account,
            "MultiAccount: Invalid target"
        );
        for (uint256 i = selector.length; i != 0; i--) {
            revokeProposalTimestamp[account][target][selector[i - 1]] = block
                .timestamp;
        }
        emit ProposeToRevokeAccesses(account, target, selector);
    }

    /**
     * @notice Execute revocation of delegated access after cooldown period.
     * @param account   Account address to revoke access from.
     * @param target    Target address.
     * @param selector  Array of function selectors to revoke.
     */
    function revokeAccesses(
        address account,
        address target,
        bytes4[] memory selector
    ) external onlyOwner(account, msg.sender) {
        require(
            target != msg.sender && target != account,
            "MultiAccount: Invalid target"
        );
        for (uint256 i = selector.length; i != 0; i--) {
            require(
                revokeProposalTimestamp[account][target][selector[i - 1]] != 0,
                "MultiAccount: Revoke access not proposed"
            );
            require(
                revokeProposalTimestamp[account][target][selector[i - 1]] +
                    revokeCooldown <=
                    block.timestamp,
                "MultiAccount: Cooldown not reached"
            );
            delegatedAccesses[account][target][selector[i - 1]] = false;
            revokeProposalTimestamp[account][target][selector[i - 1]] = 0;
        }
        emit DelegateAccesses(account, target, selector, false);
    }

    /* ────────────────────────── Account Management ────────────────────────── */

    /**
     * @notice Create multiple accounts in a single transaction with flexible options.
     * @param params Array of AccountCreationParams structs defining each account's configuration.
     * @return accountAddresses Array of newly created account addresses.
     */
    function createAccounts(
        AccountCreationParams[] memory params
    ) public whenNotPaused returns (address[] memory accountAddresses) {
        require(params.length > 0, "MultiAccount: No accounts to create");

        accountAddresses = new address[](params.length);

        for (uint256 i = 0; i < params.length; i++) {
            AccountCreationParams memory param = params[i];

            // Create the account
            address account = _deployPartyA(param.symmioAddress);
            indexOfAccount[account] = accounts[msg.sender].length;
            accounts[msg.sender].push(Account(account, param.name));
            owners[account] = msg.sender;

            accountAddresses[i] = account;

            // Mint RFL NFT if specified
            if (bytes(param.rflCode).length > 0) {
                if (param.referrerTokenId == 0) {
                    IRFL(vibeRfl).safeMintFor(msg.sender, param.rflCode);
                } else {
                    IRFL(vibeRfl).safeMintWithReferrerFor(
                        msg.sender,
                        param.referrerTokenId,
                        param.rflCode
                    );
                }
            }

            vibeAccountData[account] = VibeAccountData({
                symmioAddress: param.symmioAddress,
                boundPartyB: param.partyB
            });

            if (param.partyB != address(0))
                emit BindToPartyB(account, param.partyB);
            emit AddAccount(msg.sender, account, param.name);
        }

        return accountAddresses;
    }

    /**
     * @notice Update the display name of an existing account.
     * @param accountAddress Address of the account to rename.
     * @param name           New display name for the account.
     */
    function editAccountName(
        address accountAddress,
        string memory name
    ) external whenNotPaused {
        uint256 index = indexOfAccount[accountAddress];
        accounts[msg.sender][index].name = name;
        emit EditAccountName(msg.sender, accountAddress, name);
    }

    /**
     * @notice Deposit collateral tokens for an account in symmio platform.
     * @param account Account address to deposit into.
     * @param amount  Amount of collateral tokens to deposit.
     */
    function depositForAccount(
        address account,
        uint256 amount
    ) external onlyOwner(account, msg.sender) whenNotPaused {
        require(
            !depositsPaused[account],
            "MultiAccount: Deposits paused for this account"
        );
        address symmioAddress = vibeAccountData[account].symmioAddress;
        address collateral = ISymmio(symmioAddress).getCollateral();
        IERC20(collateral).safeTransferFrom(msg.sender, address(this), amount);
        IERC20(collateral).approve(symmioAddress, amount);
        ISymmio(symmioAddress).depositFor(account, amount);
        emit DepositForAccount(msg.sender, account, amount);
    }

    /**
     * @notice Deposit collateral tokens and immediately allocate them in symmio platform.
     * @param account Account address to deposit and allocate for.
     * @param amount  Amount of collateral tokens to deposit and allocate.
     */
    function depositAndAllocateForAccount(
        address account,
        uint256 amount
    ) external onlyOwner(account, msg.sender) whenNotPaused {
        require(
            !depositsPaused[account],
            "MultiAccount: Deposits paused for this account"
        );
        address symmioAddress = vibeAccountData[account].symmioAddress;
        address collateral = ISymmio(symmioAddress).getCollateral();
        IERC20(collateral).safeTransferFrom(msg.sender, address(this), amount);
        IERC20(collateral).approve(symmioAddress, amount);
        ISymmio(symmioAddress).depositFor(account, amount);
        uint256 amountWith18Decimals = (amount * 1e18) /
            (10 ** IERC20Metadata(collateral).decimals());
        bytes memory _callData = abi.encodeWithSignature(
            "allocate(uint256)",
            amountWith18Decimals
        );
        innerCall(account, _callData);
        emit DepositForAccount(msg.sender, account, amount);
        emit AllocateForAccount(msg.sender, account, amountWith18Decimals);
    }

    /**
     * @notice Withdraw collateral tokens from a account to the owner.
     * @param account Account address to withdraw from.
     * @param amount  Amount of collateral tokens to withdraw.
     */
    function withdrawFromAccount(
        address account,
        uint256 amount
    ) external onlyOwner(account, msg.sender) whenNotPaused {
        require(
            !withdrawalsPaused[account],
            "MultiAccount: Withdrawals paused for this account"
        );
        bytes memory _callData = abi.encodeWithSignature(
            "withdrawTo(address,uint256)",
            owners[account],
            amount
        );
        emit WithdrawFromAccount(msg.sender, account, amount);
        innerCall(account, _callData);
    }

    /**
     * @notice Execute multiple function calls on behalf of a account.
     * @param account    Account address to execute calls for.
     * @param _callDatas Array of encoded function call data.
     */
    function _call(
        address account,
        bytes[] memory _callDatas
    ) external whenNotPaused {
        bool isOwner = owners[account] == msg.sender;
        for (uint8 i; i < _callDatas.length; i++) {
            bytes memory _callData = _callDatas[i];
            if (!isOwner) {
                require(
                    _callData.length >= 4,
                    "MultiAccount: Invalid call data"
                );
                bytes4 functionSelector;
                assembly {
                    functionSelector := mload(add(_callData, 0x20))
                }
                require(
                    delegatedAccesses[account][msg.sender][functionSelector],
                    "MultiAccount: Unauthorized access"
                );
            }
            innerCall(account, _callData);
        }
    }

    /* ───────────────────────── Internal Helpers ───────────────────────── */

    /**
     * @dev Execute a function call on a account with PartyB binding validation.
     * @param account   Account address to call.
     * @param _callData Encoded function call data.
     */
    function innerCall(address account, bytes memory _callData) internal {
        // Check if this is a withdrawal or deposit related call and if they are paused
        if (_callData.length >= 4) {
            bytes4 functionSelector;
            assembly {
                functionSelector := mload(add(_callData, 0x20))
            }

            // Check if withdrawals are paused for this account and if it's a withdrawal function
            if (withdrawalsPaused[account]) {
                require(
                    functionSelector != SELECTOR_DEALLOCATE,
                    "MultiAccount: Withdrawals paused for this account"
                );
            }

            // Check if deposits are paused for this account and if it's a deposit/allocation function
            if (depositsPaused[account]) {
                require(
                    functionSelector != SELECTOR_ALLOCATE &&
                        functionSelector != SELECTOR_TRANSFER_ALLOCATION,
                    "MultiAccount: Deposits paused for this account"
                );
            }
        }

        address boundPartyB = vibeAccountData[account].boundPartyB;
        if (boundPartyB != address(0)) {
            address expectedPartyB = decodePartyBFromInput(_callData);
            require(
                expectedPartyB == address(0) || boundPartyB == expectedPartyB,
                "MultiAccount: Unauthorized partyB"
            );
        }

        (bool _success, bytes memory _resultData) = ISymmioPartyA(account)
            ._call(_callData);
        emit Call(msg.sender, account, _callData, _success, _resultData);
        if (!_success) {
            assembly {
                revert(add(_resultData, 32), mload(_resultData))
            }
        }
    }

    /**
     * @dev Deploy a new PartyA account contract using CREATE2.
     * @return account Address of the newly deployed account contract.
     */
    function _deployPartyA(
        address symmioAddress
    ) internal returns (address account) {
        bytes32 salt = keccak256(
            abi.encodePacked("MultiAccount_", saltCounter)
        );
        saltCounter += 1;

        bytes memory bytecode = abi.encodePacked(
            accountImplementation,
            abi.encode(accountsAdmin, address(this), symmioAddress)
        );
        account = _deployContract(bytecode, salt);
        return account;
    }

    /**
     * @dev Deploy a contract using CREATE2 with the specified bytecode and salt.
     * @param bytecode Bytecode of the contract to deploy.
     * @param salt     Salt for CREATE2 deployment.
     * @return contractAddress Address of the deployed contract.
     */
    function _deployContract(
        bytes memory bytecode,
        bytes32 salt
    ) internal returns (address contractAddress) {
        assembly {
            contractAddress := create2(
                0,
                add(bytecode, 32),
                mload(bytecode),
                salt
            )
        }
        require(contractAddress != address(0), "MultiAccount: create2 failed");
        emit DeployContract(msg.sender, contractAddress);
        return contractAddress;
    }

    /**
     * @dev Extract PartyB address from encoded function call data for binding validation.
     * @param data Encoded function call data.
     * @return PartyB address if found in supported function signatures, otherwise address(0).
     */
    function decodePartyBFromInput(
        bytes memory data
    ) internal pure returns (address) {
        bytes memory args;
        bytes4 _selector;

        assembly {
            _selector := mload(add(data, 0x20))

            // Allocate memory for the args slice
            let len := mload(data)
            let newLen := sub(len, 4)
            args := mload(0x40) // free memory pointer
            mstore(0x40, add(args, add(newLen, 0x20))) // move free memory pointer
            mstore(args, newLen) // set length

            // Copy data from `data + 4` to `args + 32`
            for {
                let i := 0
            } lt(i, newLen) {
                i := add(i, 32)
            } {
                mstore(add(args, add(0x20, i)), mload(add(data, add(0x24, i))))
            }
        }

        if (_selector == SELECTOR_SEND_QUOTE) {
            (address[] memory partyBsWhitelist, , , , , , , , , , , , ) = abi
                .decode(
                    args,
                    (
                        address[],
                        uint256,
                        uint8,
                        uint8,
                        uint256,
                        uint256,
                        uint256,
                        uint256,
                        uint256,
                        uint256,
                        uint256,
                        uint256,
                        SingleUpnlAndPriceSig
                    )
                );

            require(
                partyBsWhitelist.length == 1,
                "MultiAccount: Only one PartyB must be whitelisted"
            );
            require(
                partyBsWhitelist[0] != address(0),
                "MultiAccount: zeroAddress in args"
            );
            return partyBsWhitelist[0];
        } else if (_selector == SELECTOR_SEND_QUOTE_WITH_AFFILIATE) {
            (address[] memory partyBsWhitelist, , , , , , , , , , , , , ) = abi
                .decode(
                    args,
                    (
                        address[],
                        uint256,
                        uint8,
                        uint8,
                        uint256,
                        uint256,
                        uint256,
                        uint256,
                        uint256,
                        uint256,
                        uint256,
                        uint256,
                        address,
                        SingleUpnlAndPriceSig
                    )
                );

            require(
                partyBsWhitelist.length == 1,
                "MultiAccount: Only one PartyB must be whitelisted"
            );
            require(
                partyBsWhitelist[0] != address(0),
                "MultiAccount: zeroAddress in args"
            );
            return partyBsWhitelist[0];
        } else {
            return address(0);
        }
    }

    /* ────────────────────────── Admin Functions ────────────────────────── */

    /// @notice Update the bytecode for new account deployments.
    function setAccountImplementation(
        bytes memory accountImplementation_
    ) external onlyRole(SETTER_ROLE) {
        emit SetAccountImplementation(
            accountImplementation,
            accountImplementation_
        );
        accountImplementation = accountImplementation_;
    }

    /// @notice Update the admin address for deployed accounts.
    function setAccountsAdmin(address admin) external onlyRole(SETTER_ROLE) {
        emit SetAccountsAdmin(accountsAdmin, admin);
        accountsAdmin = admin;
    }

    /// @notice Update the cooldown period for access revocation.
    function setRevokeCooldown(
        uint256 cooldown
    ) external onlyRole(SETTER_ROLE) {
        emit SetRevokeCooldown(revokeCooldown, cooldown);
        revokeCooldown = cooldown;
    }

    /// @notice Update the vibe rfl contract address.
    function setVibeRflAddress(address addr) external onlyRole(SETTER_ROLE) {
        emit SetVibeRflAddress(vibeRfl, addr);
        vibeRfl = addr;
    }

    /// @notice Pause all contract operations except view functions.
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /// @notice Resume all contract operations.
    function unpause() external onlyRole(UNPAUSER_ROLE) {
        _unpause();
    }

    /* ────────────────────────── View Functions ────────────────────────── */

    /**
     * @notice Get the number of accounts owned by a user.
     * @param user User address to query.
     * @return Number of accounts owned by the user.
     */
    function getAccountsLength(address user) external view returns (uint256) {
        return accounts[user].length;
    }

    /**
     * @notice Get a paginated list of accounts owned by a user.
     * @param user  User address to query.
     * @param start Starting index for pagination.
     * @param size  Maximum number of accounts to return.
     * @return Array of Account structures.
     */
    function getAccounts(
        address user,
        uint256 start,
        uint256 size
    ) external view returns (Account[] memory) {
        uint256 len = size > accounts[user].length - start
            ? accounts[user].length - start
            : size;
        Account[] memory userAccounts = new Account[](len);
        for (uint256 i = start; i < start + len; i++) {
            userAccounts[i - start] = accounts[user][i];
        }
        return userAccounts;
    }

    /**
     * @notice Get vibe accounts with their PartyB binding information.
     * @param user  User address to query.
     * @param start Starting index for pagination.
     * @param size  Maximum number of accounts to return.
     * @return Array of VibeAccount structures.
     */
    function getVibeAccounts(
        address user,
        uint256 start,
        uint256 size
    ) external view returns (VibeAccount[] memory) {
        uint256 len = size > accounts[user].length - start
            ? accounts[user].length - start
            : size;
        VibeAccount[] memory userAccountsWithBinding = new VibeAccount[](len);

        for (uint256 i = start; i < start + len; i++) {
            Account memory userAccount = accounts[user][i];
            userAccountsWithBinding[i - start] = VibeAccount({
                accountAddress: userAccount.accountAddress,
                name: userAccount.name,
                data: vibeAccountData[userAccount.accountAddress]
            });
        }

        return userAccountsWithBinding;
    }

    /**
     * @notice Get vibe account with its PartyB binding information.
     * @param account Account address to query.
     * @return VibeAccount structure.
     */
    function getVibeAccount(
        address account
    ) external view returns (VibeAccount memory) {
        address owner = owners[account];
        for (uint256 i = 0; i < accounts[owner].length; i++) {
            if (accounts[owner][i].accountAddress == account) {
                return
                    VibeAccount({
                        accountAddress: account,
                        name: accounts[owner][i].name,
                        data: vibeAccountData[account]
                    });
            }
        }
        revert("MultiAccount: Account not found");
    }

    /**
     * @notice Check if withdrawals are paused for a specific account.
     * @param account Account address to check.
     * @return True if withdrawals are paused, false otherwise.
     */
    function isWithdrawalPaused(address account) external view returns (bool) {
        return withdrawalsPaused[account];
    }

    /**
     * @notice Check if deposits are paused for a specific account.
     * @param account Account address to check.
     * @return True if deposits are paused, false otherwise.
     */
    function isDepositPaused(address account) external view returns (bool) {
        return depositsPaused[account];
    }

    /* ─────────────────────────────── Modifiers ─────────────────────────────── */

    /// @notice Restricts function access to the owner of the specified account.
    modifier onlyOwner(address account, address sender) {
        require(
            owners[account] == sender,
            "MultiAccount: Sender isn't owner of account"
        );
        _;
    }
}
