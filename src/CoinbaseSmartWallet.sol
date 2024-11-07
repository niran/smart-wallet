// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IAccount} from "account-abstraction/interfaces/IAccount.sol";

import {UserOperation, UserOperationLib} from "account-abstraction/interfaces/UserOperation.sol";
import {Receiver} from "solady/accounts/Receiver.sol";
import {SignatureCheckerLib} from "solady/utils/SignatureCheckerLib.sol";
import {UUPSUpgradeable} from "solady/utils/UUPSUpgradeable.sol";
import {WebAuthn} from "webauthn-sol/WebAuthn.sol";

import {Keystore, MasterKeystoreStorage, ReplicaKeystoreStorage} from "keyspace-v3/Keystore.sol";
import {OPStackKeystore} from "keyspace-v3/examples/OPStackKeystore.sol";
import {BlockHeader} from "keyspace-v3/libs/BlockLib.sol";
import {Config, ConfigLib} from "keyspace-v3/libs/ConfigLib.sol";

import {ERC1271} from "./ERC1271.sol";

struct CoinbaseSmartWalletConfig {
    bytes[] owners;
    address implementation;
}

struct CoinbaseSmartWalletConfigView {
    mapping(bytes owner => bool isOwner_) isOwner;
}

struct CoinbaseSmartWalletConfigVersion {
    CoinbaseSmartWalletConfig config;
    CoinbaseSmartWalletConfigView view_;
}

/// @notice Storage layout used by this contract.
///
/// @custom:storage-location erc7201:coinbase.storage.CoinbaseSmartWalletStorage
struct CoinbaseSmartWalletStorage {
    /// @dev The mapping of Keystore configs.
    ///      NOTE: Using a mapping allows to set a new entry for each new Keystore config and thus avoid the need to
    ///            to have to properly delete all the previous config.
    mapping(bytes32 configHash => CoinbaseSmartWalletConfigVersion) configVersion;
}

/// @title Coinbase Smart Wallet
///
/// @notice ERC-4337-compatible smart account, based on Solady's ERC4337 account implementation
///         with inspiration from Alchemy's LightAccount and Daimo's DaimoAccount.
///
/// @author Coinbase (https://github.com/coinbase/smart-wallet)
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/accounts/ERC4337.sol)
contract CoinbaseSmartWallet is OPStackKeystore, ERC1271, IAccount, UUPSUpgradeable, Receiver {
    /// @notice A wrapper struct used for signature validation so that callers
    ///         can identify the owner that signed.
    struct SignatureWrapper {
        /// @dev The index of the owner that signed, see `MultiOwnable.ownerAtIndex`
        uint256 ownerIndex;
        /// @dev If `ownerAtIndex` is an Ethereum address, this should be `abi.encodePacked(r, s, v)`
        ///      If `ownerAtIndex` is a public key, this should be `abi.encode(WebAuthnAuth)`.
        bytes signatureData;
    }

    /// @notice Represents a call to make.
    struct Call {
        /// @dev The address to call.
        address target;
        /// @dev The value to send when making the call.
        uint256 value;
        /// @dev The data of the call.
        bytes data;
    }

    /// @notice Reserved nonce key (upper 192 bits of `UserOperation.nonce`) for cross-chain replayable
    ///         transactions.
    ///
    /// @dev MUST BE the `UserOperation.nonce` key when `UserOperation.calldata` is calling
    ///      `executeWithoutChainIdValidation`and MUST NOT BE `UserOperation.nonce` key when `UserOperation.calldata` is
    ///      NOT calling `executeWithoutChainIdValidation`.
    ///
    /// @dev Helps enforce sequential sequencing of replayable transactions.
    uint256 public constant REPLAYABLE_NONCE_KEY = 8453;

    /// @dev Slot for the `CoinbaseSmartWalletStorage` struct in storage.
    ///      Computed from:
    ///
    ///      keccak256(abi.encode(uint256(keccak256("coinbase.storage.CoinbaseSmartWallet")) - 1))
    ///         &
    ///      ~bytes32(uint256(0xff))
    ///
    ///      Follows ERC-7201 (see https://eips.ethereum.org/EIPS/eip-7201).
    bytes32 private constant COINBASE_SMART_WALLET_LOCATION =
        0x99a34bffa68409ea583717aeb46691b092950ed596c79c2fc789604435b66c00;

    /// @notice The wallet eventual consistency window.
    uint256 constant EVENTUAL_CONSISTENCY_WINDOW = 7 days;
    
    /// @notice Thrown when `initialize` is called but the account has already been initialized.
    error Initialized();

    /// @notice Thrown when the `msg.sender` is not authorized to call a privileged function.
    error Unauthorized();

    /// @notice Thrown when a call is passed to `executeWithoutChainIdValidation` that is not allowed by
    ///         `canSkipChainIdValidation`
    ///
    /// @param selector The selector of the call.
    error SelectorNotAllowed(bytes4 selector);

    /// @notice Thrown in validateUserOp if the key of `UserOperation.nonce` does not match the calldata.
    ///
    /// @dev Calls to `this.executeWithoutChainIdValidation` MUST use `REPLAYABLE_NONCE_KEY` and
    ///      calls NOT to `this.executeWithoutChainIdValidation` MUST NOT use `REPLAYABLE_NONCE_KEY`.
    ///
    /// @param key The invalid `UserOperation.nonce` key.
    error InvalidNonceKey(uint256 key);

    /// @notice Thrown when a provided owner is neither 64 bytes long (for public key)
    ///         nor a ABI encoded address.
    ///
    /// @param owner The invalid owner.
    error InvalidOwnerBytesLength(bytes owner);

    /// @notice Thrown if a provided owner is 32 bytes long but does not fit in an `address` type.
    ///
    /// @param owner The invalid owner.
    error InvalidEthereumAddressOwner(bytes owner);

    /// @notice Thrown when the caller is not authorized.
    error UnauthorizedCaller();

    /// @notice Thrown when the Keystore config update is not authorized.
    error UnauthorizedKeystoreConfigUpdate();

    /// @notice Thrown when the Keystore config update is invalid.
    error InvalidKeystoreConfigUpdate();

    /// @notice Reverts if the caller is not the EntryPoint.
    modifier onlyEntryPoint() virtual {
        if (msg.sender != entryPoint()) {
            revert Unauthorized();
        }

        _;
    }

    /// @notice Reverts if the caller is neither the EntryPoint nor the account itself.
    modifier onlyEntryPointOrSelf() virtual {
        if (msg.sender != entryPoint()) {
            _ensureIsSelf();
        }

        _;
    }

    /// @notice Access control modifier ensuring the call is originating from the contract itself.
    modifier onlySelf() virtual {
        _ensureIsSelf();
        _;
    }

    /// @notice Sends to the EntryPoint (i.e. `msg.sender`) the missing funds for this transaction.
    ///
    /// @dev Subclass MAY override this modifier for better funds management (e.g. send to the
    ///      EntryPoint more than the minimum required, so that in future transactions it will not
    ///      be required to send again).
    ///
    /// @param missingAccountFunds The minimum value this modifier should send the EntryPoint which
    ///                            MAY be zero, in case there is enough deposit, or the userOp has a
    ///                            paymaster.
    modifier payPrefund(uint256 missingAccountFunds) virtual {
        _;

        assembly ("memory-safe") {
            if missingAccountFunds {
                // Ignore failure (it's EntryPoint's job to verify, not the account's).
                pop(call(gas(), caller(), missingAccountFunds, codesize(), 0x00, codesize(), 0x00))
            }
        }
    }

    /// @notice Ensures the Keystore config is eventually consistent with the master chain.
    modifier withEventualConsistency() {
        // On replica chains ensure eventual consistency.
        if (msg.sender != entryPoint() && msg.sender != address(this) && block.chainid != masterChainId) {
            uint256 confirmedConfigTimestamp = _confirmedConfigTimestamp();
            uint256 validUntil = confirmedConfigTimestamp + EVENTUAL_CONSISTENCY_WINDOW;

            require(block.timestamp <= validUntil, UnauthorizedCaller());
        }

        _;
    }

    constructor(uint256 masterChainId) OPStackKeystore(masterChainId) {}

    /// @notice Initializes the contract with the given `config`.
    ///
    /// @dev Only callable once on the master chain.
    /// @dev The timestamps for the confirmed config hash remain zero on either chain.
    ///
    /// @param config The initial configuration of the account.
    function initialize(bytes32 configHash, bytes calldata config) external {
        if (block.chainid == masterChainId) {
            require(_sMaster().configHash == 0 && _sMaster().configNonce == 0, Initialized());
            _sMaster().configHash = configHash;
        } else {
            require(_sReplica().confirmedConfigHash == 0 && _sReplica().confirmedConfigNonce == 0, Initialized());
            _sReplica().confirmedConfigHash = configHash;
            // FIXME: Add this back after making the function internal rather than private.
            //_ensurePreconfirmedConfigsAreValid(configHash, config);
        }

        _newConfigHook(configHash, config);
    }

    /// @inheritdoc IAccount
    ///
    /// @notice ERC-4337 `validateUserOp` method. The EntryPoint will
    ///         call `UserOperation.sender.call(UserOperation.callData)` only if this validation call returns
    ///         successfully.
    ///
    /// @dev Signature failure should be reported by returning 1 (see: `this._isValidSignature`). This
    ///      allows making a "simulation call" without a valid signature. Other failures (e.g. invalid signature format)
    ///      should still revert to signal failure.
    /// @dev Reverts if the `UserOperation.nonce` key is invalid for `UserOperation.calldata`.
    /// @dev Reverts if the signature format is incorrect or invalid for owner type.
    ///
    /// @param userOp              The `UserOperation` to validate.
    /// @param userOpHash          The `UserOperation` hash, as computed by `EntryPoint.getUserOpHash(UserOperation)`.
    /// @param missingAccountFunds The missing account funds that must be deposited on the Entrypoint.
    ///
    /// @return validationData The encoded `ValidationData` structure:
    ///                        `(uint256(validAfter) << (160 + 48)) | (uint256(validUntil) << 160) | (success ? 0 : 1)`
    ///                        where `validUntil` is 0 (indefinite) and `validAfter` is 0.
    function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        virtual
        onlyEntryPoint
        payPrefund(missingAccountFunds)
        returns (uint256 validationData)
    {
        uint256 key = userOp.nonce >> 64;

        if (bytes4(userOp.callData) == this.executeWithoutChainIdValidation.selector) {
            userOpHash = getUserOpHashWithoutChainId(userOp);
            if (key != REPLAYABLE_NONCE_KEY) {
                revert InvalidNonceKey(key);
            }
        } else {
            if (key == REPLAYABLE_NONCE_KEY) {
                revert InvalidNonceKey(key);
            }
        }

        // Return 0 if the recovered address matches the owner.
        if (_isValidSignature(userOpHash, userOp.signature)) {
            return 0;
        }

        // Else return 1
        return 1;
    }

    /// @notice Executes `calls` on this account (i.e. self call).
    ///
    /// @dev Can only be called by the Entrypoint.
    /// @dev Reverts if the given call is not authorized to skip the chain ID validtion.
    /// @dev `validateUserOp()` will recompute the `userOpHash` without the chain ID before validating
    ///      it if the `UserOperation.calldata` is calling this function. This allows certain UserOperations
    ///      to be replayed for all accounts sharing the same address across chains. E.g. This may be
    ///      useful for syncing owner changes.
    ///
    /// @param calls An array of calldata to use for separate self calls.
    function executeWithoutChainIdValidation(bytes[] calldata calls) external payable virtual onlyEntryPoint {
        for (uint256 i; i < calls.length; i++) {
            bytes calldata call = calls[i];
            bytes4 selector = bytes4(call);
            if (!canSkipChainIdValidation(selector)) {
                revert SelectorNotAllowed(selector);
            }

            _call(address(this), 0, call);
        }
    }

    /// @notice Executes the given call from this account.
    ///
    /// @dev Can only be called by the Entrypoint or an owner of this account (including itself).
    ///
    /// @param target The address to call.
    /// @param value  The value to send with the call.
    /// @param data   The data of the call.
    function execute(address target, uint256 value, bytes calldata data)
        external
        payable
        virtual
        onlyEntryPointOrSelf
    {
        _call(target, value, data);
    }

    /// @notice Executes batch of `Call`s.
    ///
    /// @dev Can only be called by the Entrypoint or an owner of this account (including itself).
    ///
    /// @param calls The list of `Call`s to execute.
    function executeBatch(Call[] calldata calls) external payable virtual onlyEntryPointOrSelf {
        for (uint256 i; i < calls.length; i++) {
            _call(calls[i].target, calls[i].value, calls[i].data);
        }
    }

    /// @notice Returns the address of the EntryPoint v0.6.
    ///
    /// @return The address of the EntryPoint v0.6
    function entryPoint() public view virtual returns (address) {
        return 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    }

    /// @notice Computes the hash of the `UserOperation` in the same way as EntryPoint v0.6, but
    ///         leaves out the chain ID.
    ///
    /// @dev This allows accounts to sign a hash that can be used on many chains.
    ///
    /// @param userOp The `UserOperation` to compute the hash for.
    ///
    /// @return The `UserOperation` hash, which does not depend on chain ID.
    function getUserOpHashWithoutChainId(UserOperation calldata userOp) public view virtual returns (bytes32) {
        return keccak256(abi.encode(UserOperationLib.hash(userOp), entryPoint()));
    }

    /// @notice Returns the implementation of the ERC1967 proxy.
    ///
    /// @return $ The address of implementation contract.
    function implementation() public view returns (address $) {
        assembly {
            $ := sload(_ERC1967_IMPLEMENTATION_SLOT)
        }
    }

    /// @notice Returns whether `functionSelector` can be called in `executeWithoutChainIdValidation`.
    ///
    /// @param functionSelector The function selector to check.
    ////
    /// @return `true` is the function selector is allowed to skip the chain ID validation, else `false`.
    function canSkipChainIdValidation(bytes4 functionSelector) public pure returns (bool) {
        if (functionSelector == UUPSUpgradeable.upgradeToAndCall.selector) {
            return true;
        }
        return false;
    }

    /// @notice Executes the given call from this account.
    ///
    /// @dev Reverts if the call reverted.
    /// @dev Implementation taken from
    /// https://github.com/alchemyplatform/light-account/blob/43f625afdda544d5e5af9c370c9f4be0943e4e90/src/common/BaseLightAccount.sol#L125
    ///
    /// @param target The target call address.
    /// @param value  The call value to user.
    /// @param data   The raw call data.
    function _call(address target, uint256 value, bytes memory data) internal {
        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) {
            assembly ("memory-safe") {
                revert(add(result, 32), mload(result))
            }
        }
    }

    /// @inheritdoc ERC1271
    ///
    /// @dev Used by both `ERC1271.isValidSignature` AND `IAccount.validateUserOp` signature validation.
    /// @dev Reverts if owner at `ownerIndex` is not compatible with `signature` format.
    ///
    /// @param signature ABI encoded `SignatureWrapper`.
    function _isValidSignature(bytes32 hash, bytes calldata signature) internal view virtual override returns (bool) {
        SignatureWrapper memory sigWrapper = abi.decode(signature, (SignatureWrapper));
        bytes memory ownerBytes = ownerAtIndex(sigWrapper.ownerIndex);
        return _isValidSignatureForOwner(ownerBytes, hash, sigWrapper.signatureData);
    }

    function _isValidSignatureForOwner(bytes32 hash, bytes memory ownerBytes, bytes memory signatureData) internal view virtual returns (bool) {
        if (ownerBytes.length == 32) {
            if (uint256(bytes32(ownerBytes)) > type(uint160).max) {
                // technically should be impossible given owners can only be added with
                // addOwnerAddress and addOwnerPublicKey, but we leave incase of future changes.
                revert InvalidEthereumAddressOwner(ownerBytes);
            }

            address owner;
            assembly ("memory-safe") {
                owner := mload(add(ownerBytes, 32))
            }

            return SignatureCheckerLib.isValidSignatureNow(owner, hash, signatureData);
        }

        if (ownerBytes.length == 64) {
            (uint256 x, uint256 y) = abi.decode(ownerBytes, (uint256, uint256));

            WebAuthn.WebAuthnAuth memory auth = abi.decode(signatureData, (WebAuthn.WebAuthnAuth));

            return WebAuthn.verify({challenge: abi.encode(hash), requireUV: false, webAuthnAuth: auth, x: x, y: y});
        }

        revert InvalidOwnerBytesLength(ownerBytes);
    }

    /// @inheritdoc Keystore
    function _authorizeUpdate(Config calldata newConfig, BlockHeader memory, bytes calldata authorizationProof)
        internal
        view
        virtual
        override
        // TODO: If we enforce every preconfirmation to also perform a confirmation we can safely remove this.
        withEventualConsistency
    {
        bytes32 newConfigHash = ConfigLib.hash(newConfig);
        (bytes memory sigAuth, bytes memory sigUpdate,) =
            abi.decode(authorizationProof, (bytes, bytes));

        // Ensure the update is authorized.
        require(_isValidSignature({hash: newConfigHash, signature: sigAuth}), UnauthorizedKeystoreConfigUpdate());

        // Verify that `sigUpdate` is a valid signature of newConfigHash with the new owners to ensure
        // the new owners are valid.
        CoinbaseSmartWalletConfig memory newData = abi.decode(newConfig.data, (CoinbaseSmartWalletConfig));
        if (sigUpdate.length == 0) {
            // If an owner is being added, a second signature is not needed: we can just verify the
            // same signature using the new config.
            sigUpdate = sigAuth;
        }
        SignatureWrapper memory sigWrapper = abi.decode(sigUpdate, (SignatureWrapper));
        bytes memory ownerBytes = newData.owners[sigWrapper.ownerIndex];

        require(
            _isValidSignatureForOwner(newConfigHash, ownerBytes, sigWrapper.signatureData),
            InvalidKeystoreConfigUpdate()
        );
    }

    function ownerAtIndex(uint256 index) public view virtual returns (bytes memory) {
        return _currentVersionedConfig().config.owners[index];
    }

    /// @notice Checks if the given `account` address is registered as owner.
    ///
    /// @param account The account address to check.
    ///
    /// @return `true` if the account is an owner else `false`.
    function isOwnerAddress(address account) public view virtual returns (bool) {
        return _currentVersionedConfig().config.view_.isOwner[abi.encode(account)];
    }

    /// @notice Checks if the given `x`, `y` public key is registered as owner.
    ///
    /// @param x The public key x coordinate.
    /// @param y The public key y coordinate.
    ///
    /// @return `true` if the account is an owner else `false`.
    function isOwnerPublicKey(bytes32 x, bytes32 y) public view virtual returns (bool) {
        return _currentVersionedConfig().config.view_.isOwner[_currentConfigHash()][abi.encode(x, y)];
    }

    /// @notice Checks if the given `account` bytes is registered as owner.
    ///
    /// @param account The account, should be ABI encoded address or public key.
    ///
    /// @return `true` if the account is an owner else `false`.
    function isOwnerBytes(bytes memory account) public view virtual returns (bool) {
        return _currentVersionedConfig().config.view_.isOwner[account];
    }

    function _currentVersionedConfig() internal view virtual returns (CoinbaseSmartWalletConfigVersion storage) {
        return _getCoinbaseSmartWalletStorage().configVersion[_currentConfigHash()];
    }

    /// @inheritdoc Keystore
    function _newConfigHook(bytes32 configHash, bytes memory configData) internal virtual override {
        CoinbaseSmartWalletStorage storage sWallet = _getCoinbaseSmartWalletStorage();
        CoinbaseSmartWalletConfig memory newConfig = abi.decode(configData, (CoinbaseSmartWalletConfig));
        sWallet.configVersion[configHash].config = newConfig;

        // Register the new signers.
        for (uint256 i; i < newConfig.owners.length; i++) {
            sWallet.configVersion[configHash].view_.isOwner[newConfig.owners[i]] = true;
        }
    }

    /// @inheritdoc UUPSUpgradeable
    ///
    /// @dev Authorization logic is only based on the `msg.sender` being `address(this)`.
    function _authorizeUpgrade(address) internal view virtual override(UUPSUpgradeable) onlySelf {}

    /// @inheritdoc ERC1271
    function _domainNameAndVersion() internal pure override(ERC1271) returns (string memory, string memory) {
        return ("Coinbase Smart Wallet", "1");
    }

    /// @notice Checks if the sender is the account itself.
    ///
    /// @dev Reverts if the sender is not the contract itself.
    function _ensureIsSelf() internal view virtual {
        if (msg.sender != address(this)) {
            revert Unauthorized();
        }
    }

    /// @notice Helper function to get a storage reference to the `CoinbaseSmartWalletStorage` struct.
    ///
    /// @return $ A storage reference to the `CoinbaseSmartWalletStorage` struct.
    function _getCoinbaseSmartWalletStorage() internal pure returns (CoinbaseSmartWalletStorage storage $) {
        assembly ("memory-safe") {
            $.slot := COINBASE_SMART_WALLET_LOCATION
        }
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        PRIVATE FUNCTIONS                                       //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Helper function to get a storage reference to the `MasterKeystoreStorage` struct.
    ///
    /// @return $ A storage reference to the `MasterKeystoreStorage` struct.
    function _sMaster() private pure returns (MasterKeystoreStorage storage $) {
        bytes32 position = MASTER_KEYSTORE_STORAGE_LOCATION;
        assembly ("memory-safe") {
            $.slot := position
        }
    }

    /// @notice Helper function to get a storage reference to the `ReplicaKeystoreStorage` struct.
    ///
    /// @return $ A storage reference to the `ReplicaKeystoreStorage` struct.
    function _sReplica() private pure returns (ReplicaKeystoreStorage storage $) {
        bytes32 position = REPLICA_KEYSTORE_STORAGE_LOCATION;
        assembly ("memory-safe") {
            $.slot := position
        }
    }
}
