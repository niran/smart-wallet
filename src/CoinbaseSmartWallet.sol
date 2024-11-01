// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IAccount} from "account-abstraction/interfaces/IAccount.sol";

import {UserOperation, UserOperationLib} from "account-abstraction/interfaces/UserOperation.sol";
import {Receiver} from "solady/accounts/Receiver.sol";
import {SignatureCheckerLib} from "solady/utils/SignatureCheckerLib.sol";
import {UUPSUpgradeable} from "solady/utils/UUPSUpgradeable.sol";
import {WebAuthn} from "webauthn-sol/WebAuthn.sol";

import {BridgedKeystore} from "keyspace-v2/BridgedKeystore.sol";
import {LibCoinbaseSmartWalletRecord, UserOpSignature} from "./LibCoinbaseSmartWalletRecord.sol";
import {CoinbaseSmartWalletAggregator} from "./CoinbaseSmartWalletAggregator.sol";

import {ERC1271} from "./ERC1271.sol";

/// @notice Storage layout used by this contract.
///
/// @custom:storage-location erc7201:coinbase.storage.CoinbaseSmartWalletStorage
struct CoinbaseSmartWalletStorage {
    bytes32 ksID;
}

/// @title Coinbase Smart Wallet
///
/// @notice ERC-4337-compatible smart account, based on Solady's ERC4337 account implementation
///         with inspiration from Alchemy's LightAccount and Daimo's DaimoAccount.
///
/// @author Coinbase (https://github.com/coinbase/smart-wallet)
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/accounts/ERC4337.sol)
contract CoinbaseSmartWallet is ERC1271, IAccount, UUPSUpgradeable, Receiver {
    /// @notice The supported Keyspace key types.
    ///
    /// @dev `None` is intentionnaly placed first so that it equals the default unset value.
    ///      It is never allowed to register a Keyspace key with type `None`.
    enum KeyspaceKeyType {
        None,
        Secp256k1,
        WebAuthn
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

    /// @notice The BridgedKeystore used to prove the current configuration of the wallet.
    BridgedKeystore public immutable keystore;

    /// @notice The aggregator used to validate the signatures of the UserOperations.
    CoinbaseSmartWalletAggregator public immutable aggregator;
    
    /// @notice Thrown when `initialize` is called but the account has already been initialized.
    error Initialized();

    /// @notice Thrown when the `msg.sender` is not authorized to call a privileged function.
    error Unauthorized();

    /// @notice Thrown when a call is passed to `executeWithoutChainIdValidation` that is not allowed by
    ///         `canSkipChainIdValidation`
    ///
    /// @param selector The selector of the call.
    error SelectorNotAllowed(bytes4 selector);

    /// @notice Thrown when trying to register a Keyspace with with type `KeyspaceKeyType.None` type.
    error KeyspaceKeyTypeCantBeNone();

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

    constructor(address keystore_, address aggregator_) {
        // Set the immutable variables that will be used by all proxies pointing to this implementation.
        keystore = BridgedKeystore(keystore_);
        aggregator = CoinbaseSmartWalletAggregator(aggregator_);
        // Prevent the implementation from being initialized.
        _getCoinbaseSmartWalletStorage().ksID = bytes32(uint256(1));
    }

    /// @notice Initializes the account.
    ///
    /// @dev Reverts if the account has already been initialized.
    ///
    /// @param ksID     The Keyspace ID.
    function initialize(bytes32 ksID) external payable virtual {
        if (_getCoinbaseSmartWalletStorage().ksID != 0) {
            revert Initialized();
        }

        _getCoinbaseSmartWalletStorage().ksID = ksID;
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
        // ERC 4337 aggregators are the path forward for bundlers to support Keyspace transactions
        // without needing to configure exceptions for them, but aggregators aren't widely supported
        // yet. We allow the userOp signature to indicate whether the aggregator should be used.
        UserOpSignature memory signature =
            abi.decode(userOp.signature, (UserOpSignature));
        if (signature.useAggregator) {
            return uint160(address(aggregator));
        } else {
            if (LibCoinbaseSmartWalletRecord.isValidUserOp(userOp, userOpHash, address(keystore))) {
                return 0;
            } else {
                return 1;
            }
        }
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

    /// @notice Returns the implementation of the ERC1967 proxy.
    ///
    /// @return $ The address of implementation contract.
    function implementation() public view returns (address $) {
        assembly {
            $ := sload(_ERC1967_IMPLEMENTATION_SLOT)
        }
    }

    /// @notice Retrieves the keystore ID associated with the Coinbase Smart Wallet.
    /// @dev This function fetches the keystore ID from the Coinbase Smart Wallet storage.
    /// @return ksID The keystore ID as a uint256.
    function keystoreID() public view returns (bytes32) {
        return _getCoinbaseSmartWalletStorage().ksID;
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
    /// @dev Used by `ERC1271.isValidSignature` signature validation. This is simpler than our 
    ///      IAccount.validateUserOp implementation because no aggregator can be involved and storage
    ///      access is unlimited.
    /// @dev `signature` should be the resutlf of: `abi.encode(sig, recordData, confirmedValueHashStorageProof)`.
    //       The content of `sig` depends on the Keyspace key type:
    ///         - For Secp256k1 key type `sig` should be `abi.encodePacked(r, s, v)`
    ///         - For WebAuthn key type `sig` should be `abi.encode(WebAuthnAuth)`
    ///
    /// @param signature ABI encoded `SignatureWrapper`.
    function _isValidSignature(bytes32 h, bytes calldata signature) internal view virtual override returns (bool) {
        // Decode the raw `signature`.
        (bytes memory sig, bytes memory recordData, bytes[] memory confirmedValueHashStorageProof) =
            abi.decode(signature, (bytes, bytes, bytes[]));

        if (!keystore.isValueHashCurrent(
                _getCoinbaseSmartWalletStorage().ksID,
                keccak256(recordData),
                confirmedValueHashStorageProof)) {
            return false;
        }

        return LibCoinbaseSmartWalletRecord.isValidSignature(h, sig, recordData);
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
}
