// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {CoinbaseSmartWallet} from "./CoinbaseSmartWallet.sol";
import {ConfigLib} from "keyspace-v3/libs/ConfigLib.sol";

import {LibClone} from "solady/utils/LibClone.sol";

/// @title Coinbase Smart Wallet Factory
///
/// @notice CoinbaseSmartWallet factory, based on Solady's ERC4337Factory.
///
/// @author Coinbase (https://github.com/coinbase/smart-wallet)
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/accounts/ERC4337Factory.sol)
contract CoinbaseSmartWalletFactory {
    /// @notice Address of the ERC-4337 implementation used as implementation for new accounts.
    address public immutable implementation;

    /// @notice Thrown when trying to create a new `CoinbaseSmartWallet` account without any Keyspace key.
    error KeyRequired();

    /// @notice Factory constructor used to initialize the implementation address to use for future
    ///         CoinbaseSmartWallet deployments.
    ///
    /// @param implementation_ The address of the CoinbaseSmartWallet implementation which new accounts will proxy to.
    constructor(address implementation_) payable {
        implementation = implementation_;
    }

    /// @notice Returns the deterministic address for a CoinbaseSmartWallet created with `ksKeyAndType` and `nonce`
    ///         deploys and initializes contract if it has not yet been created.
    ///
    /// @dev Deployed as a ERC-1967 proxy that's implementation is `this.implementation`.
    ///
    /// @param configData The initial config data for the wallet.
    /// @param nonce      The nonce of the account, a caller defined value which allows multiple accounts
    ///                   with the same `configHash` to exist at different addresses.
    ///
    /// @return account The address of the ERC-1967 proxy created with inputs `configHash`, `nonce`, and
    ///                 `this.implementation`.
    function createAccount(bytes calldata configData, uint256 nonce)
        external
        payable
        virtual
        returns (CoinbaseSmartWallet account)
    {
        ConfigLib.Config memory config = ConfigLib.Config({nonce: uint96(0), data: configData});
        bytes32 configHash = _hashConfig(config);
        (bool alreadyDeployed, address accountAddress) =
            LibClone.createDeterministicERC1967(msg.value, implementation, _getSalt(configHash, nonce));

        account = CoinbaseSmartWallet(payable(accountAddress));

        if (!alreadyDeployed) {
            account.initialize(config);
        }
    }

    /// @notice Returns the deterministic address of the account that would be created by `createAccount`.
    ///
    /// @param initialConfigHash The hash of the config provided to `createAccount()`.
    /// @param nonce             The nonce provided to `createAccount()`.
    ///
    /// @return The predicted account deployment address.
    function getAddressByHash(bytes32 initialConfigHash, uint256 nonce)
        public
        view
        returns (address)
    {
        return LibClone.predictDeterministicAddress(initCodeHash(), _getSalt(initialConfigHash, nonce), address(this));
    }

    /// @notice Returns the deterministic address of the account that would be created by `createAccount`.
    ///
    /// @param initialConfigData The initial config data provided to `createAccount()`.
    /// @param nonce             The nonce provided to `createAccount()`.
    ///
    /// @return The predicted account deployment address.
    function getAddress(bytes calldata initialConfigData, uint256 nonce)
        external
        view
        returns (address)
    {
        bytes32 initialConfigHash = _hashConfig(ConfigLib.Config({nonce: uint96(0), data: initialConfigData}));
        return getAddressByHash(initialConfigHash, nonce);
    }

    /// @notice Returns the initialization code hash of the account:
    ///         a ERC1967 proxy that's implementation is `this.implementation`.
    ///
    /// @return The initialization code hash.
    function initCodeHash() public view virtual returns (bytes32) {
        return LibClone.initCodeHashERC1967(implementation);
    }

    /// @notice Returns the create2 salt for `LibClone.predictDeterministicAddress`
    ///
    /// @param configHash The hash of the initial config.
    /// @param nonce      The nonce provided to `createAccount()`.
    ///
    /// @return The computed salt.
    function _getSalt(bytes32 configHash,  uint256 nonce)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(configHash, nonce));
    }

    function _getKeystoreID(address controller, bytes32 storageHash)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(controller, uint96(0), storageHash));
    }

    /// @notice Computes a wallet factory-specific hash of the provided `config`.
    ///
    /// @dev The actual config hash calculation includes the address of the wallet, but the factory
    ///      needs to be able to calculate the hash before the address is known.
    ///
    /// @param config The Keystore config.
    ///
    /// @return The corresponding config hash.
    function _hashConfig(ConfigLib.Config memory config) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(config.nonce, config.data));
    }
}
