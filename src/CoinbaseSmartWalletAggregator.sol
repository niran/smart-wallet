// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {IAggregator} from "account-abstraction/interfaces/IAggregator.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {UserOperation, UserOperationLib} from "account-abstraction/interfaces/UserOperation.sol";
import {BridgedKeystore} from "keyspace-v2/BridgedKeystore.sol";

import {CoinbaseSmartWallet} from "./CoinbaseSmartWallet.sol";
import {LibCoinbaseSmartWalletRecord} from "./LibCoinbaseSmartWalletRecord.sol";


contract CoinbaseSmartWalletAggregator is IAggregator {
    /// @notice Thrown in validateUserOpSignature if the value hash of the record cannot be proven against the 
    ///         latest keystore storage root.
    error ValueHashMismatch(bytes32 ksID, bytes32 valueHash);

    /// @notice Thrown in validateUserOpSignature if the userOp is invalid.
    error InvalidUserOp();

    /// @notice The BridgedKeystore used to prove the current configuration of the wallet.
    BridgedKeystore public immutable keystore;

    constructor(address keystore_) {
        keystore = BridgedKeystore(keystore_);
    }
    
    /// @notice Validate aggregated signature.
    ///
    /// @dev Since CoinbaseSmartWalletAggregator is just a container for ERC-4337 forbidden opcodes
    ///      and storage access, each userOp is validated individually, and the transaction is
    ///      reverted if any of them is invalid.
    function validateSignatures(UserOperation[] calldata userOps, bytes calldata signature) external view {
        for (uint256 i = 0; i < userOps.length; i++) {
            validateUserOpSignature(userOps[i]);
        }
    }

    /// @notice Validate signature of a single userOp.
    ///
    /// @dev This method should be called by bundler after EntryPoint.simulateValidation() returns (reverts) with ValidationResultWithAggregation.
    ///      First, it validates the signature over the userOp. Then it returns data to be used when creating the handleOps.
    ///
    /// @param userOp The userOperation received from the user.
    ///
    /// @return sigForUserOp The value to put into the signature field of the userOp when calling handleOps.
    ///                      (Usually empty for BLS-style aggregators, but for this aggregator it's the same as the input)
    function validateUserOpSignature(UserOperation calldata userOp) public view returns (bytes memory sigForUserOp) {
        require(LibCoinbaseSmartWalletRecord.isValidUserOp(userOp, address(keystore)), InvalidUserOp());

        return userOp.signature;
    }

    /// @notice No-op implementation of IAggregator.aggregateSignatures.
    ///
    /// @dev This method is called off-chain to calculate the signature to pass with handleOps(), but
    ///      our aggregator doesn't use any intermediate values. It's just a container for forbidden
    ///      opcodes and storage access for individual userOps.
    ///
    /// @param userOps Array of UserOperations to collect the signatures from.
    ///
    /// @return aggregatedSignature The aggregated signature.
    function aggregateSignatures(UserOperation[] calldata userOps) external view returns (bytes memory aggregatedSignature) {
        return bytes("");
    }
}
