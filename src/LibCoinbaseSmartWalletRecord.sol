// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {UserOperation, UserOperationLib} from "account-abstraction/interfaces/UserOperation.sol";
import {BlockHeader} from "keyspace-v2/libs/BlockLib.sol";
import {BridgedKeystore} from "keyspace-v2/BridgedKeystore.sol";
import {SignatureCheckerLib} from "solady/utils/SignatureCheckerLib.sol";
import {WebAuthn} from "webauthn-sol/WebAuthn.sol";
import {CoinbaseSmartWallet} from "./CoinbaseSmartWallet.sol";

struct CoinbaseSmartWalletRecordData {
    bytes[] signers;
    bytes sidecar;
}

struct UserOpSignature {
    bytes sig;
    bytes recordValue;
    bytes[] confirmedValueHashStorageProof;
    bool useAggregator;
}

struct SignatureWrapper {
    /// @dev The index of the owner that signed
    uint256 ownerIndex;
    /// @dev If the owner is an Ethereum address, this should be `abi.encodePacked(r, s, v)`
    ///      If the owner is a public key, this should be `abi.encode(WebAuthnAuth)`.
    bytes signatureData;
}

library LibCoinbaseSmartWalletRecord {
    /// @notice Reserved nonce key (upper 192 bits of `UserOperation.nonce`) for cross-chain replayable
    ///         transactions.
    ///
    /// @dev MUST BE the `UserOperation.nonce` key when `UserOperation.calldata` is calling
    ///      `executeWithoutChainIdValidation`and MUST NOT BE `UserOperation.nonce` key when `UserOperation.calldata` is
    ///      NOT calling `executeWithoutChainIdValidation`.
    ///
    /// @dev Helps enforce sequential sequencing of replayable transactions.
    uint256 public constant REPLAYABLE_NONCE_KEY = 8453;

    /// @notice Thrown in validateUserOpSignature if the key of `UserOperation.nonce` does not match the calldata.
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

    /// @notice Verifies the validity of a signature for a given hash and keystore record value.
    ///
    /// @param hash The hash of the data that was signed.
    /// @param signature The signature data to verify.
    /// @param recordValue The keystore record value containing the wallet configuration.
    ///
    /// @return bool True if the signature is valid, false otherwise.
    ///
    /// @dev Reverts with `InvalidEthereumAddressOwner` if the ownerBytes length is 32 but the address is invalid.
    /// @dev Reverts with `InvalidOwnerBytesLength` if the ownerBytes length is neither 32 nor 64.
    function isValidSignatureCalldata(bytes32 hash, bytes calldata signature, bytes calldata recordValue) internal view returns (bool) {
        CoinbaseSmartWalletRecordData memory data = abi.decode(recordValue, (CoinbaseSmartWalletRecordData));
        SignatureWrapper memory sigWrapper = abi.decode(signature, (SignatureWrapper));
        return isValidSignature(hash, sigWrapper, data);
    }

    function isValidSignature(bytes32 hash, bytes memory signature, bytes memory recordValue) internal view returns (bool) {
        CoinbaseSmartWalletRecordData memory data = abi.decode(recordValue, (CoinbaseSmartWalletRecordData));
        SignatureWrapper memory sigWrapper = abi.decode(signature, (SignatureWrapper));
        return isValidSignature(hash, sigWrapper, data);
    }

    function isValidSignature(bytes32 hash, SignatureWrapper memory sigWrapper, CoinbaseSmartWalletRecordData memory data) internal view returns (bool) {
        bytes memory ownerBytes = data.signers[sigWrapper.ownerIndex];

        if (ownerBytes.length == 32) {
            if (uint256(bytes32(ownerBytes)) > type(uint160).max) {
                revert InvalidEthereumAddressOwner(ownerBytes);
            }

            address owner;
            assembly ("memory-safe") {
                owner := mload(add(ownerBytes, 32))
            }

            return SignatureCheckerLib.isValidSignatureNow(owner, hash, sigWrapper.signatureData);
        }

        if (ownerBytes.length == 64) {
            (uint256 x, uint256 y) = abi.decode(ownerBytes, (uint256, uint256));

            WebAuthn.WebAuthnAuth memory auth = abi.decode(sigWrapper.signatureData, (WebAuthn.WebAuthnAuth));

            return WebAuthn.verify({challenge: abi.encode(hash), requireUV: false, webAuthnAuth: auth, x: x, y: y});
        }

        revert InvalidOwnerBytesLength(ownerBytes);
    }

    function isValidUserOp(UserOperation calldata userOp, address keystore) public view returns (bool) {
        uint256 key = userOp.nonce >> 64;

        bytes32 userOpHash;
        if (bytes4(userOp.callData) == CoinbaseSmartWallet.executeWithoutChainIdValidation.selector) {
            userOpHash = getUserOpHashWithoutChainId(userOp);
            if (key != REPLAYABLE_NONCE_KEY) {
                revert InvalidNonceKey(key);
            }
        } else {
            userOpHash = UserOperationLib.hash(userOp);
            if (key == REPLAYABLE_NONCE_KEY) {
                revert InvalidNonceKey(key);
            }
        }

        UserOpSignature memory signature = abi.decode(userOp.signature, (UserOpSignature));
        bytes32 ksID = CoinbaseSmartWallet(payable(userOp.sender)).keystoreID();
        bytes32 valueHash = keccak256(signature.recordValue);
        if (!BridgedKeystore(keystore).isValueHashCurrent(ksID, valueHash, signature.confirmedValueHashStorageProof)) {
            return false;
        }

        return isValidSignature(userOpHash, signature.sig, signature.recordValue);
    }


    /// @notice Computes the hash of the `UserOperation` in the same way as EntryPoint v0.6, but
    ///         leaves out the chain ID.
    ///
    /// @dev This allows accounts to sign a hash that can be used on many chains.
    ///
    /// @param userOp The `UserOperation` to compute the hash for.
    ///
    /// @return The `UserOperation` hash, which does not depend on chain ID.
    function getUserOpHashWithoutChainId(UserOperation calldata userOp) public view returns (bytes32) {
        return keccak256(abi.encode(UserOperationLib.hash(userOp), CoinbaseSmartWallet(payable(userOp.sender)).entryPoint()));
    }
}

