// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {IRecordController} from "keyspace-v2/interfaces/IRecordController.sol";
import {BlockHeader} from "keyspace-v2/libs/BlockLib.sol";
import {SignatureCheckerLib} from "solady/utils/SignatureCheckerLib.sol";
import {WebAuthn} from "webauthn-sol/WebAuthn.sol";

import {LibCoinbaseSmartWalletRecord} from "./LibCoinbaseSmartWalletRecord.sol";

struct CoinbaseSmartWalletRecordData {
    bytes[] signers;
    bytes sidecar;
}

struct SignatureWrapper {
    /// @dev The index of the owner that signed
    uint256 ownerIndex;
    /// @dev If the owner is an Ethereum address, this should be `abi.encodePacked(r, s, v)`
    ///      If the owner is a public key, this should be `abi.encode(WebAuthnAuth)`.
    bytes signatureData;
}

contract CoinbaseSmartWalletRecordController /* is IRecordController */ {
    /// @notice Thrown when a provided owner is neither 64 bytes long (for public key)
    ///         nor a ABI encoded address.
    ///
    /// @param owner The invalid owner.
    error InvalidOwnerBytesLength(bytes owner);

    /// @notice Thrown if a provided owner is 32 bytes long but does not fit in an `address` type.
    ///
    /// @param owner The invalid owner.
    error InvalidEthereumAddressOwner(bytes owner);

    /// @notice Authorizes (or not) a Keystore record update.
    ///
    /// @dev The `l1BlockHeader` is OPTIONAL. If using this parameter, the implementation MUST check that the provided
    ///      L1 block header is not the default one. This can be done by using `require(l1BlockHeader.number > 0)`.
    ///
    /// @param id The identifier of the Keystore record being updated.
    /// @param currentValue The current value of the Keystore record.
    /// @param newValueHash The new value hash of the Keystore record.
    /// @param l1BlockHeader OPTIONAL: The L1 block header to access and prove L1 state.
    /// @param proof A proof authorizing the update, typically a signature. The proof must commit to both the id and
    ///              the newValueHash, and authorize() implementations must enforce this.
    ///
    /// @return True if the update is authorized, otherwise false.
    function authorize(
        bytes32 id,
        bytes calldata currentValue,
        bytes32 newValueHash,
        BlockHeader calldata l1BlockHeader,
        bytes calldata proof
    ) external view returns (bool) {
        bytes32 hash = keccak256(abi.encodePacked(id, newValueHash));
        return LibCoinbaseSmartWalletRecord.isValidSignatureCalldata(hash, proof, currentValue);
    }
}

