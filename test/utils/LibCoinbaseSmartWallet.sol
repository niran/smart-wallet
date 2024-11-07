// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {FCL_ecdsa_utils} from "FreshCryptoLib/FCL_ecdsa_utils.sol";
import {FCL_Elliptic_ZZ} from "FreshCryptoLib/FCL_elliptic.sol";
import {UserOperation, UserOperationLib} from "account-abstraction/interfaces/UserOperation.sol";
import {Vm} from "forge-std/Vm.sol";
import {Base64} from "openzeppelin-contracts/contracts/utils/Base64.sol";
import {UUPSUpgradeable} from "solady/utils/UUPSUpgradeable.sol";
import {WebAuthn} from "webauthn-sol/WebAuthn.sol";

import {CoinbaseSmartWallet} from "../../src/CoinbaseSmartWallet.sol";
import {ERC1271} from "../../src/ERC1271.sol";

import {console} from "forge-std/Test.sol";

enum KeystoreOutput {
    Reverts,
    Fails,
    Succeeds
}

library LibCoinbaseSmartWallet {
    bytes32 private constant COINBASE_SMART_WALLET_LOCATION =
        0x99a34bffa68409ea583717aeb46691b092950ed596c79c2fc789604435b66c00;

    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                         MOCK HELPERS                                           //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    function uninitialize(address target) internal {
        vm.store(target, COINBASE_SMART_WALLET_LOCATION, bytes32(0));
    }

    function initialize(address target, bytes32 ksID) internal {
        vm.store(target, COINBASE_SMART_WALLET_LOCATION, bytes32(ksID));
    }

    function readEip1967ImplementationSlot(address target) internal view returns (address) {
        return address(
            uint160(
                uint256(
                    vm.load({target: target, slot: 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc})
                )
            )
        );
    }

    function mockEip1271(address signer, bool isValid) internal {
        bytes memory res = abi.encode(isValid ? bytes4(0x1626ba7e) : bytes4(0xffffffff));
        vm.mockCall({callee: signer, data: abi.encodeWithSelector(ERC1271.isValidSignature.selector), returnData: res});
    }

    function mockKeystore(address keystore, uint256 root) internal {
        vm.mockCall({
            callee: keystore,
            data: hex"00",
            returnData: abi.encode(root)
        });
    }

    function mockRevertKeystore(address keystore, bytes memory revertData) internal {
        vm.mockCallRevert({
            callee: keystore,
            data: hex"00",
            revertData: revertData
        });
    }

    function mockIsValueHashCurrent(address keystore, bool result) internal {
        vm.mockCall({
            callee: keystore,
            data: hex"00,
            returnData: abi.encode(result)
        });
    }

    function mockRevertIsValueHashCurrent(address keystore, bytes memory revertData)
        internal
    {
        vm.mockCallRevert({
            callee: keystore,
            data: hex"00,
            revertData: revertData
        });
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                         TEST HELPERS                                           //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    function hashUserOp(CoinbaseSmartWallet sut, UserOperation memory userOp, bool forceChainId)
        internal
        view
        returns (bytes32)
    {
        bytes32 h = keccak256(
            abi.encode(
                userOp.sender,
                userOp.nonce,
                keccak256(userOp.initCode),
                keccak256(userOp.callData),
                userOp.callGasLimit,
                userOp.verificationGasLimit,
                userOp.preVerificationGas,
                userOp.maxFeePerGas,
                userOp.maxPriorityFeePerGas,
                keccak256(userOp.paymasterAndData)
            )
        );

        if (
            forceChainId == false
                && bytes4(userOp.callData) == CoinbaseSmartWallet.executeWithoutChainIdValidation.selector
        ) {
            return keccak256(abi.encode(h, sut.entryPoint()));
        } else {
            return keccak256(abi.encode(h, sut.entryPoint(), block.chainid));
        }
    }

    function wallet(uint256 privateKey) internal returns (Vm.Wallet memory wallet_) {
        if (privateKey == 0) {
            privateKey = 1;
        }

        wallet_ = vm.createWallet(privateKey, "Wallet");
    }

    function passKeyWallet(uint256 privateKey) internal view returns (Vm.Wallet memory passKeyWallet_) {
        if (privateKey == 0) {
            privateKey = 1;
        }

        passKeyWallet_.addr = address(0xdead);
        passKeyWallet_.privateKey = privateKey;
        (passKeyWallet_.publicKeyX, passKeyWallet_.publicKeyY) = FCL_ecdsa_utils.ecdsa_derivKpub(privateKey);
    }

    function validNonceKey(CoinbaseSmartWallet sut, UserOperation memory userOp)
        internal
        view
        returns (uint256 nonce)
    {
        // Force the key to be REPLAYABLE_NONCE_KEY when calling `executeWithoutChainIdValidation`
        if (bytes4(userOp.callData) == CoinbaseSmartWallet.executeWithoutChainIdValidation.selector) {
            nonce = 8453 << 64 | uint256(uint64(userOp.nonce));
        }
        // Else ensure the key is NOT REPLAYABLE_NONCE_KEY.
        else {
            uint256 key = userOp.nonce >> 64;
            if (key == 8453) {
                key += 1;
            }

            nonce = key << 64 | uint256(uint64(userOp.nonce));
        }
    }

    function eoaSignature(Vm.Wallet memory w, bytes32 userOpHash, bool validSig)
        internal
        returns (bytes memory sigData)
    {
        uint8 v;
        bytes32 r;
        bytes32 s;
        bytes memory sig = bytes("invalid by default");
        if (validSig) {
            (v, r, s) = vm.sign(w, userOpHash);
        }

        sig = abi.encodePacked(r, s, v);
        bytes memory signer = abi.encode(w.addr);
        sigData = _encodeUserOpSignature(w, sig, signer);
    }

    function eip1271Signature(Vm.Wallet memory w, bytes32 userOpHash, bool validSig)
        internal
        returns (bytes memory sigData)
    {
        bytes memory sig = bytes.concat("CUSTOM EIP1271 SIGNATURE: ", userOpHash);
        sigData = abi.encode(sig, w.publicKeyX, w.publicKeyY);

        mockEip1271({signer: w.addr, isValid: validSig});
    }

    function webAuthnSignature(Vm.Wallet memory w, bytes32 userOpHash, bool validSig)
        internal
        returns (bytes memory sigData)
    {
        string memory challengeb64url = Base64.encodeURL(abi.encode(userOpHash));
        string memory clientDataJSON = string(
            abi.encodePacked(
                '{"type":"webauthn.get","challenge":"',
                challengeb64url,
                '","origin":"https://sign.coinbase.com","crossOrigin":false}'
            )
        );

        // Authenticator data for Chrome Profile touchID signature
        bytes memory authenticatorData = hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000000";

        bytes32 h = sha256(abi.encodePacked(authenticatorData, sha256(bytes(clientDataJSON))));

        WebAuthn.WebAuthnAuth memory webAuthn;
        webAuthn.authenticatorData = authenticatorData;
        webAuthn.clientDataJSON = clientDataJSON;
        webAuthn.typeIndex = 1;
        webAuthn.challengeIndex = 23;

        if (validSig) {
            (bytes32 r, bytes32 s) = vm.signP256(w.privateKey, h);
            if (uint256(s) > (FCL_Elliptic_ZZ.n / 2)) {
                s = bytes32(FCL_Elliptic_ZZ.n - uint256(s));
            }
            webAuthn.r = uint256(r);
            webAuthn.s = uint256(s);
        }

        bytes memory sig = abi.encode(webAuthn);
        bytes memory signer = abi.encode(w.publicKeyX, w.publicKeyY);
        sigData = _encodeUserOpSignature(w, sig, signer);
    }

    function _encodeUserOpSignature(Vm.Wallet memory w, bytes memory sig, bytes memory signer)
        internal
        pure
        returns (bytes memory)
    {
        CoinbaseSmartWallet.SignatureWrapper memory sigWrapper = CoinbaseSmartWallet.SignatureWrapper({
            ownerIndex: 0,
            signatureData: sig
        });
        bytes[] memory signers = new bytes[](1);
        signers[0] = signer;
        CoinbaseSmartWalletRecordData memory recordData = CoinbaseSmartWalletRecordData({
            signers: signers,
            sidecar: bytes("")
        });
        UserOpSignature memory userOpSig = UserOpSignature({
            sig: abi.encode(sigWrapper),
            recordData: abi.encode(recordData),
            confirmedValueHashStorageProof: new bytes[](0),
            useAggregator: false
        });
        return abi.encode(userOpSig);
    }

    function isApprovedSelector(bytes4 selector) internal pure returns (bool) {
        return selector == UUPSUpgradeable.upgradeToAndCall.selector;
    }

    function approvedSelectors() internal pure returns (bytes4[] memory selectors) {
        selectors = new bytes4[](1);
        selectors[0] = UUPSUpgradeable.upgradeToAndCall.selector;
    }

    function notApprovedSelectors() internal pure returns (bytes4[] memory selectors) {
        selectors = new bytes4[](2);
        selectors[0] = CoinbaseSmartWallet.execute.selector;
        selectors[1] = CoinbaseSmartWallet.executeBatch.selector;
    }
}
