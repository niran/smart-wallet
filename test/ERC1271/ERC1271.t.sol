// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import "forge-std/Test.sol";

import {BridgedKeystore} from "keyspace-v2/BridgedKeystore.sol";

import {CoinbaseSmartWallet} from "../../src/CoinbaseSmartWallet.sol";
import {ERC1271} from "../../src/ERC1271.sol";

import {LibCoinbaseSmartWallet} from "../utils/LibCoinbaseSmartWallet.sol";

contract ERC1271Test is Test {
    address private keystore = makeAddr("KeyStore");
    address private aggregator = makeAddr("Aggregator");
    CoinbaseSmartWallet private sut;

    function setUp() public {
        sut = new CoinbaseSmartWallet({keystore_: keystore, aggregator_: aggregator});
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                             TESTS                                              //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @custom:test-section isValidSignature

    function test_isValidSignature_returns0xffffffff_whenStateProofIsInvalid(
        uint248 privateKey,
        bytes32 ksID,
        bytes32 h
    ) external {
        bytes memory signature = _setUpTestWrapper_isValidSignature({
            ksID: ksID,
            privateKey: privateKey,
            isValidProof: false,
            isValidSig: true,
            h: h
        });

        bytes4 result = sut.isValidSignature({hash: h, signature: signature});
        assertEq(result, bytes4(0xffffffff));
    }

    function test_isValidSignature_returns0xffffffff_whenSignatureIsInvalid(
        uint248 privateKey,
        bytes32 ksID,
        bytes32 h
    ) external {
        bytes memory signature = _setUpTestWrapper_isValidSignature({
            ksID: ksID,
            privateKey: privateKey,
            isValidProof: true,
            isValidSig: false,
            h: h
        });

        bytes4 result = sut.isValidSignature({hash: h, signature: signature});
        assertEq(result, bytes4(0xffffffff));
    }

    function test_isValidSignature_returns0x1626ba7e_whenStateProofIsValidAndSignatureIsValid(
        bytes32 ksID,
        uint248 privateKey,
        bytes32 h
    ) external {
        bytes memory signature = _setUpTestWrapper_isValidSignature({
            ksID: ksID,
            privateKey: privateKey,
            isValidProof: true,
            isValidSig: true,
            h: h
        });

        bytes4 result = sut.isValidSignature({hash: h, signature: signature});
        assertEq(result, bytes4(0x1626ba7e));
    }

    /// @custom:test-section eip712Domain

    function test_eip712Domain_returnsTheEip712DomainInformation() external {
        (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
            uint256[] memory extensions
        ) = sut.eip712Domain();

        assertEq(fields, hex"0f");
        assertEq(keccak256(bytes(name)), keccak256("Coinbase Smart Wallet"));
        assertEq(keccak256(bytes(version)), keccak256("1"));
        assertEq(chainId, block.chainid);
        assertEq(verifyingContract, address(sut));
        assertEq(salt, bytes32(0));
        assertEq(abi.encode(extensions), abi.encode(new uint256[](0)));
    }

    /// @custom:test-section domainSeparator

    function test_domainSeparator_returnsTheDomainSeparator() external {
        (, string memory name, string memory version, uint256 chainId, address verifyingContract,,) = sut.eip712Domain();

        bytes32 expected = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                chainId,
                verifyingContract
            )
        );
        assertEq(expected, sut.domainSeparator());
    }

    /// @custom:test-section replaySafeHash

    function test_replaySafeHash_returnsAnEip712HashOfTheGivenHash(uint256 privateKey, bytes32 h) external {
        // Setup test:
        // 1. Set the `.message.hash` key to `h` in "test/ERC1271/ERC712.json".
        // 2. Ensure `privateKey` is a valid private key.
        // 3. Create a wallet from the `privateKey`.
        Vm.Wallet memory wallet;
        {
            string memory json = vm.readFile("test/ERC1271/ERC712.json");
            vm.writeJson({json: json, path: "/tmp/ERC712-test.json"});

            vm.writeJson({json: vm.toString(h), path: "/tmp/ERC712-test.json", valueKey: ".message.hash"});

            privateKey = bound(privateKey, 1, type(uint248).max);
            wallet = vm.createWallet(privateKey, "Wallet");
        }

        bytes32 replaySafeHash = sut.replaySafeHash(h);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign({wallet: wallet, digest: replaySafeHash});

        string[] memory inputs = new string[](8);
        inputs[0] = "cast";
        inputs[1] = "wallet";
        inputs[2] = "sign";
        inputs[3] = "--data";
        inputs[4] = "--from-file";
        inputs[5] = "/tmp/ERC712-test.json";
        inputs[6] = "--private-key";
        inputs[7] = vm.toString(bytes32(privateKey));

        bytes memory expectedSignature = vm.ffi(inputs);
        bytes memory signature = abi.encodePacked(r, s, v);

        assertEq(signature, expectedSignature);
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                         TEST HELPERS                                           //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    function _setUpTestWrapper_isValidSignature(
        bytes32 ksID,
        uint248 privateKey,
        bool isValidProof,
        bool isValidSig,
        bytes32 h
    ) private returns (bytes memory signature) {
        // Setup test:
        // 1. Pick the correct `sigBuilder` method depending on `ksKeyType`.
        // 2. Setup the test for `isValidSignature`;
        // 3. Expect calls to the KeyStore and StateVerifier contracts.
        // 4. If `isValidProof`and using ERC1271 signature expect calls to `ERC1271.isValidSignature`.

        function (Vm.Wallet memory , bytes32, bool )  returns(bytes memory) sigBuilder;
        sigBuilder = LibCoinbaseSmartWallet.webAuthnSignature;

        Vm.Wallet memory wallet;
        uint256 stateRoot;
        bytes memory proof;

        (wallet, stateRoot, proof, signature) = _setUpTest_isValidSignature({
            privateKey: privateKey,
            ksID: ksID,
            h: h,
            isValidProof: isValidProof,
            isValidSig: isValidSig,
            sigBuilder: sigBuilder
        });

        vm.expectCall({callee: keystore, data: abi.encodeWithSelector(BridgedKeystore(keystore).keystoreStorageRoot.selector)});

        if (isValidProof == true && sigBuilder == LibCoinbaseSmartWallet.eip1271Signature) {
            vm.expectCall({callee: wallet.addr, data: abi.encodeWithSelector(ERC1271.isValidSignature.selector)});
        }
    }

    function _setUpTest_isValidSignature(
        bytes32 ksID,
        uint248 privateKey,
        bool isValidProof,
        bool isValidSig,
        function (Vm.Wallet memory , bytes32, bool )  returns(bytes memory) sigBuilder,
        bytes32 h
    ) private returns (Vm.Wallet memory wallet, uint256 stateRoot, bytes memory proof, bytes memory signature) {
        // Setup test:
        // 1. Mock `BridgedKeystore.keystoreStorageRoot` to return 42.
        // 2. Mock `IVerifier.Verify` to return `isValidProof`.
        // 3. Create a Secp256k1 or Secp256r1 wallet.
        // 4. Add the `ksID` as owner.
        // 5. Create a valid or invalid `signature` of `replaySafeHash(h)` depending on `isValidSig`.
        //    NOTE: Invalid signatures are still correctly encoded.

        stateRoot = 42;

        LibCoinbaseSmartWallet.mockKeystore({keystore: keystore, root: stateRoot});
        LibCoinbaseSmartWallet.mockIsValueHashCurrent({
            keystore: keystore,
            result: isValidProof
        });

        wallet = LibCoinbaseSmartWallet.passKeyWallet(privateKey);

        LibCoinbaseSmartWallet.initialize({target: address(sut), ksID: ksID});

        signature = sigBuilder(wallet, sut.replaySafeHash(h), isValidSig);
    }
}
