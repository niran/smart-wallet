// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import "forge-std/Test.sol";

import {LibClone} from "solady/utils/LibClone.sol";

import {CoinbaseSmartWallet} from "../../src/CoinbaseSmartWallet.sol";
import {CoinbaseSmartWalletRecordController} from "../../src/CoinbaseSmartWalletRecordController.sol";
import {CoinbaseSmartWalletFactory} from "../../src/CoinbaseSmartWalletFactory.sol";

import {LibCoinbaseSmartWallet} from "../utils/LibCoinbaseSmartWallet.sol";

contract CoinbaseSmartWalletFactoryTest is Test {
    CoinbaseSmartWallet private sw;
    CoinbaseSmartWalletRecordController private rc;
    CoinbaseSmartWalletFactory private sut;

    function setUp() public {
        sw = new CoinbaseSmartWallet({keystore_: address(0), aggregator_: address(0)});
        sut = new CoinbaseSmartWalletFactory(address(sw));
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                            MODIFIERS                                           //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    modifier withAccountDeployed(bytes32 storageHash, uint256 nonce) {
        address account =
            sut.getAddress({controller: address(rc), storageHash: storageHash, nonce: nonce});
        vm.etch({target: account, newRuntimeBytecode: "Some bytecode"});

        _;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                             TESTS                                              //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @custom:test-section createAccount

    function test_createAccount_deploysTheAccount_whenNotAlreadyDeployed(
        bytes32 storageHash,
        uint256 nonce
    ) external {
        address account = address(
            sut.createAccount({controller: address(rc), storageHash: storageHash, nonce: nonce})
        );
        assertTrue(account != address(0));
        assertGt(account.code.length, 0);
    }

    function test_createAccount_initializesTheAccount_whenNotAlreadyDeployed(
        bytes32 storageHash,
        uint256 nonce
    ) external {
        address expectedAccount = _create2Address({storageHash: storageHash, nonce: nonce});
        bytes32 ksID = keccak256(abi.encodePacked(rc, uint96(0), storageHash));
        vm.expectCall({
            callee: expectedAccount,
            data: abi.encodeCall(CoinbaseSmartWallet.initialize, (ksID))
        });
        sut.createAccount({controller: address(rc), storageHash: storageHash, nonce: nonce});
    }

    function test_createAccount_returnsTheAccountAddress_whenAlreadyDeployed(
        bytes32 storageHash,
        uint256 nonce
    ) external withAccountDeployed(storageHash, nonce) {
        address account = address(
            sut.createAccount({controller: address(rc), storageHash: storageHash, nonce: nonce})
        );
        assertTrue(account != address(0));
        assertGt(account.code.length, 0);
    }

    /// @custom:test-section getAddress

    function test_getAddress_returnsTheAccountCounterfactualAddress(bytes32 storageHash, uint256 nonce)
        external
    {
        address expectedAccountAddress = _create2Address({storageHash: storageHash, nonce: nonce});
        address accountAddress = sut.getAddress({controller: address(rc), storageHash: storageHash, nonce: nonce});

        assertEq(accountAddress, expectedAccountAddress);
    }

    /// @custom:test-section initCodeHash

    function test_initCodeHash_returnsTheInitCodeHash() external {
        assertEq(sut.initCodeHash(), LibClone.initCodeHashERC1967(address(sw)));
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                         TESTS HELPERS                                          //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    function _create2Address(bytes32 storageHash, uint256 nonce)
        private
        view
        returns (address)
    {
        bytes32 ksID = keccak256(abi.encodePacked(rc, uint96(0), storageHash));
        return vm.computeCreate2Address({
            salt: _getSalt({ksID: ksID, nonce: nonce}),
            initCodeHash: LibClone.initCodeHashERC1967(address(sw)),
            deployer: address(sut)
        });
    }

    function _getSalt(bytes32 ksID, uint256 nonce)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(ksID, nonce));
    }
}
