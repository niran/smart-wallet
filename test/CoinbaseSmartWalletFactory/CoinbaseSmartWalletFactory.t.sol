// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import "forge-std/Test.sol";

import {LibClone} from "solady/utils/LibClone.sol";
import {ConfigLib} from "keyspace-v3/libs/ConfigLib.sol";

import {CoinbaseSmartWallet} from "../../src/CoinbaseSmartWallet.sol";
import {CoinbaseSmartWalletFactory} from "../../src/CoinbaseSmartWalletFactory.sol";

import {LibCoinbaseSmartWallet} from "../utils/LibCoinbaseSmartWallet.sol";

contract CoinbaseSmartWalletFactoryTest is Test {
    CoinbaseSmartWallet private sw;
    CoinbaseSmartWalletFactory private sut;

    function setUp() public {
        sw = new CoinbaseSmartWallet({masterChainId: block.chainid});
        sut = new CoinbaseSmartWalletFactory(address(sw));
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                            MODIFIERS                                           //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    modifier withAccountDeployed(bytes calldata owner, uint256 nonce) {
        (ConfigLib.Config memory c, bytes memory d, bytes32 configHash) = LibCoinbaseSmartWallet.ownerConfig(owner);
        address account =
            sut.getAddressByHash({initialConfigHash: configHash, nonce: nonce});
        vm.etch({target: account, newRuntimeBytecode: "Some bytecode"});

        _;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                             TESTS                                              //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @custom:test-section createAccount

    function test_createAccount_deploysTheAccount_whenNotAlreadyDeployed(
        bytes calldata initialOwner,
        uint256 nonce
    ) external {
        (ConfigLib.Config memory c, bytes memory configData, bytes32 h) = LibCoinbaseSmartWallet.ownerConfig(initialOwner);
        address account = address(
            sut.createAccount({configData: configData, nonce: nonce})
        );
        assertTrue(account != address(0));
        assertGt(account.code.length, 0);
    }

    function test_createAccount_initializesTheAccount_whenNotAlreadyDeployed(
        bytes calldata initialOwner,
        uint256 nonce
    ) external {
        (ConfigLib.Config memory config, bytes memory configData, bytes32 configHash) = LibCoinbaseSmartWallet.ownerConfig(initialOwner);
        address expectedAccount = _create2Address({initialConfigHash: configHash, nonce: nonce});
        vm.expectCall({
            callee: expectedAccount,
            data: abi.encodeCall(CoinbaseSmartWallet.initialize, (config))
        });
        sut.createAccount({configData: configData, nonce: nonce});
    }

    function test_createAccount_returnsTheAccountAddress_whenAlreadyDeployed(
        bytes calldata initialOwner,
        uint256 nonce
    ) external withAccountDeployed(initialOwner, nonce) {
        (ConfigLib.Config memory c, bytes memory configData, bytes32 h) = LibCoinbaseSmartWallet.ownerConfig(initialOwner);
        address account = address(
            sut.createAccount({configData: configData, nonce: nonce})
        );
        assertTrue(account != address(0));
        assertGt(account.code.length, 0);
    }

    /// @custom:test-section getAddress

    function test_getAddress_returnsTheAccountCounterfactualAddress(bytes32 initialConfigHash, uint256 nonce)
        external
    {
        address expectedAccountAddress = _create2Address({initialConfigHash: initialConfigHash, nonce: nonce});
        address accountAddress = sut.getAddressByHash({initialConfigHash: initialConfigHash, nonce: nonce});

        assertEq(accountAddress, expectedAccountAddress);
    }

    /// @custom:test-section initCodeHash

    function test_initCodeHash_returnsTheInitCodeHash() external {
        assertEq(sut.initCodeHash(), LibClone.initCodeHashERC1967(address(sw)));
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                         TESTS HELPERS                                          //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    function _create2Address(bytes32 initialConfigHash, uint256 nonce)
        private
        view
        returns (address)
    {
        return vm.computeCreate2Address({
            salt: _getSalt({initialConfigHash: initialConfigHash, nonce: nonce}),
            initCodeHash: LibClone.initCodeHashERC1967(address(sw)),
            deployer: address(sut)
        });
    }

    function _getSalt(bytes32 initialConfigHash, uint256 nonce)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(initialConfigHash, nonce));
    }
}
