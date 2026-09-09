// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {HKWrapped} from "../src/HKWrapped.sol";
import {AttestorSet} from "../src/AttestorSet.sol";
import {DailyLimit} from "../src/DailyLimit.sol";

/// B1.4's contract: the wrapped HashKinetics test asset on Sepolia (wHKT.sep). Same attestor rules as the vault.
contract HKWrappedTest is Test {
    HKWrapped w;

    uint256 constant PK_A = 0xA11CE;
    uint256 constant PK_B = 0xB0B;
    uint256 constant PK_C = 0xCA7;
    address owner = makeAddr("owner");
    address bob = makeAddr("bob");
    bytes32 constant HK_GENESIS = 0x4e4ea68d48cba1ad4cc7155c19e7768f1fa2cbc99ba0f2b47c58948ec9e971c7;
    bytes32 constant HK_ASSET = 0x0909090909090909090909090909090909090909090909090909090909090909;
    bytes32 constant HK_ACCOUNT = keccak256("an hk account");
    uint256 constant CAP = 500e6;

    event Minted(bytes32 indexed mintId, address indexed to, uint256 amount);
    event Burned(bytes32 indexed burnId, address indexed from, uint256 amount, bytes32 indexed hkAccount, uint256 nonce);

    function setUp() public {
        address[] memory set = new address[](3);
        set[0] = vm.addr(PK_A);
        set[1] = vm.addr(PK_B);
        set[2] = vm.addr(PK_C);
        w = new HKWrapped("Wrapped HK Test (Sepolia)", "wHKT.sep", HK_GENESIS, HK_ASSET, set, 2, CAP, owner);
        vm.warp(1_800_000_000);
    }

    function _sigs(uint256 pk1, uint256 pk2, address to, uint256 amount, bytes32 mintId) internal view returns (bytes[] memory out) {
        if (vm.addr(pk1) > vm.addr(pk2)) (pk1, pk2) = (pk2, pk1);
        bytes32 digest = w.typedDigest(w.mintStructHash(to, amount, mintId));
        out = new bytes[](2);
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(pk1, digest);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(pk2, digest);
        out[0] = abi.encodePacked(r1, s1, v1);
        out[1] = abi.encodePacked(r2, s2, v2);
    }

    function test_metadata() public view {
        assertEq(w.decimals(), 6);
        assertEq(w.symbol(), "wHKT.sep");
        assertEq(w.hkGenesis(), HK_GENESIS);
        assertEq(w.hkAsset(), HK_ASSET);
        assertEq(w.threshold(), 2);
    }

    function test_mint_under_attestations_once() public {
        bytes32 mintId = keccak256("hk lock txid");
        bytes[] memory sigs = _sigs(PK_A, PK_B, bob, 42e6, mintId);
        vm.expectEmit(true, true, true, true, address(w));
        emit Minted(mintId, bob, 42e6);
        w.mint(bob, 42e6, mintId, sigs);
        assertEq(w.balanceOf(bob), 42e6);
        assertEq(w.totalSupply(), 42e6);
        vm.expectRevert(abi.encodeWithSelector(HKWrapped.AlreadyProcessed.selector, mintId));
        w.mint(bob, 42e6, mintId, sigs);
    }

    function test_mint_refuses_short_threshold_zero_amount_and_cap() public {
        bytes32 mintId = keccak256("m1");
        bytes[] memory one = new bytes[](1);
        bytes32 digest = w.typedDigest(w.mintStructHash(bob, 1e6, mintId));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PK_A, digest);
        one[0] = abi.encodePacked(r, s, v);
        vm.expectRevert(abi.encodeWithSelector(AttestorSet.NotEnoughAttestations.selector, 1, 2));
        w.mint(bob, 1e6, mintId, one);
        vm.expectRevert(HKWrapped.ZeroAmount.selector);
        w.mint(bob, 0, mintId, one);
        bytes32 big = keccak256("too big");
        bytes[] memory sigs = _sigs(PK_A, PK_C, bob, CAP + 1, big);
        vm.expectRevert(abi.encodeWithSelector(DailyLimit.DailyCapExceeded.selector, CAP + 1, CAP));
        w.mint(bob, CAP + 1, big, sigs);
    }

    function test_burn_emits_unique_ids_and_destroys_tokens() public {
        bytes32 mintId = keccak256("m2");
        w.mint(bob, 100e6, mintId, _sigs(PK_B, PK_C, bob, 100e6, mintId));
        bytes32 expected = keccak256(abi.encode(block.chainid, address(w), uint256(1)));
        vm.expectEmit(true, true, true, true, address(w));
        emit Burned(expected, bob, 30e6, HK_ACCOUNT, 1);
        vm.prank(bob);
        bytes32 id = w.burn(30e6, HK_ACCOUNT);
        assertEq(id, expected);
        assertEq(w.balanceOf(bob), 70e6);
        assertEq(w.totalSupply(), 70e6);
        vm.prank(bob);
        vm.expectRevert(HKWrapped.ZeroAccount.selector);
        w.burn(1e6, bytes32(0));
    }

    function test_pause_blocks_mint_and_burn_but_not_transfers() public {
        bytes32 mintId = keccak256("m3");
        w.mint(bob, 10e6, mintId, _sigs(PK_A, PK_B, bob, 10e6, mintId));
        vm.prank(vm.addr(PK_C));
        w.pause();
        vm.prank(bob);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        w.burn(1e6, HK_ACCOUNT);
        bytes32 m4 = keccak256("m4");
        bytes[] memory sigs = _sigs(PK_A, PK_B, bob, 1e6, m4);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        w.mint(bob, 1e6, m4, sigs);
        vm.prank(bob);
        w.transfer(owner, 1e6); // an ERC-20 stays an ERC-20 while the bridge is paused
        assertEq(w.balanceOf(owner), 1e6);
    }
}
