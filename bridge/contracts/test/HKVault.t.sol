// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {HKVault} from "../src/HKVault.sol";
import {AttestorSet} from "../src/AttestorSet.sol";
import {DailyLimit} from "../src/DailyLimit.sol";
import {MockUSDC} from "./MockUSDC.sol";

/// The B1.0 receipt (docs/BRIDGE-SEPOLIA-USDC-PLAN.md §5): lock / unlock / threshold / replay / cap / pause /
/// attestor rotation. Attestors are three test keys; the threshold is 2.
contract HKVaultTest is Test {
    MockUSDC usdc;
    HKVault vault;

    uint256 constant PK_A = 0xA11CE;
    uint256 constant PK_B = 0xB0B;
    uint256 constant PK_C = 0xCA7;
    uint256 constant PK_X = 0xDEAD; // not an attestor
    address attA;
    address attB;
    address attC;
    address attX;

    address owner = makeAddr("owner");
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    bytes32 constant HK_GENESIS = 0x4e4ea68d48cba1ad4cc7155c19e7768f1fa2cbc99ba0f2b47c58948ec9e971c7;
    bytes32 constant HK_ACCOUNT = keccak256("some hashkinetics account id");
    uint256 constant CAP = 1_000e6; // 1,000 USDC per day
    uint256 constant MIN_LOCK = 10_000; // 0.01 USDC

    event Locked(bytes32 indexed depositId, address indexed sender, uint256 amount, bytes32 indexed hkAccount, uint256 nonce);
    event Unlocked(bytes32 indexed burnId, address indexed to, uint256 amount);

    function setUp() public {
        attA = vm.addr(PK_A);
        attB = vm.addr(PK_B);
        attC = vm.addr(PK_C);
        attX = vm.addr(PK_X);
        usdc = new MockUSDC();
        address[] memory set = new address[](3);
        set[0] = attA;
        set[1] = attB;
        set[2] = attC;
        vault = new HKVault(IERC20(address(usdc)), HK_GENESIS, set, 2, CAP, MIN_LOCK, owner);
        usdc.mint(alice, 10_000e6);
        vm.prank(alice);
        usdc.approve(address(vault), type(uint256).max);
        vm.warp(1_800_000_000); // a fixed, sane clock for the daily cap
    }

    // ------------------------------------------------------------ helpers

    /// Sign the unlock struct with `pks`, returned in ascending signer order (what the vault requires).
    function _sigs(uint256[] memory pks, address to, uint256 amount, bytes32 burnId) internal view returns (bytes[] memory out) {
        bytes32 digest = vault.typedDigest(vault.unlockStructHash(to, amount, burnId));
        // sort by signer address (insertion sort; n <= 4)
        for (uint256 i = 1; i < pks.length; i++) {
            uint256 k = pks[i];
            uint256 j = i;
            while (j > 0 && vm.addr(pks[j - 1]) > vm.addr(k)) {
                pks[j] = pks[j - 1];
                j--;
            }
            pks[j] = k;
        }
        out = new bytes[](pks.length);
        for (uint256 i = 0; i < pks.length; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(pks[i], digest);
            out[i] = abi.encodePacked(r, s, v);
        }
    }

    function _two(uint256 a, uint256 b) internal pure returns (uint256[] memory p) {
        p = new uint256[](2);
        p[0] = a;
        p[1] = b;
    }

    function _fund(uint256 amount) internal {
        vm.prank(alice);
        vault.lock(amount, HK_ACCOUNT);
    }

    // ------------------------------------------------------------ lock

    function test_lock_transfers_and_emits_a_unique_deposit_id() public {
        bytes32 expected = keccak256(abi.encode(block.chainid, address(vault), uint256(1)));
        vm.expectEmit(true, true, true, true, address(vault));
        emit Locked(expected, alice, 25e6, HK_ACCOUNT, 1);
        vm.prank(alice);
        bytes32 id = vault.lock(25e6, HK_ACCOUNT);
        assertEq(id, expected);
        assertEq(vault.depositIdOf(1), expected);
        assertEq(usdc.balanceOf(address(vault)), 25e6);
        assertEq(vault.reserves(), 25e6);
        assertEq(vault.lockNonce(), 1);
        // the second lock has a different id
        vm.prank(alice);
        bytes32 id2 = vault.lock(1e6, HK_ACCOUNT);
        assertTrue(id2 != id);
        assertEq(vault.lockNonce(), 2);
    }

    function test_lock_refuses_zero_account_and_dust() public {
        vm.prank(alice);
        vm.expectRevert(HKVault.ZeroAccount.selector);
        vault.lock(1e6, bytes32(0));
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(HKVault.BelowMinLock.selector, MIN_LOCK - 1, MIN_LOCK));
        vault.lock(MIN_LOCK - 1, HK_ACCOUNT);
    }

    function test_lock_refused_while_paused() public {
        vm.prank(attB);
        vault.pause();
        vm.prank(alice);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        vault.lock(1e6, HK_ACCOUNT);
    }

    function testFuzz_lock_any_amount_above_min(uint256 amount) public {
        amount = bound(amount, MIN_LOCK, 10_000e6);
        vm.prank(alice);
        vault.lock(amount, HK_ACCOUNT);
        assertEq(vault.reserves(), amount);
    }

    // ------------------------------------------------------------ unlock: happy path

    function test_unlock_with_two_of_three_releases_once() public {
        _fund(500e6);
        bytes32 burnId = keccak256("hk txid 1");
        bytes[] memory sigs = _sigs(_two(PK_A, PK_C), bob, 120e6, burnId);
        vm.expectEmit(true, true, true, true, address(vault));
        emit Unlocked(burnId, bob, 120e6);
        vault.unlock(bob, 120e6, burnId, sigs);
        assertEq(usdc.balanceOf(bob), 120e6);
        assertEq(vault.reserves(), 380e6);
        assertTrue(vault.processed(burnId));
        assertEq(vault.remainingToday(), CAP - 120e6);
        // replay: same burn id, same (valid) signatures
        vm.expectRevert(abi.encodeWithSelector(HKVault.AlreadyProcessed.selector, burnId));
        vault.unlock(bob, 120e6, burnId, sigs);
    }

    function test_unlock_three_of_three_also_fine() public {
        _fund(500e6);
        uint256[] memory pks = new uint256[](3);
        pks[0] = PK_C;
        pks[1] = PK_A;
        pks[2] = PK_B;
        bytes32 burnId = keccak256("hk txid 2");
        vault.unlock(bob, 1e6, burnId, _sigs(pks, bob, 1e6, burnId));
        assertEq(usdc.balanceOf(bob), 1e6);
    }

    function test_anyone_may_submit_a_valid_unlock() public {
        _fund(500e6);
        bytes32 burnId = keccak256("hk txid 3");
        bytes[] memory sigs = _sigs(_two(PK_A, PK_B), bob, 5e6, burnId);
        vm.prank(makeAddr("relayer"));
        vault.unlock(bob, 5e6, burnId, sigs);
        assertEq(usdc.balanceOf(bob), 5e6);
    }

    // ------------------------------------------------------------ unlock: threshold and signature rules

    function test_unlock_refuses_one_signature() public {
        _fund(500e6);
        bytes32 burnId = keccak256("hk txid 4");
        uint256[] memory one = new uint256[](1);
        one[0] = PK_A;
        bytes[] memory sigs = _sigs(one, bob, 5e6, burnId);
        vm.expectRevert(abi.encodeWithSelector(AttestorSet.NotEnoughAttestations.selector, 1, 2));
        vault.unlock(bob, 5e6, burnId, sigs);
    }

    function test_unlock_does_not_count_a_non_attestor() public {
        _fund(500e6);
        bytes32 burnId = keccak256("hk txid 5");
        bytes[] memory sigs = _sigs(_two(PK_A, PK_X), bob, 5e6, burnId);
        vm.expectRevert(abi.encodeWithSelector(AttestorSet.NotEnoughAttestations.selector, 1, 2));
        vault.unlock(bob, 5e6, burnId, sigs);
    }

    function test_unlock_refuses_the_same_signature_twice() public {
        _fund(500e6);
        bytes32 burnId = keccak256("hk txid 6");
        uint256[] memory one = new uint256[](1);
        one[0] = PK_A;
        bytes[] memory single = _sigs(one, bob, 5e6, burnId);
        bytes[] memory twice = new bytes[](2);
        twice[0] = single[0];
        twice[1] = single[0];
        vm.expectRevert(AttestorSet.SignaturesNotSorted.selector);
        vault.unlock(bob, 5e6, burnId, twice);
    }

    function test_unlock_refuses_unsorted_signatures() public {
        _fund(500e6);
        bytes32 burnId = keccak256("hk txid 7");
        bytes[] memory sorted = _sigs(_two(PK_A, PK_B), bob, 5e6, burnId);
        bytes[] memory reversed = new bytes[](2);
        reversed[0] = sorted[1];
        reversed[1] = sorted[0];
        vm.expectRevert(AttestorSet.SignaturesNotSorted.selector);
        vault.unlock(bob, 5e6, burnId, reversed);
    }

    function test_unlock_signature_is_bound_to_the_fields() public {
        _fund(500e6);
        bytes32 burnId = keccak256("hk txid 8");
        bytes[] memory sigs = _sigs(_two(PK_A, PK_B), bob, 5e6, burnId);
        // a different amount → the recovered signers are random addresses → not attestors (and possibly
        // not in ascending order either) → refused one way or the other, and nothing moves
        vm.expectRevert();
        vault.unlock(bob, 6e6, burnId, sigs);
        // a different recipient
        vm.expectRevert();
        vault.unlock(alice, 5e6, burnId, sigs);
        assertEq(usdc.balanceOf(bob), 0);
        assertEq(vault.reserves(), 500e6);
    }

    function test_unlock_signature_is_bound_to_this_vault() public {
        // a second vault with the same attestors: signatures for one do not open the other (EIP-712 domain)
        address[] memory set = new address[](3);
        set[0] = attA;
        set[1] = attB;
        set[2] = attC;
        HKVault other = new HKVault(IERC20(address(usdc)), HK_GENESIS, set, 2, CAP, MIN_LOCK, owner);
        usdc.mint(address(other), 100e6);
        _fund(100e6);
        bytes32 burnId = keccak256("hk txid 9");
        bytes[] memory sigsForVault = _sigs(_two(PK_A, PK_B), bob, 5e6, burnId);
        vm.expectRevert();
        other.unlock(bob, 5e6, burnId, sigsForVault);
        assertEq(usdc.balanceOf(bob), 0);
        assertTrue(vault.domainSeparator() != other.domainSeparator());
    }

    function test_unlock_refuses_zero_recipient() public {
        _fund(100e6);
        bytes32 burnId = keccak256("hk txid 10");
        bytes[] memory sigs = _sigs(_two(PK_A, PK_B), address(0), 5e6, burnId);
        vm.expectRevert(HKVault.ZeroAddress.selector);
        vault.unlock(address(0), 5e6, burnId, sigs);
    }

    // ------------------------------------------------------------ daily cap

    function test_daily_cap_enforced_and_rolls_over_at_utc_midnight() public {
        _fund(5_000e6);
        bytes32 b1 = keccak256("burn a");
        vault.unlock(bob, 900e6, b1, _sigs(_two(PK_A, PK_B), bob, 900e6, b1));
        assertEq(vault.remainingToday(), 100e6);
        bytes32 b2 = keccak256("burn b");
        bytes[] memory s2 = _sigs(_two(PK_A, PK_B), bob, 101e6, b2);
        vm.expectRevert(abi.encodeWithSelector(DailyLimit.DailyCapExceeded.selector, 101e6, 100e6));
        vault.unlock(bob, 101e6, b2, s2);
        assertFalse(vault.processed(b2)); // a refused unlock is not consumed — the service retries tomorrow
        // exactly the remainder passes
        bytes32 b3 = keccak256("burn c");
        vault.unlock(bob, 100e6, b3, _sigs(_two(PK_A, PK_B), bob, 100e6, b3));
        assertEq(vault.remainingToday(), 0);
        // next UTC day: the cap is fresh and the queued unlock passes
        vm.warp(((block.timestamp / 1 days) + 1) * 1 days);
        assertEq(vault.remainingToday(), CAP);
        vault.unlock(bob, 101e6, b2, s2);
        assertEq(usdc.balanceOf(bob), 900e6 + 100e6 + 101e6);
    }

    function test_owner_can_change_cap_and_min_lock() public {
        vm.prank(owner);
        vault.setDailyCap(10e6);
        assertEq(vault.dailyCap(), 10e6);
        vm.prank(owner);
        vault.setMinLock(1e6);
        assertEq(vault.minLock(), 1e6);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, alice));
        vault.setDailyCap(1);
    }

    // ------------------------------------------------------------ pause

    function test_any_attestor_can_pause_only_owner_unpauses() public {
        vm.prank(attC);
        vault.pause();
        assertTrue(vault.paused());
        _fundExpectPaused();
        bytes32 burnId = keccak256("burn while paused");
        bytes[] memory sigs = _sigs(_two(PK_A, PK_B), bob, 1e6, burnId);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        vault.unlock(bob, 1e6, burnId, sigs);
        // an attestor cannot unpause
        vm.prank(attC);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, attC));
        vault.unpause();
        // the owner can; the queued unlock then passes
        vm.prank(owner);
        vault.unpause();
        _fund(10e6);
        vault.unlock(bob, 1e6, burnId, sigs);
        assertEq(usdc.balanceOf(bob), 1e6);
    }

    function _fundExpectPaused() internal {
        vm.prank(alice);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        vault.lock(1e6, HK_ACCOUNT);
    }

    function test_stranger_cannot_pause() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(AttestorSet.NotAttestorOrOwner.selector, alice));
        vault.pause();
    }

    // ------------------------------------------------------------ attestor rotation

    function test_owner_rotates_attestors_and_old_keys_stop_counting() public {
        _fund(100e6);
        address[] memory set = new address[](2);
        set[0] = attX;
        set[1] = attC;
        vm.prank(owner);
        vault.setAttestors(set, 2);
        assertEq(vault.attestorCount(), 2);
        assertEq(vault.threshold(), 2);
        assertFalse(vault.isAttestor(attA));
        assertTrue(vault.isAttestor(attX));
        bytes32 burnId = keccak256("after rotation");
        // the old pair A+B no longer counts (signatures built BEFORE expectRevert: _sigs makes a view call to the vault,
        // and expectRevert binds to the very next external call)
        bytes[] memory oldPair = _sigs(_two(PK_A, PK_B), bob, 1e6, burnId);
        vm.expectRevert(abi.encodeWithSelector(AttestorSet.NotEnoughAttestations.selector, 0, 2));
        vault.unlock(bob, 1e6, burnId, oldPair);
        // the new pair does
        bytes[] memory newPair = _sigs(_two(PK_X, PK_C), bob, 1e6, burnId);
        vault.unlock(bob, 1e6, burnId, newPair);
        assertEq(usdc.balanceOf(bob), 1e6);
    }

    function test_set_attestors_validation() public {
        address[] memory set = new address[](2);
        set[0] = attA;
        set[1] = attA;
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(AttestorSet.DuplicateAttestor.selector, attA));
        vault.setAttestors(set, 1);
        set[1] = address(0);
        vm.prank(owner);
        vm.expectRevert(AttestorSet.ZeroAttestor.selector);
        vault.setAttestors(set, 1);
        set[1] = attB;
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(AttestorSet.BadThreshold.selector, 3, 2));
        vault.setAttestors(set, 3);
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(AttestorSet.BadThreshold.selector, 0, 2));
        vault.setAttestors(set, 0);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, alice));
        vault.setAttestors(set, 1);
    }

    function test_ownership_is_two_step() public {
        vm.prank(owner);
        vault.transferOwnership(bob);
        assertEq(vault.owner(), owner); // not yet
        vm.prank(bob);
        vault.acceptOwnership();
        assertEq(vault.owner(), bob);
    }

    // ------------------------------------------------------------ invariants

    function test_no_admin_path_moves_funds() public {
        _fund(100e6);
        // the owner has no function that transfers the token; the only outflow is unlock with attestations
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(AttestorSet.NotEnoughAttestations.selector, 0, 2));
        vault.unlock(owner, 100e6, keccak256("owner grab"), new bytes[](0));
        assertEq(vault.reserves(), 100e6);
    }

    function test_reserves_track_locks_minus_unlocks() public {
        _fund(300e6);
        _fund(200e6);
        bytes32 burnId = keccak256("burn z");
        vault.unlock(bob, 150e6, burnId, _sigs(_two(PK_B, PK_C), bob, 150e6, burnId));
        assertEq(vault.reserves(), 500e6 - 150e6);
        assertEq(vault.hkGenesis(), HK_GENESIS);
    }
}
