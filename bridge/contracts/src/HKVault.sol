// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {AttestorSet} from "./AttestorSet.sol";
import {DailyLimit} from "./DailyLimit.sol";

/// @title HKVault — the Sepolia side of the USDC ↔ testnet-1 bridge (B1, docs/BRIDGE-SEPOLIA-USDC-PLAN.md).
/// @notice Holds one ERC-20 (Circle's Sepolia USDC, 6 decimals — the same 6 as HashKinetics "micro", 1:1).
///   lock(amount, hkAccount)              — pulls USDC, emits Locked(depositId, …); hk-attest mints USDC.sep on
///                                          HashKinetics to hkAccount after Sepolia finality.
///   unlock(to, amount, burnId, sigs[])   — releases USDC for a committed HashKinetics burn (burnId = the HK
///                                          txid) under t-of-n attestor signatures; each burnId once; a daily cap;
///                                          refused while paused.
///   No admin path moves funds. No upgradeability on the testnet (redeploy). Trust label: exactly as safe as
///   the attestor keys and the hk-attest code — said plainly on the site.
contract HKVault is AttestorSet, DailyLimit, ReentrancyGuard {
    using SafeERC20 for IERC20;

    /// @notice The bridged token (Sepolia USDC 0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238 on chain 11155111).
    IERC20 public immutable token;
    /// @notice The HashKinetics chain this vault mirrors: the genesis digest (testnet-1: 4e4ea68d…). Informational —
    ///         the EIP-712 domain (this contract, this chain) already binds every attestation to this vault.
    bytes32 public immutable hkGenesis;

    /// @dev EIP-712: Unlock(address to,uint256 amount,bytes32 burnId)
    bytes32 public constant UNLOCK_TYPEHASH = keccak256("Unlock(address to,uint256 amount,bytes32 burnId)");

    uint256 public lockNonce;
    /// @notice burnId (HashKinetics txid of the AssetBurn) → already released.
    mapping(bytes32 => bool) public processed;
    /// @notice Dust guard for locks (a mint on HashKinetics costs the issuer a fee; 0.01 USDC by default).
    uint256 public minLock;

    event Locked(bytes32 indexed depositId, address indexed sender, uint256 amount, bytes32 indexed hkAccount, uint256 nonce);
    event Unlocked(bytes32 indexed burnId, address indexed to, uint256 amount);
    event MinLockSet(uint256 minLock);

    error ZeroAccount();
    error ZeroAddress();
    error BelowMinLock(uint256 amount, uint256 minLock);
    error AlreadyProcessed(bytes32 burnId);

    constructor(
        IERC20 token_,
        bytes32 hkGenesis_,
        address[] memory attestors_,
        uint256 threshold_,
        uint256 dailyCap_,
        uint256 minLock_,
        address owner_
    ) AttestorSet("HKVault", attestors_, threshold_, owner_) {
        if (address(token_) == address(0)) revert ZeroAddress();
        token = token_;
        hkGenesis = hkGenesis_;
        _initDailyCap(dailyCap_);
        minLock = minLock_;
        emit MinLockSet(minLock_);
    }

    // ---------------------------------------------------------------- Sepolia → HashKinetics

    /// @notice Lock `amount` for HashKinetics account `hkAccount` (its 32-byte id). The caller must have
    ///         approved this vault. Emits Locked with a depositId unique to this vault on this chain.
    function lock(uint256 amount, bytes32 hkAccount) external whenNotPaused nonReentrant returns (bytes32 depositId) {
        if (hkAccount == bytes32(0)) revert ZeroAccount();
        if (amount < minLock) revert BelowMinLock(amount, minLock);
        uint256 nonce = ++lockNonce;
        depositId = keccak256(abi.encode(block.chainid, address(this), nonce));
        token.safeTransferFrom(msg.sender, address(this), amount);
        emit Locked(depositId, msg.sender, amount, hkAccount, nonce);
    }

    /// @notice The depositId a given lock nonce produces on this vault (for the service's ledger and the page).
    function depositIdOf(uint256 nonce) external view returns (bytes32) {
        return keccak256(abi.encode(block.chainid, address(this), nonce));
    }

    // ---------------------------------------------------------------- HashKinetics → Sepolia

    /// @notice The struct hash an attestor signs (EIP-712) to release `amount` to `to` for HK burn `burnId`.
    function unlockStructHash(address to, uint256 amount, bytes32 burnId) public pure returns (bytes32) {
        return keccak256(abi.encode(UNLOCK_TYPEHASH, to, amount, burnId));
    }

    /// @notice Release `amount` to `to` for the HashKinetics burn `burnId`, given `threshold` attestor
    ///         signatures (strictly ascending signer order). Each burnId is released at most once.
    function unlock(address to, uint256 amount, bytes32 burnId, bytes[] calldata sigs)
        external
        whenNotPaused
        nonReentrant
    {
        if (to == address(0)) revert ZeroAddress();
        if (processed[burnId]) revert AlreadyProcessed(burnId);
        _requireAttested(unlockStructHash(to, amount, burnId), sigs);
        _consumeDaily(amount);
        processed[burnId] = true;
        token.safeTransfer(to, amount);
        emit Unlocked(burnId, to, amount);
    }

    // ---------------------------------------------------------------- admin (owner; never moves funds)

    function setDailyCap(uint256 dailyCap_) external onlyOwner {
        _setDailyCap(dailyCap_);
    }

    function setMinLock(uint256 minLock_) external onlyOwner {
        minLock = minLock_;
        emit MinLockSet(minLock_);
    }

    /// @notice The reconciliation number: must equal `supply − burned` of USDC.sep on HashKinetics.
    function reserves() external view returns (uint256) {
        return token.balanceOf(address(this));
    }
}
