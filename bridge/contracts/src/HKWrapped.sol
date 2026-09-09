// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {AttestorSet} from "./AttestorSet.sol";
import {DailyLimit} from "./DailyLimit.sol";

/// @title HKWrapped — the reverse leg (B1.4): a HashKinetics asset wrapped on Sepolia (e.g. `wHKT.sep`).
/// @notice "Lock here, mint there": a holder locks the asset on HashKinetics with a Sepolia destination (a
///         burn-with-destination, re-credited on the way back by the bridge); hk-attest attests the committed
///         HK transaction and `mint`s here under t-of-n signatures. `burn(amount, hkAccount)` on this side
///         emits Burned; hk-attest releases the asset on HashKinetics to `hkAccount`.
///         6 decimals = HashKinetics micro, 1:1. Same attestor rules, daily cap, pause and replay guard as HKVault.
contract HKWrapped is ERC20, AttestorSet, DailyLimit, ReentrancyGuard {
    /// @notice The HashKinetics chain (genesis digest) and asset id this token mirrors. Informational.
    bytes32 public immutable hkGenesis;
    bytes32 public immutable hkAsset;

    /// @dev EIP-712: Mint(address to,uint256 amount,bytes32 mintId)
    bytes32 public constant MINT_TYPEHASH = keccak256("Mint(address to,uint256 amount,bytes32 mintId)");

    /// @notice mintId (the HashKinetics txid of the lock) → already minted.
    mapping(bytes32 => bool) public processed;
    uint256 public burnNonce;

    event Minted(bytes32 indexed mintId, address indexed to, uint256 amount);
    event Burned(bytes32 indexed burnId, address indexed from, uint256 amount, bytes32 indexed hkAccount, uint256 nonce);

    error ZeroAccount();
    error ZeroAddress();
    error ZeroAmount();
    error AlreadyProcessed(bytes32 mintId);

    constructor(
        string memory name_,
        string memory symbol_,
        bytes32 hkGenesis_,
        bytes32 hkAsset_,
        address[] memory attestors_,
        uint256 threshold_,
        uint256 dailyCap_,
        address owner_
    ) ERC20(name_, symbol_) AttestorSet(name_, attestors_, threshold_, owner_) {
        hkGenesis = hkGenesis_;
        hkAsset = hkAsset_;
        _initDailyCap(dailyCap_);
    }

    /// @notice HashKinetics micro = 6 decimals.
    function decimals() public pure override returns (uint8) {
        return 6;
    }

    // ---------------------------------------------------------------- HashKinetics → Sepolia (mint)

    function mintStructHash(address to, uint256 amount, bytes32 mintId) public pure returns (bytes32) {
        return keccak256(abi.encode(MINT_TYPEHASH, to, amount, mintId));
    }

    /// @notice Mint `amount` to `to` for the HashKinetics lock `mintId` under `threshold` attestor signatures.
    function mint(address to, uint256 amount, bytes32 mintId, bytes[] calldata sigs)
        external
        whenNotPaused
        nonReentrant
    {
        if (to == address(0)) revert ZeroAddress();
        if (amount == 0) revert ZeroAmount();
        if (processed[mintId]) revert AlreadyProcessed(mintId);
        _requireAttested(mintStructHash(to, amount, mintId), sigs);
        _consumeDaily(amount);
        processed[mintId] = true;
        _mint(to, amount);
        emit Minted(mintId, to, amount);
    }

    // ---------------------------------------------------------------- Sepolia → HashKinetics (burn)

    /// @notice Burn `amount` here to receive the asset on HashKinetics account `hkAccount` (32-byte id).
    function burn(uint256 amount, bytes32 hkAccount) external whenNotPaused returns (bytes32 burnId) {
        if (hkAccount == bytes32(0)) revert ZeroAccount();
        if (amount == 0) revert ZeroAmount();
        uint256 nonce = ++burnNonce;
        burnId = keccak256(abi.encode(block.chainid, address(this), nonce));
        _burn(msg.sender, amount);
        emit Burned(burnId, msg.sender, amount, hkAccount, nonce);
    }

    // ---------------------------------------------------------------- admin

    function setDailyCap(uint256 dailyCap_) external onlyOwner {
        _setDailyCap(dailyCap_);
    }
}
