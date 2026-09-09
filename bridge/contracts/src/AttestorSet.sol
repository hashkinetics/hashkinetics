// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title AttestorSet — the t-of-n attestor authority shared by HKVault and HKWrapped (B1, testnets).
/// @notice The Ethereum side of the HashKinetics bridge trusts a THRESHOLD of attestor keys. They are
///         ECDSA because Ethereum verifies nothing else; on the HashKinetics side every balance moves
///         under hash-based authority (docs/BRIDGE-SEPOLIA-USDC-PLAN.md §4). Rules baked in here:
///           - signatures over an EIP-712 digest (domain = this contract on this chain: no replay
///             across vaults, forks or chains);
///           - signers must be strictly ascending, so a signature can never be counted twice;
///           - ANY single attestor may pause (the brake is cheap); only the owner unpauses;
///           - the owner is two-step (Ownable2Step) and never has a path to move funds.
abstract contract AttestorSet is EIP712, Pausable, Ownable2Step {
    /// @dev attestor set + threshold. `attestors` is kept for enumeration; `isAttestor` for O(1) checks.
    address[] private _attestors;
    mapping(address => bool) public isAttestor;
    uint256 public threshold;

    event AttestorsSet(address[] attestors, uint256 threshold);
    event PausedBy(address indexed by);

    error NotAttestorOrOwner(address caller);
    error BadThreshold(uint256 threshold, uint256 attestors);
    error ZeroAttestor();
    error DuplicateAttestor(address attestor);
    error SignaturesNotSorted();
    error NotEnoughAttestations(uint256 valid, uint256 threshold);

    constructor(string memory name_, address[] memory attestors_, uint256 threshold_, address owner_)
        EIP712(name_, "1")
        Ownable(owner_)
    {
        _setAttestors(attestors_, threshold_);
    }

    // ---------------------------------------------------------------- views

    function attestors() external view returns (address[] memory) {
        return _attestors;
    }

    function attestorCount() external view returns (uint256) {
        return _attestors.length;
    }

    /// @notice The EIP-712 domain separator, exposed for off-chain signers (hk-attest) to cross-check.
    function domainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    // ---------------------------------------------------------------- admin

    /// @notice Replace the attestor set. Owner only. Threshold must satisfy 1 <= t <= n.
    function setAttestors(address[] calldata attestors_, uint256 threshold_) external onlyOwner {
        _setAttestors(attestors_, threshold_);
    }

    /// @notice Emergency brake: the owner OR any single attestor. Cheap on purpose.
    function pause() external {
        if (msg.sender != owner() && !isAttestor[msg.sender]) revert NotAttestorOrOwner(msg.sender);
        _pause();
        emit PausedBy(msg.sender);
    }

    /// @notice Only the owner unpauses — resuming is the expensive decision.
    function unpause() external onlyOwner {
        _unpause();
    }

    // ---------------------------------------------------------------- internals

    function _setAttestors(address[] memory attestors_, uint256 threshold_) internal {
        uint256 n = attestors_.length;
        if (threshold_ == 0 || threshold_ > n) revert BadThreshold(threshold_, n);
        // clear the old set
        for (uint256 i = 0; i < _attestors.length; i++) {
            isAttestor[_attestors[i]] = false;
        }
        delete _attestors;
        for (uint256 i = 0; i < n; i++) {
            address a = attestors_[i];
            if (a == address(0)) revert ZeroAttestor();
            if (isAttestor[a]) revert DuplicateAttestor(a);
            isAttestor[a] = true;
            _attestors.push(a);
        }
        threshold = threshold_;
        emit AttestorsSet(attestors_, threshold_);
    }

    /// @dev Verify that at least `threshold` DISTINCT attestors signed `structHash` (EIP-712 typed data).
    ///      Signatures must be ordered by strictly ascending signer address; a non-attestor signature
    ///      is not an error (it simply does not count) so a rotated-out key cannot brick a queued unlock.
    function _requireAttested(bytes32 structHash, bytes[] calldata sigs) internal view {
        bytes32 digest = _hashTypedDataV4(structHash);
        address last = address(0);
        uint256 valid = 0;
        for (uint256 i = 0; i < sigs.length; i++) {
            address signer = ECDSA.recover(digest, sigs[i]);
            if (signer <= last) revert SignaturesNotSorted();
            last = signer;
            if (isAttestor[signer]) valid++;
        }
        if (valid < threshold) revert NotEnoughAttestations(valid, threshold);
    }

    /// @notice The exact digest an attestor signs for `structHash` — for off-chain signers and tests.
    function typedDigest(bytes32 structHash) external view returns (bytes32) {
        return _hashTypedDataV4(structHash);
    }
}
