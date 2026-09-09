// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {HKVault} from "../src/HKVault.sol";
import {HKWrapped} from "../src/HKWrapped.sol";
import {MockUSDC} from "../test/MockUSDC.sol";

/// Deploys HKVault (and, for the reverse leg, HKWrapped) from environment variables. Nothing secret is read
/// here — the deployer key is passed to `forge script` itself (--private-key / --account / --ledger).
///
///   VAULT_TOKEN      the ERC-20 to bridge (Sepolia USDC 0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238); "mock" deploys MockUSDC (anvil)
///   HK_GENESIS       bytes32 — testnet-1 4e4ea68d48cba1ad4cc7155c19e7768f1fa2cbc99ba0f2b47c58948ec9e971c7
///   ATTESTORS        comma-separated attestor addresses (the hk-attest signer keys)
///   THRESHOLD        t of n (1 for the single-service POC; 2 once a founding operator holds the second key)
///   DAILY_CAP        token units per UTC day (1000000000 = 1,000 USDC)
///   MIN_LOCK         dust guard (10000 = 0.01 USDC)
///   VAULT_OWNER      the owner (a hardware wallet or a Safe on Sepolia; never the attestor key)
///   WRAPPED          "1" to also deploy HKWrapped (wHKT.sep) with HK_ASSET (bytes32 asset id) and WRAPPED_CAP
contract Deploy is Script {
    function run() external {
        string memory tokenEnv = vm.envString("VAULT_TOKEN");
        bytes32 hkGenesis = vm.envBytes32("HK_GENESIS");
        address[] memory attestors = vm.envAddress("ATTESTORS", ",");
        uint256 threshold = vm.envUint("THRESHOLD");
        uint256 dailyCap = vm.envUint("DAILY_CAP");
        uint256 minLock = vm.envOr("MIN_LOCK", uint256(10_000));
        address owner = vm.envAddress("VAULT_OWNER");

        vm.startBroadcast();
        address token;
        if (keccak256(bytes(tokenEnv)) == keccak256("mock")) {
            token = address(new MockUSDC());
            console2.log("MockUSDC:", token);
        } else {
            token = vm.parseAddress(tokenEnv);
        }
        HKVault vault = new HKVault(IERC20(token), hkGenesis, attestors, threshold, dailyCap, minLock, owner);
        console2.log("HKVault:", address(vault));
        console2.log("  token:", token);
        console2.log("  threshold:", threshold, "of", attestors.length);
        console2.log("  dailyCap:", dailyCap, "minLock:", minLock);

        if (vm.envOr("WRAPPED", uint256(0)) == 1) {
            bytes32 hkAsset = vm.envBytes32("HK_ASSET");
            uint256 wcap = vm.envOr("WRAPPED_CAP", dailyCap);
            HKWrapped w = new HKWrapped("Wrapped HashKinetics Test (Sepolia)", "wHKT.sep", hkGenesis, hkAsset, attestors, threshold, wcap, owner);
            console2.log("HKWrapped wHKT.sep:", address(w));
        }
        vm.stopBroadcast();
    }
}
