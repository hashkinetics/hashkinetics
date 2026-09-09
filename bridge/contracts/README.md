# bridge/contracts — the Ethereum side of B1 (Sepolia only)

`HKVault.sol` holds Sepolia USDC: `lock(amount, hkAccount)` → `Locked(depositId, …)` (hk-attest mints `USDC.sep` on testnet-1 after finality); `unlock(to, amount, burnId, sigs[])` releases USDC for a committed HashKinetics burn under **t-of-n EIP-712 attestor signatures**, once per `burnId`, under a per-UTC-day cap, refused while paused. `HKWrapped.sol` is the reverse leg (B1.4): `wHKT.sep`, minted under the same attestations for an HK lock, burned here to be released on HK. Shared rules live in `AttestorSet.sol` (strictly ascending signers, any attestor may pause, only the owner unpauses, two-step ownership, no admin path to funds) and `DailyLimit.sol`. Design: `docs/BRIDGE-SEPOLIA-USDC-PLAN.md`.

Trust label (say it everywhere): the Ethereum side is exactly as safe as the attestor keys and the hk-attest code — ECDSA because Ethereum verifies nothing else. On the HashKinetics side every balance moves under hash-based authority.

## 1 · Test (WSL; one-time toolchain + libs, then `forge test`)

```bash
# one time: Foundry
curl -L https://foundry.paradigm.xyz | bash && source ~/.bashrc && foundryup
forge --version
```

```bash
# libs go under lib/ (gitignored — never submodules in the private tree); pinned tags
cd "/mnt/c/Quranium projects/Quranium/Yadu Projects/HashKinetics/bridge/contracts" && mkdir -p lib \
  && ([ -d lib/forge-std ] || git clone -q --depth 1 --branch v1.9.6 https://github.com/foundry-rs/forge-std lib/forge-std) \
  && ([ -d lib/openzeppelin-contracts ] || git clone -q --depth 1 --branch v5.1.0 https://github.com/OpenZeppelin/openzeppelin-contracts lib/openzeppelin-contracts) \
  && forge build 2>&1 | tail -3 && forge test -vv 2>&1 | tail -40
```

Expected: every test in `test/HKVault.t.sol` (lock, unlock 2-of-3, replay, one signature, non-attestor, duplicate, unsorted, wrong fields, wrong vault, daily cap + rollover, pause by attestor / unpause by owner, rotation, validation, two-step ownership, no admin path) and `test/HKWrapped.t.sol` passes; the fuzz test runs 256 cases.

## 2 · Deploy to Sepolia (founder — the deployer key never leaves your machine)

```bash
# one time, ALONE (interactive prompt): import the deployer key into Foundry's encrypted keystore
cast wallet import hk-deployer --interactive
```

```bash
cd "/mnt/c/Quranium projects/Quranium/Yadu Projects/HashKinetics/bridge/contracts"
export SEPOLIA_RPC_URL="https://…"                    # your provider URL (a credential; never in the tree)
export ETHERSCAN_API_KEY="…"                          # for --verify
export VAULT_TOKEN=0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238   # Circle Sepolia USDC (6 dec)
export HK_GENESIS=0x4e4ea68d48cba1ad4cc7155c19e7768f1fa2cbc99ba0f2b47c58948ec9e971c7
export ATTESTORS=0x…                                  # the hk-attest signer address(es), comma-separated
export THRESHOLD=1                                    # 1 for the single-service POC; 2 once a second attestor exists
export DAILY_CAP=1000000000                           # 1,000 USDC per UTC day
export MIN_LOCK=10000                                 # 0.01 USDC
export VAULT_OWNER=0x…                                # NOT the attestor key; a separate wallet (hardware or Safe)
forge script script/Deploy.s.sol:Deploy --rpc-url "$SEPOLIA_RPC_URL" --account hk-deployer --broadcast --verify --etherscan-api-key "$ETHERSCAN_API_KEY" -vv
```

The script prints `HKVault: 0x…` — record it in `ops/B1-FACTS.md` (vault address, deploy tx, verified-source link, attestor addresses, cap). Reverse leg later: add `WRAPPED=1 HK_ASSET=0x<USDC.sep or test-asset id>`.

## 3 · The first lock by hand (the B1.0 receipt)

```bash
export VAULT=0x…   # from the deploy
export USDC=0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238
export HK_ACCOUNT=0x<32-byte hashkinetics account id>
cast send "$USDC" "approve(address,uint256)" "$VAULT" 20000000 --rpc-url "$SEPOLIA_RPC_URL" --account hk-deployer
cast send "$VAULT" "lock(uint256,bytes32)" 20000000 "$HK_ACCOUNT" --rpc-url "$SEPOLIA_RPC_URL" --account hk-deployer
cast call "$VAULT" "reserves()(uint256)" --rpc-url "$SEPOLIA_RPC_URL"        # 20000000
cast logs --from-block latest --address "$VAULT" --rpc-url "$SEPOLIA_RPC_URL" 'Locked(bytes32,address,uint256,bytes32,uint256)'
```

## 4 · What an attestor signs (for hk-attest and for a second attestor's independent check)

EIP-712 domain `{name: "HKVault", version: "1", chainId, verifyingContract}`; type `Unlock(address to,uint256 amount,bytes32 burnId)` where `burnId` is the HashKinetics txid of the `AssetBurn` and `to` is its 20-byte destination. `vault.typedDigest(vault.unlockStructHash(to, amount, burnId))` returns the exact digest; signatures are 65-byte `r‖s‖v`, ordered by ascending signer address. `HKWrapped` uses `Mint(address to,uint256 amount,bytes32 mintId)` under the domain `{name: <token name>, version: "1", …}`.

## 5 · Not in the POC (on purpose)

No upgradeable proxy (redeploy on a testnet); no admin withdrawal; no general message passing; no price oracle. Mainnet value never flows through this path before X2 (deposit ids in consensus), the audit, and a real attestor committee.
