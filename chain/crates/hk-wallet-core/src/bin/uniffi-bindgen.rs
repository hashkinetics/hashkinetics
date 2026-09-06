//! `cargo run -p hk-wallet-core --features cli --bin uniffi-bindgen -- generate --library
//! target/release/libhk_wallet_core.so --language kotlin --out-dir <android>/app/src/main/java`
//! — emits `org/hashkinetics/wallet/core/hk_wallet_core.kt` from the proc-macro metadata baked
//! into the library (no UDL file to keep in sync).
fn main() {
    uniffi::uniffi_bindgen_main()
}
