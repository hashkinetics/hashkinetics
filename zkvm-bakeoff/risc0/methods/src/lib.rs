//! Embeds the compiled guest ELF + image id. Guest package `hk-spend` yields the
//! constants `HK_SPEND_ELF` and `HK_SPEND_ID`.
include!(concat!(env!("OUT_DIR"), "/methods.rs"));
