// Compiles the SP1 guests with the SP1 toolchain and makes their ELFs available to the
// host via `include_elf!("hk-spend-program")` / `include_elf!("hk-mint-program")`.
fn main() {
    sp1_build::build_program("../program");
    sp1_build::build_program("../mint-program");
    sp1_build::build_program("../agg-program");
}
