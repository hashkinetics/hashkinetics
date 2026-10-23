pub fn is_odd(x: usize) -> bool {
    x % 2 == 1
}

/// Read `length` bytes of `src` at `*index`, or `None` when they are not there.
///
/// HashKinetics RZ-1 (external report 2026-10-14, fixed 2026-10-22): both readers used to slice
/// `&src[*index..*index + length]` unchecked, so every in-memory parser built on them panicked
/// on an empty, short or mis-typed input instead of refusing it — and the consensus verifier
/// feeds them bytes straight off the wire. They are total now: an out-of-range read is `None`,
/// and every parser propagates it with `?`. Well-formed input reads exactly as before.
pub fn read<'a>(src: &'a [u8], length: usize, index: &usize) -> Option<&'a [u8]> {
    let start = *index;
    let end = start.checked_add(length)?;
    src.get(start..end)
}

/// `read`, then move `*index` past the bytes. `*index` is untouched when the read fails.
pub fn read_and_advance<'a>(src: &'a [u8], length: usize, index: &mut usize) -> Option<&'a [u8]> {
    let result = read(src, length, index)?;
    *index += length;
    Some(result)
}

/// Read a big-endian `u32` and advance (the type codes, levels and leaf numbers of RFC 8554).
pub fn read_u32_and_advance(src: &[u8], index: &mut usize) -> Option<u32> {
    let bytes = read_and_advance(src, 4, index)?;
    Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

#[cfg(test)]
pub mod test_helper {
    use crate::{HashChain, Seed};
    use rand::{rngs::OsRng, RngCore};

    pub fn gen_random_seed<H: HashChain>() -> Seed<H> {
        let mut seed = Seed::default();
        OsRng.fill_bytes(seed.as_mut_slice());
        seed
    }
}
