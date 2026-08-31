//! HK-R5.2: the dedicated verification thread pool.
//!
//! Hash-based signature verification (hbs-lms) allocates large fixed arrays on the
//! STACK — the node's main thread runs at 64 MiB and its tokio workers at 32 MiB for
//! exactly this reason (see hk-node/src/main.rs). A default rayon worker gets 2 MiB
//! and overflows instantly, so verification work MUST run on this pool and nowhere
//! else. Capped at 8 threads: a commit certificate carries only a handful of
//! signatures, and a block's envelope pre-verification saturates well before that
//! on the fleet's machine shapes.

use std::sync::OnceLock;

static POOL: OnceLock<rayon::ThreadPool> = OnceLock::new();

/// The shared verification pool (built on first use).
pub fn verify_pool() -> &'static rayon::ThreadPool {
    POOL.get_or_init(|| {
        let threads = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(2)
            .min(8);
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .stack_size(32 * 1024 * 1024)
            .thread_name(|i| format!("hk-verify-{i}"))
            .build()
            .expect("failed to build the hk verification pool")
    })
}

/// Map `f` over `items` in parallel on the verification pool, preserving order.
/// Small inputs skip the pool — thread handoff costs more than the work.
pub fn par_bools<T, F>(items: &[T], f: F) -> Vec<bool>
where
    T: Sync,
    F: Fn(&T) -> bool + Send + Sync,
{
    if items.len() < 2 {
        return items.iter().map(f).collect();
    }
    use rayon::prelude::*;
    verify_pool().install(|| items.par_iter().map(f).collect())
}

#[cfg(test)]
mod tests {
    #[test]
    fn par_bools_preserves_order_and_values() {
        let items: Vec<u32> = (0..1000).collect();
        let out = super::par_bools(&items, |v| v % 3 == 0);
        assert_eq!(out.len(), 1000);
        for (i, v) in items.iter().enumerate() {
            assert_eq!(out[i], v % 3 == 0, "verdict misordered at {i}");
        }
    }

    #[test]
    fn par_bools_small_inputs_stay_serial() {
        let empty: [u32; 0] = [];
        assert_eq!(super::par_bools(&empty, |_| true), Vec::<bool>::new());
        assert_eq!(super::par_bools(&[7u32], |v| *v == 7), vec![true]);
    }
}
