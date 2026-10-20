//! Best-effort zeroing of secret-bearing buffers.

use std::ops::{Deref, DerefMut};

#[cfg(test)]
thread_local! {
    /// Test-only: bytes zeroed by [`wipe`] on this thread, so tests can assert that every buffer
    /// that held credential content was wiped.
    pub(super) static WIPED_BYTES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Overwrites `s` with `zero` using volatile writes, so the compiler cannot drop them as dead.
pub(super) fn wipe<T: Copy>(s: &mut [T], zero: T) {
    #[cfg(test)]
    WIPED_BYTES.with(|c| c.set(c.get() + std::mem::size_of_val(s)));
    for x in s.iter_mut() {
        // SAFETY: `x` is a valid, aligned, exclusive reference to a `Copy` value.
        unsafe { std::ptr::write_volatile(x, zero) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// A vector that is zeroed when dropped, on every exit path.
pub(super) struct Wiped<T: Copy> {
    v: Vec<T>,
    zero: T,
}

impl<T: Copy> Wiped<T> {
    pub(super) fn new(v: Vec<T>, zero: T) -> Self {
        Self { v, zero }
    }
}

impl<T: Copy> Deref for Wiped<T> {
    type Target = Vec<T>;
    fn deref(&self) -> &Vec<T> {
        &self.v
    }
}

impl<T: Copy> DerefMut for Wiped<T> {
    fn deref_mut(&mut self) -> &mut Vec<T> {
        &mut self.v
    }
}

impl<T: Copy> Drop for Wiped<T> {
    fn drop(&mut self) {
        let z = self.zero;
        wipe(&mut self.v, z);
    }
}

/// A fixed-size secret, zeroed when dropped.
pub(super) struct SecretArray<const N: usize>(pub [u8; N]);

impl<const N: usize> Drop for SecretArray<N> {
    fn drop(&mut self) {
        wipe(&mut self.0, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test(unsupported = test)]
    fn wipe_zeroes() {
        let mut v = vec![7u8; 33];
        wipe(&mut v, 0);
        assert!(v.iter().all(|&b| b == 0));
    }
}
