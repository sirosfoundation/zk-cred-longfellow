// Copyright 2026 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// This file is derived in part from google/longfellow-zk (commit 61a8a73),
// rust/core/proto/src/reader/lfc2.rs, writer/lfc1.rs and uleb.rs. It has been MODIFIED: the
// reader is ported to this crate's error type and writes the LFC1 byte layout this crate's
// `Circuit` decodes, with a tighter output budget and an exact two-circuit rule; the ULEB128
// helper is reimplemented. A copy of the Apache-2.0 licence is in
// third_party/google-longfellow-zk/LICENSE and the attribution is repeated in NOTICE. The
// modifications are part of this repository, which is licensed under MPL-2.0 (see LICENSE).

//! Reader for the `LFC2` circuit serialization of Google's newer Rust runtime, converting it to
//! the legacy `LFC1` byte layout that [`crate::circuit::Circuit`] decodes.
//!
//! The nym_auth circuits are published as LFC2 pairs (signature circuit, then hash circuit). LFC2
//! stores each layer's terms as a dictionary of relative deltas with a token stream; the circuit
//! they describe is the same object as in LFC1, so this module expands the terms and writes them
//! out in LFC1 (three-byte sizes, delta-coded wire indices). The circuit id is carried over
//! unchanged and is checked against the recomputed id by [`super::load`].
//!
//! The format is read from the reference implementation
//! (`rust/core/proto/src/reader/lfc2.rs` of google/longfellow-zk) and hardened with the same
//! limits.

use super::error::NymAuthError;

const MAX_WIRES: usize = 5_000_000;
const MAX_TERMS: usize = 20_000_000;
const MAX_DELTAS: usize = 20_000_000;
const MAX_CONSTANTS: usize = 5_000_000;
const MAX_LAYERS: usize = 10_000;
const SIZE_LIMIT: usize = 1 << 24;
/// Output budget for one converted circuit (each expanded term takes 12 bytes). The published
/// circuits convert to about 3 MiB in total.
const MAX_OUT_BYTES: usize = 32 << 20;

fn bad(m: impl Into<String>) -> NymAuthError {
    NymAuthError::Circuit(format!("LFC2: {}", m.into()))
}

struct Rd<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Rd<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], NymAuthError> {
        let end = self
            .p
            .checked_add(n)
            .ok_or_else(|| bad("length overflow"))?;
        let s = self.b.get(self.p..end).ok_or_else(|| bad("truncated"))?;
        self.p = end;
        Ok(s)
    }

    /// ULEB128, at most four bytes.
    fn uleb(&mut self) -> Result<u32, NymAuthError> {
        let mut v = 0u32;
        for i in 0..4 {
            let b = self.take(1)?[0];
            v |= u32::from(b & 0x7f) << (7 * i);
            if b & 0x80 == 0 {
                return Ok(v);
            }
        }
        Err(bad("ULEB128 longer than four bytes"))
    }

    fn size(&mut self, max: usize, what: &str) -> Result<usize, NymAuthError> {
        let v = self.uleb()? as usize;
        if v > max {
            return Err(bad(format!("excessive {what}: {v}")));
        }
        Ok(v)
    }
}

fn put3(out: &mut Vec<u8>, v: usize) -> Result<(), NymAuthError> {
    if v >= SIZE_LIMIT {
        return Err(bad(
            "a value does not fit the three-byte size of the legacy layout",
        ));
    }
    out.extend_from_slice(&[v as u8, (v >> 8) as u8, (v >> 16) as u8]);
    Ok(())
}

fn unzigzag(v: u32) -> u32 {
    (v >> 1) ^ (v & 1).wrapping_neg()
}

/// A legacy index delta: 2*(v - prev) if v >= prev, else 2*(prev - v) + 1.
fn put_delta(out: &mut Vec<u8>, v: u32, prev: u32) -> Result<(), NymAuthError> {
    let enc = if v >= prev {
        2 * u64::from(v - prev)
    } else {
        2 * u64::from(prev - v) + 1
    };
    put3(out, usize::try_from(enc).map_err(|_| bad("index delta"))?)
}

/// Converts the LFC2 circuit at the start of `input` to LFC1 bytes, returning them and the
/// number of input bytes consumed.
pub(super) fn one(input: &[u8]) -> Result<(Vec<u8>, usize), NymAuthError> {
    if !input.starts_with(b"LFC2") {
        return Err(bad("missing LFC2 header"));
    }
    let mut r = Rd { b: input, p: 4 };
    let fid = r.size(255, "field id")?;
    let elt = match fid {
        1 => 32,
        4 => 16,
        _ => return Err(bad(format!("unsupported field id {fid}"))),
    };
    let nv = r.size(MAX_WIRES, "output count")?;
    let nc = r.size(usize::MAX, "copy count")?;
    if nc != 1 {
        return Err(bad("only one copy is supported"));
    }
    let npub = r.size(MAX_WIRES, "public input count")?;
    let subfield = r.size(MAX_WIRES, "subfield boundary")?;
    let ninputs = r.size(MAX_WIRES, "input count")?;
    let nl = r.size(MAX_LAYERS, "layer count")?;
    if npub > ninputs {
        return Err(bad("more public inputs than inputs"));
    }
    let nconst = r.size(MAX_CONSTANTS, "constant count")?;
    let constants = r.take(nconst.checked_mul(elt).ok_or_else(|| bad("overflow"))?)?;

    let mut out = vec![1u8];
    for v in [fid, nv, 1, npub, subfield, ninputs, nl, nconst] {
        put3(&mut out, v)?;
    }
    out.extend_from_slice(constants);

    let mut total_terms = 0usize;
    for _ in 0..nl {
        let logw = r.size(63, "logw")?;
        let nw = r.size(MAX_WIRES, "layer width")?;
        let ndeltas = r.size(MAX_DELTAS, "delta count")?;
        let mut deltas = Vec::with_capacity(ndeltas.min(1 << 16));
        for _ in 0..ndeltas {
            let g = unzigzag(r.uleb()?);
            let h0 = unzigzag(r.uleb()?);
            let h1 = unzigzag(r.uleb()?);
            let k = r.uleb()? as usize;
            if k >= nconst {
                return Err(bad("constant index out of range"));
            }
            deltas.push((g, h0, h1, k));
        }
        let nseg = r.size(MAX_DELTAS, "segment count")?;
        let mut segments: Vec<Vec<u32>> = Vec::with_capacity(nseg.min(1 << 16));
        for _ in 0..nseg {
            let len = r.size(MAX_TERMS, "segment length")?;
            let mut seg = Vec::with_capacity(len.min(1 << 16));
            for _ in 0..len {
                let d = r.uleb()?;
                if d as usize >= deltas.len() {
                    return Err(bad("delta index out of range"));
                }
                seg.push(d);
            }
            segments.push(seg);
        }
        let ntok = r.size(MAX_TERMS, "token count")?;
        let mut tokens = Vec::with_capacity(ntok.min(1 << 16));
        let mut nterms = 0usize;
        for _ in 0..ntok {
            let t = r.uleb()? as usize;
            let seg = segments.get(t).ok_or_else(|| bad("token out of range"))?;
            nterms = nterms.saturating_add(seg.len());
            tokens.push(t);
        }
        total_terms = total_terms.saturating_add(nterms);
        if nterms > MAX_TERMS || total_terms > MAX_TERMS {
            return Err(bad("too many terms"));
        }
        if nterms.saturating_mul(12).saturating_add(out.len()) > MAX_OUT_BYTES {
            return Err(bad("converted circuit exceeds the size limit"));
        }
        put3(&mut out, logw)?;
        put3(&mut out, nw)?;
        put3(&mut out, nterms)?;
        let (mut pg, mut p0, mut p1) = (0u32, 0u32, 0u32);
        for t in tokens {
            for &d in &segments[t] {
                let (dg, d0, d1, k) = deltas[d as usize];
                let (g, h0, h1) = (
                    pg.wrapping_add(dg),
                    p0.wrapping_add(d0),
                    p1.wrapping_add(d1),
                );
                put_delta(&mut out, g, pg)?;
                put_delta(&mut out, h0, p0)?;
                put_delta(&mut out, h1, p1)?;
                put3(&mut out, k)?;
                (pg, p0, p1) = (g, h0, h1);
            }
        }
    }
    out.extend_from_slice(r.take(32)?);
    Ok((out, r.p))
}

/// Converts an LFC2 pair (signature circuit, then hash circuit) to LFC1 bytes. Exactly two
/// circuits are read and nothing may follow them. Callers authenticate the artifact (length and
/// SHA-256, see [`super::profile`]) before calling this; the limits here bound memory regardless.
pub(super) fn to_legacy_pair(artifact: &[u8]) -> Result<Vec<u8>, NymAuthError> {
    let mut out = Vec::new();
    let mut at = 0;
    for _ in 0..2 {
        let (bytes, used) = one(&artifact[at..])?;
        if out.len() + bytes.len() > MAX_OUT_BYTES {
            return Err(bad("converted circuits exceed the size limit"));
        }
        out.extend_from_slice(&bytes);
        at += used;
    }
    if at != artifact.len() {
        return Err(bad("bytes left over after the hash circuit"));
    }
    Ok(out)
}
