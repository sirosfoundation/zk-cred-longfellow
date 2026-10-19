//! A minimal, bounds-checked CBOR walker for the IssuerSigned structure. Only definite lengths
//! are accepted, which is what the nym_auth issuance profile requires.

use super::error::{NymAuthError, credential};

type R<T> = Result<T, NymAuthError>;

const MAX_DEPTH: usize = 16;

/// (major type, argument, head length) of the item at `p`.
pub(super) fn head(d: &[u8], p: usize) -> R<(u8, u64, usize)> {
    let b = *d.get(p).ok_or_else(|| credential("truncated CBOR"))?;
    let (mt, ai) = (b >> 5, b & 31);
    match ai {
        0..=23 => Ok((mt, u64::from(ai), 1)),
        24..=27 => {
            let n = 1usize << (ai - 24);
            let bytes = d
                .get(p + 1..p + 1 + n)
                .ok_or_else(|| credential("truncated CBOR head"))?;
            let v = bytes.iter().fold(0u64, |v, &x| (v << 8) | u64::from(x));
            Ok((mt, v, 1 + n))
        }
        _ => Err(credential("indefinite or reserved CBOR length")),
    }
}

pub(super) fn end(d: &[u8], p: usize) -> R<usize> {
    end_depth(d, p, 0)
}

fn end_depth(d: &[u8], p: usize, depth: usize) -> R<usize> {
    if depth > MAX_DEPTH {
        return Err(credential("CBOR nested too deeply"));
    }
    let (mt, v, hl) = head(d, p)?;
    let e = match mt {
        2 | 3 => p
            .checked_add(hl)
            .and_then(|x| x.checked_add(usize::try_from(v).ok()?))
            .ok_or_else(|| credential("CBOR length overflow"))?,
        0 | 1 | 7 => p + hl,
        6 => end_depth(d, p + hl, depth + 1)?,
        4 | 5 => {
            let count = if mt == 5 { v.checked_mul(2) } else { Some(v) }
                .ok_or_else(|| credential("CBOR length overflow"))?;
            // Every item takes at least one byte, so a count beyond the data is truncation.
            if count > (d.len() - p) as u64 {
                return Err(credential("truncated CBOR container"));
            }
            let mut q = p + hl;
            for _ in 0..count {
                q = end_depth(d, q, depth + 1)?;
            }
            q
        }
        _ => return Err(credential("unknown CBOR item type")),
    };
    if e > d.len() {
        return Err(credential("truncated CBOR item"));
    }
    Ok(e)
}

/// The content bytes of the byte or text string at `p`.
pub(super) fn content(d: &[u8], p: usize) -> R<&[u8]> {
    let (mt, v, hl) = head(d, p)?;
    if mt != 2 && mt != 3 {
        return Err(credential("expected a CBOR string"));
    }
    let n = usize::try_from(v).map_err(|_| credential("CBOR length overflow"))?;
    d.get(
        p + hl
            ..p.checked_add(hl)
                .and_then(|x| x.checked_add(n))
                .ok_or_else(|| credential("CBOR length overflow"))?,
    )
    .ok_or_else(|| credential("truncated CBOR string"))
}

/// The value after the text or byte key `key` in the map at `p`.
pub(super) fn map_get(d: &[u8], p: usize, key: &[u8]) -> R<Option<usize>> {
    let (mt, n, hl) = head(d, p)?;
    if mt != 5 {
        return Err(credential("expected a CBOR map"));
    }
    let mut q = p + hl;
    for _ in 0..n {
        let k_end = end(d, q)?;
        let (kmt, _, _) = head(d, q)?;
        if (kmt == 2 || kmt == 3) && content(d, q)? == key {
            return Ok(Some(k_end));
        }
        q = end(d, k_end)?;
    }
    Ok(None)
}

pub(super) fn map_require(d: &[u8], p: usize, key: &[u8], what: &str) -> R<usize> {
    map_get(d, p, key)?.ok_or_else(|| credential(format!("{what} is missing")))
}

pub(super) fn array_item(d: &[u8], p: usize, i: usize) -> R<usize> {
    let (mt, n, hl) = head(d, p)?;
    if mt != 4 {
        return Err(credential("expected a CBOR array"));
    }
    if i as u64 >= n {
        return Err(credential("CBOR array too short"));
    }
    let mut q = p + hl;
    for _ in 0..i {
        q = end(d, q)?;
    }
    Ok(q)
}

pub(super) fn find(hay: &[u8], pat: &[u8]) -> Option<usize> {
    if pat.is_empty() || pat.len() > hay.len() {
        return None;
    }
    hay.windows(pat.len()).position(|w| w == pat)
}

pub(super) fn found(hay: &[u8], pat: &[u8], what: &str) -> R<usize> {
    find(hay, pat).ok_or_else(|| credential(format!("{what} not found")))
}
