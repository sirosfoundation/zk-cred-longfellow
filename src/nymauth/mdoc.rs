//! The hash circuit's semantic bits S for an mdoc nym_auth credential (SPEC.md L4.2).

use super::{
    cbor::{array_item, content, end, found, head, map_get, map_require},
    error::{NymAuthError, credential},
    profile::Profile,
    sha::{IV, faces, faces_padded, pad, sha256, word},
    wipe::Wiped,
};

type R<T> = Result<T, NymAuthError>;

/// (haystack, pattern, padded message the window is read from, window width)
type Window<'a> = (&'a [u8], Vec<u8>, &'a [u8], usize);

pub(super) const DOC_TYPE: &str = "eu.europa.ec.eudi.nym_auth.1";
pub(super) const DST: &[u8] = b"nym_auth/v1/known-offender-matching-ssc";

/// What the witness needs of the credential besides S.
pub(super) struct Parsed {
    /// The COSE Sig_structure the issuer signed.
    pub signed: Vec<u8>,
    pub issuer_sig: [u8; 64],
    /// Device key coordinates, big-endian.
    pub x: [u8; 32],
    pub y: [u8; 32],
}

impl Drop for Parsed {
    fn drop(&mut self) {
        super::wipe::wipe(&mut self.signed, 0);
        super::wipe::wipe(&mut self.issuer_sig, 0);
        super::wipe::wipe(&mut self.x, 0);
        super::wipe::wipe(&mut self.y, 0);
    }
}

/// The nym message DST || secret_seed || 0x00*32 || verifier_input (119 bytes).
pub(super) fn nym_message(seed: &[u8; 16], vi: &[u8; 32]) -> Wiped<u8> {
    let mut m = Vec::with_capacity(119);
    m.extend_from_slice(DST);
    m.extend_from_slice(seed);
    m.extend_from_slice(&[0u8; 32]);
    m.extend_from_slice(vi);
    Wiped::new(m, 0)
}

fn fit(m: &[u8], blocks: usize, what: &str) -> R<Vec<u8>> {
    pad(m, blocks).ok_or_else(|| {
        credential(format!(
            "{what} of {} bytes does not fit {blocks} blocks",
            m.len()
        ))
    })
}

/// Builds S. The returned buffer holds bits derived from `seed`; it is wiped on drop.
pub(super) fn semantic(
    d: &[u8],
    seed: &[u8; 16],
    vi: &[u8; 32],
    profile: &Profile,
) -> R<(Wiped<u8>, Parsed)> {
    let auth = map_require(d, 0, b"issuerAuth", "issuerAuth")?;
    let spaces = map_require(d, 0, b"nameSpaces", "nameSpaces")?;
    let prot = array_item(d, auth, 0)?;
    let pay = array_item(d, auth, 2)?;
    let sigp = array_item(d, auth, 3)?;
    let (prot_end, pay_end) = (end(d, prot)?, end(d, pay)?);
    let sig = [
        &b"\x84\x6aSignature1"[..],
        &d[prot..prot_end],
        b"\x40",
        &d[pay..pay_end],
    ]
    .concat();
    let issuer_sig: [u8; 64] = content(d, sigp)?
        .try_into()
        .map_err(|_| credential("issuer signature is not 64 bytes"))?;

    let ns = map_get(d, spaces, DOC_TYPE.as_bytes())?
        .ok_or_else(|| credential("nym_auth namespace is missing"))?;
    let (nmt, n, hl) = head(d, ns)?;
    if nmt != 4 {
        return Err(credential("namespace is not an array"));
    }
    let (mut item, mut ssc) = (None, None);
    let mut q = ns + hl;
    for _ in 0..n {
        let e = end(d, q)?;
        let (_, _, thl) = head(d, q)?;
        let c = content(d, q + thl)?;
        let id = map_require(c, 0, b"elementIdentifier", "elementIdentifier")?;
        match content(c, id)? {
            b"birth_date" => item = Some(d[q..e].to_vec()),
            b"ssc" => ssc = Some(d[q..e].to_vec()),
            _ => {}
        }
        q = e;
    }
    let item = item.ok_or_else(|| credential("birth_date attribute is missing"))?;
    let ssc = ssc.ok_or_else(|| credential("ssc attribute is missing"))?;

    let sp = fit(&sig, profile.b_sig, "signed message")?;
    let ip = fit(&item, profile.b_item, "birth_date item")?;
    let cp = fit(&ssc, profile.b_ssc, "ssc item")?;

    let mut s = Wiped::new(Vec::with_capacity(profile.semantic_len), 0u8);
    for p in [&sp, &ip, &cp] {
        faces_padded(p, IV, &mut s);
    }
    // faces(secret_seed, 1) and faces(nym, 2)
    faces(seed, 1, &mut s).ok_or_else(|| credential("seed does not fit one block"))?;
    let nym = nym_message(seed, vi);
    faces(&nym, 2, &mut s).ok_or_else(|| credential("nym message does not fit two blocks"))?;
    for m in [&sig, &item, &ssc] {
        word(&mut s, m.len() as u64, 16);
    }

    let digest_of = |m: &[u8]| [&b"\x58\x20"[..], &sha256(m)].concat();
    let windows: [Window<'_>; 10] = [
        (&sig, b"\x67docType".to_vec(), &sp, 38),
        (&sig, digest_of(&item), &sp, 34),
        (
            &item,
            b"\x71elementIdentifier\x6abirth_date".to_vec(),
            &ip,
            29,
        ),
        (&item, b"\x6celementValue\xd9\x03\xec\x6a".to_vec(), &ip, 27),
        (
            &sig,
            b"\x69deviceKey\xa4\x01\x02\x20\x01\x21\x58\x20".to_vec(),
            &sp,
            85,
        ),
        (&sig, b"\x69validFrom\xc0\x74".to_vec(), &sp, 32),
        (&sig, b"\x6avalidUntil\xc0\x74".to_vec(), &sp, 33),
        (&sig, digest_of(&ssc), &sp, 34),
        (&ssc, b"\x71elementIdentifier\x63ssc".to_vec(), &cp, 22),
        (&ssc, b"\x6celementValue\x58\x20".to_vec(), &cp, 47),
    ];
    let mut dk = 0;
    for (k, (hay, pat, m, w)) in windows.iter().enumerate() {
        let o = found(hay, pat, "an mdoc window")?;
        if k == 4 {
            dk = o;
        }
        word(&mut s, o as u64, 16);
        for i in 0..*w {
            word(&mut s, u64::from(*m.get(o + i).unwrap_or(&0)), 8);
        }
    }
    let x: [u8; 32] = sig
        .get(dk + 18..dk + 50)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| credential("device key x out of range"))?;
    let y: [u8; 32] = sig
        .get(dk + 53..dk + 85)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| credential("device key y out of range"))?;
    Ok((
        s,
        Parsed {
            signed: sig,
            issuer_sig,
            x,
            y,
        },
    ))
}
