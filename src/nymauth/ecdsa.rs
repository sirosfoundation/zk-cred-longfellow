//! The signature circuit's 1,037 values for one ECDSA verification, D(Q, d, r, s)
//! (SPEC.md section L5).

use super::error::NymAuthError;
use crate::{
    Codec,
    fields::{FieldElement, fieldp256::FieldP256 as F},
};
use num_bigint::BigUint;

pub(super) const TRACE_LEN: usize = 13 + 4 * 256;

const P_HEX: &str = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
const N_HEX: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
const B_HEX: &str = "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b";
const GX_HEX: &str = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
const GY_HEX: &str = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";

type P3 = [F; 3];

fn unsat(m: &str) -> NymAuthError {
    NymAuthError::Unsatisfied(m.to_string())
}

fn const_be(h: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    // The constants above are valid 64-digit hex, checked by a unit test.
    if let Ok(v) = hex::decode(h)
        && v.len() == 32
    {
        out.copy_from_slice(&v);
    }
    out
}

/// A field element from a big-endian value below p.
pub(super) fn fe_be(b: &[u8; 32]) -> Result<F, NymAuthError> {
    let mut le = *b;
    le.reverse();
    F::try_from(&le).map_err(|_| NymAuthError::InvalidInput("a coordinate is not below p".into()))
}

/// The 32 little-endian bytes of a field element (the circuit input encoding).
pub(super) fn fe_le(x: &F) -> [u8; 32] {
    let mut out = [0u8; 32];
    // Writing 32 bytes into a 32-byte buffer cannot fail.
    let _ = x.encode(&mut &mut out[..]);
    out
}

fn fe_be_bytes(x: &F) -> [u8; 32] {
    let mut b = fe_le(x);
    b.reverse();
    b
}

/// v mod p as big-endian bytes (v < 2^256 < 2p).
pub(super) fn reduce_mod_p(v: &[u8; 32]) -> [u8; 32] {
    let p = BigUint::from_bytes_be(&const_be(P_HEX));
    let r = BigUint::from_bytes_be(v) % p;
    be32(&r)
}

fn be32(v: &BigUint) -> [u8; 32] {
    let b = v.to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - b.len()..].copy_from_slice(&b);
    out
}

pub(super) fn bit(b: &[u8; 32], i: usize) -> usize {
    usize::from((b[31 - i / 8] >> (i % 8)) & 1)
}

struct Curve {
    a: F,
    b3: F,
    n: BigUint,
}

fn dbl(c: &Curve, p: &P3) -> P3 {
    let (x, y, z) = (p[0], p[1], p[2]);
    let two = F::from(2u64);
    let (t0, t1, t2) = (x * x, y * y, z * z);
    let t3 = two * x * y;
    let zz = two * x * z;
    let yz = two * y * z;
    let u = c.a * zz + c.b3 * t2;
    let (v, w) = (t1 - u, t1 + u);
    let m = c.a * t0 - F::from(9u64) * t2 + c.b3 * zz;
    let n = F::from(3u64) * t0 + c.a * t2;
    [t3 * v - yz * m, v * w + n * m, F::from(4u64) * yz * t1]
}

fn add(c: &Curve, p: &P3, q: &P3) -> P3 {
    let (x1, y1, z1, x2, y2, z2) = (p[0], p[1], p[2], q[0], q[1], q[2]);
    let (t0, t1, t2) = (x1 * x2, y1 * y2, z1 * z2);
    let t3 = (x1 + y1) * (x2 + y2) - t0 - t1;
    let t4 = (x1 + z1) * (x2 + z2) - t0 - t2;
    let t5 = (y1 + z1) * (y2 + z2) - t1 - t2;
    let zh = c.a * t4 + c.b3 * t2;
    let (xh, zo) = (t1 - zh, t1 + zh);
    let r1 = F::from(3u64) * t0 + c.a * t2;
    let q4 = c.b3 * t4 + c.a * (t0 - c.a * t2);
    [t3 * xh - t5 * q4, xh * zo + r1 * q4, t5 * zo + t3 * r1]
}

fn identity() -> P3 {
    [F::ZERO, F::ONE, F::ZERO]
}

fn scalar_mul(c: &Curve, p: &P3, k: &BigUint) -> P3 {
    let mut acc = identity();
    for i in (0..k.bits()).rev() {
        acc = dbl(c, &acc);
        if k.bit(i) {
            acc = add(c, &acc, p);
        }
    }
    acc
}

fn affine(p: &P3) -> Option<(F, F)> {
    if bool::from(p[2].is_zero()) {
        return None;
    }
    let zi = p[2].mul_inv();
    Some((p[0] * zi, p[1] * zi))
}

fn from_affine(x: F, y: F) -> P3 {
    [x, y, F::ONE]
}

fn on_curve(c: &Curve, b: &F, x: &F, y: &F) -> bool {
    y.square() == x.square() * *x + c.a * *x + *b
}

/// The 1,037 values for the verification of signature (r, s) on digest `d` under key
/// (`qx`, `qy`), all big-endian. Fails with [`NymAuthError::Unsatisfied`] if the signature does
/// not verify.
pub(super) fn verification(
    qx: &[u8; 32],
    qy: &[u8; 32],
    d: &[u8; 32],
    r: &[u8; 32],
    s: &[u8; 32],
) -> Result<Vec<F>, NymAuthError> {
    let c = Curve {
        a: -F::from(3u64),
        b3: F::from(3u64) * fe_be(&const_be(B_HEX))?,
        n: BigUint::from_bytes_be(&const_be(N_HEX)),
    };
    let b = fe_be(&const_be(B_HEX))?;
    let (rb, sb) = (BigUint::from_bytes_be(r), BigUint::from_bytes_be(s));
    let zero = BigUint::from(0u8);
    if rb == zero || rb >= c.n || sb == zero || sb >= c.n {
        return Err(unsat("signature scalar out of range"));
    }
    let (qxf, qyf) = (fe_be(qx)?, fe_be(qy)?);
    if !on_curve(&c, &b, &qxf, &qyf) {
        return Err(unsat("key is not on the curve"));
    }
    let e = BigUint::from_bytes_be(d) % &c.n;
    let w = sb.modpow(&(&c.n - 2u8), &c.n);
    let u1 = (&e * &w) % &c.n;
    let u2 = (&rb * &w) % &c.n;
    let g = from_affine(fe_be(&const_be(GX_HEX))?, fe_be(&const_be(GY_HEX))?);
    let q = from_affine(qxf, qyf);
    let rp = add(&c, &scalar_mul(&c, &g, &u1), &scalar_mul(&c, &q, &u2));
    let (rxf, ryf) = affine(&rp).ok_or_else(|| unsat("R is the identity"))?;
    let rx = fe_be_bytes(&rxf);
    if BigUint::from_bytes_be(&rx) % &c.n != rb {
        return Err(unsat("signature does not verify"));
    }
    let m = &c.n - &sb;
    let (eb, mb) = (be32(&e), be32(&m));

    let aff = |p: &P3, what: &str| affine(p).ok_or_else(|| unsat(what));
    let (gq, gr, rq) = (
        aff(&add(&c, &g, &q), "G + Q is the identity")?,
        aff(&add(&c, &g, &rp), "G + R is the identity")?,
        aff(&add(&c, &rp, &q), "R + Q is the identity")?,
    );
    let rq_p = from_affine(rq.0, rq.1);
    let grq = aff(&add(&c, &g, &rq_p), "G + R + Q is the identity")?;

    let inv = |x: &F, what: &str| {
        if bool::from(x.is_zero()) {
            Err(unsat(what))
        } else {
            Ok(x.mul_inv())
        }
    };
    let mut out: Vec<F> = Vec::with_capacity(TRACE_LEN);
    out.push(rxf);
    out.push(ryf);
    out.push(inv(&rxf, "rx is zero")?);
    out.push(inv(&fe_be(&mb)?, "m is zero")?);
    out.push(inv(&qxf, "Qx is zero")?);
    for pt in [gq, gr, rq, grq] {
        out.push(pt.0);
        out.push(pt.1);
    }
    let table: [P3; 8] = [
        identity(),
        g,
        q,
        from_affine(gq.0, gq.1),
        from_affine(rxf, ryf),
        from_affine(gr.0, gr.1),
        rq_p,
        from_affine(grq.0, grq.1),
    ];
    let mut acc = table[0];
    for j in 0..256 {
        let pos = 255 - j;
        let idx = bit(&eb, pos) + 2 * bit(&rx, pos) + 4 * bit(&mb, pos);
        let t = table[idx];
        acc = if j == 0 {
            [t[0] * t[1], t[1] * t[1], t[1] * t[2]]
        } else {
            add(&c, &dbl(&c, &acc), &t)
        };
        out.push(F::from(2 * idx as u64) - F::from(7u64));
        out.extend_from_slice(&acc);
    }
    if !bool::from(acc[0].is_zero()) || !bool::from(acc[2].is_zero()) {
        return Err(unsat("the ladder does not end at the identity"));
    }
    debug_assert_eq!(out.len(), TRACE_LEN);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_are_well_formed() {
        for h in [P_HEX, N_HEX, B_HEX, GX_HEX, GY_HEX] {
            assert_eq!(hex::decode(h).unwrap().len(), 32);
        }
        let c = Curve {
            a: -F::from(3u64),
            b3: F::ZERO,
            n: BigUint::from(0u8),
        };
        let b = fe_be(&const_be(B_HEX)).unwrap();
        assert!(on_curve(
            &c,
            &b,
            &fe_be(&const_be(GX_HEX)).unwrap(),
            &fe_be(&const_be(GY_HEX)).unwrap()
        ));
    }
}
