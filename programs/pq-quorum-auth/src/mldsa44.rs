extern crate alloc;

use alloc::{vec, vec::Vec};
use sha3::{
    Shake128, Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

pub const MLDSA44_PUBLIC_KEY_LEN: usize = 1312;
pub const MLDSA44_SIGNATURE_LEN: usize = 2420;
pub const MLDSA44_PREPARED_PUBLIC_KEY_LEN: usize = MLDSA44_PUBLIC_KEY_LEN + 64 + K * 256 * 4;
pub const MLDSA44_PREPARED_SIGNATURE_LEN: usize = (1 + L) * 256 * 4;
pub const MLDSA44_AZ_ROW_LEN: usize = 256 * 4;
pub const MLDSA44_W1_ROW_LEN: usize = W1_ROW_LEN;
pub const MLDSA44_W1_LEN: usize = W1_LEN;
pub const MLDSA44_ROWS: usize = K;
pub const MLDSA44_COLUMNS: usize = L;

const Q: i32 = 8_380_417;
const D: u32 = 13;
const K: usize = 4;
const L: usize = 4;
const TAU: usize = 39;
const BETA: i32 = 78;
const GAMMA1: i32 = 1 << 17;
const GAMMA2: i32 = (Q - 1) / 88;
const OMEGA: usize = 80;
const CTILDE_LEN: usize = 32;
const Z_POLY_LEN: usize = 32 * 18;
const HINT_LEN: usize = OMEGA + K;
const W1_ROW_LEN: usize = 32 * 6;
const W1_LEN: usize = K * W1_ROW_LEN;

type Poly = Vec<i32>;

pub fn prepare_mldsa44_public_key(public_key: &[u8], prepared: &mut [u8]) -> bool {
    if public_key.len() != MLDSA44_PUBLIC_KEY_LEN
        || prepared.len() != MLDSA44_PREPARED_PUBLIC_KEY_LEN
    {
        return false;
    }

    prepared.fill(0);
    prepared[..MLDSA44_PUBLIC_KEY_LEN].copy_from_slice(public_key);
    let mut tr = [0u8; 64];
    shake256(&mut tr, &[public_key]);
    prepared[MLDSA44_PUBLIC_KEY_LEN..MLDSA44_PUBLIC_KEY_LEN + 64].copy_from_slice(&tr);

    let mut poly = zero_poly();
    for row in 0..K {
        if decode_t1_row_into(&mut poly, public_key, row).is_err() {
            return false;
        }
        for coeff in &mut poly {
            *coeff <<= D;
        }
        ntt(&mut poly);
        to_mont(&mut poly);
        write_prepared_poly(prepared, prepared_t1_offset(row), &poly);
    }

    true
}

#[cfg(test)]
pub fn verify_mldsa44(public_key: &[u8], signature: &[u8], message: &[u8]) -> bool {
    if public_key.len() != MLDSA44_PUBLIC_KEY_LEN || signature.len() != MLDSA44_SIGNATURE_LEN {
        return false;
    }

    let rho = &public_key[..32];
    let c_tilde = &signature[..CTILDE_LEN];
    let z_start = CTILDE_LEN;
    let hint_start = z_start + L * Z_POLY_LEN;
    let hints = &signature[hint_start..hint_start + HINT_LEN];
    let Ok(hint_offsets) = parse_hint_offsets(hints) else {
        return false;
    };

    let mut tr = [0u8; 64];
    shake256(&mut tr, &[public_key]);

    let mut mu = [0u8; 64];
    shake256(&mut mu, &[&tr, &[0u8], &[0u8], message]);

    let mut c = sample_in_ball(c_tilde);
    ntt(&mut c);

    let mut z_hat = Vec::with_capacity(L);
    for i in 0..L {
        let start = z_start + i * Z_POLY_LEN;
        let Ok(mut z) = bit_unpack(&signature[start..start + Z_POLY_LEN], GAMMA1 - 1, GAMMA1)
        else {
            return false;
        };
        if infinity_norm(&z) >= GAMMA1 - BETA {
            return false;
        }
        ntt(&mut z);
        to_mont(&mut z);
        z_hat.push(z);
    }

    let mut w1 = vec![0u8; W1_LEN];
    let mut az = zero_poly();
    let mut a = zero_poly();
    let mut t1 = zero_poly();
    let mut row_w1 = zero_poly();
    for row in 0..K {
        az.fill(0);
        for (col, z_col) in z_hat.iter().enumerate() {
            rej_ntt_poly_into(&mut a, rho, col as u8, row as u8);
            for n in 0..256 {
                az[n] += mont_reduce(i64::from(a[n]) * i64::from(z_col[n]));
            }
        }

        if decode_t1_row_into(&mut t1, public_key, row).is_err() {
            return false;
        }
        for coeff in &mut t1 {
            *coeff <<= D;
        }
        ntt(&mut t1);
        to_mont(&mut t1);

        for n in 0..256 {
            az[n] -= mont_reduce(i64::from(c[n]) * i64::from(t1[n]));
        }
        inv_ntt(&mut az);

        row_w1.fill(0);
        let mut hint_index = hint_offsets[row];
        let hint_end = hint_offsets[row + 1];
        for n in 0..256 {
            let hint = if hint_index < hint_end && usize::from(hints[hint_index]) == n {
                hint_index += 1;
                1
            } else {
                0
            };
            row_w1[n] = use_hint(hint, az[n]);
        }
        simple_bit_pack(
            &row_w1,
            43,
            &mut w1[row * W1_ROW_LEN..(row + 1) * W1_ROW_LEN],
        );
    }

    let mut expected = [0u8; CTILDE_LEN];
    shake256(&mut expected, &[&mu, &w1]);
    expected == c_tilde
}

pub fn prepare_mldsa44_challenge(signature: &[u8], prepared: &mut [u8]) -> bool {
    if signature.len() != MLDSA44_SIGNATURE_LEN || prepared.len() != MLDSA44_PREPARED_SIGNATURE_LEN
    {
        return false;
    }

    let c_tilde = &signature[..CTILDE_LEN];
    let z_start = CTILDE_LEN;
    let hint_start = z_start + L * Z_POLY_LEN;
    let hints = &signature[hint_start..hint_start + HINT_LEN];
    if parse_hint_offsets(hints).is_err() {
        return false;
    }

    prepared.fill(0);
    let mut c = sample_in_ball(c_tilde);
    ntt(&mut c);
    write_prepared_poly(prepared, prepared_c_offset(), &c);
    true
}

pub fn prepare_mldsa44_z_column(signature: &[u8], col: usize, prepared: &mut [u8]) -> bool {
    if signature.len() != MLDSA44_SIGNATURE_LEN
        || prepared.len() != MLDSA44_PREPARED_SIGNATURE_LEN
        || col >= L
    {
        return false;
    }

    let mut z = zero_poly();
    let z_start = CTILDE_LEN;
    let start = z_start + col * Z_POLY_LEN;
    if bit_unpack_into(
        &mut z,
        &signature[start..start + Z_POLY_LEN],
        GAMMA1 - 1,
        GAMMA1,
    )
    .is_err()
    {
        return false;
    }
    if infinity_norm(&z) >= GAMMA1 - BETA {
        return false;
    }
    ntt(&mut z);
    to_mont(&mut z);
    write_prepared_poly(prepared, prepared_z_offset(col), &z);
    true
}

pub fn accumulate_mldsa44_column(
    prepared_public_key: &[u8],
    prepared_signature: &[u8],
    row: usize,
    col: usize,
    az_row: &mut [u8],
) -> bool {
    if prepared_public_key.len() != MLDSA44_PREPARED_PUBLIC_KEY_LEN
        || prepared_signature.len() != MLDSA44_PREPARED_SIGNATURE_LEN
        || row >= K
        || col >= L
        || az_row.len() != MLDSA44_AZ_ROW_LEN
    {
        return false;
    }

    let rho = &prepared_public_key[..32];
    let z_offset = prepared_z_offset(col);
    let mut a = zero_poly();
    rej_ntt_poly_into(&mut a, rho, col as u8, row as u8);
    for (n, a_coeff) in a.iter().enumerate() {
        let z = read_prepared_coeff(prepared_signature, z_offset, n);
        let previous = read_prepared_coeff(az_row, 0, n);
        let next = previous + mont_reduce(i64::from(*a_coeff) * i64::from(z));
        write_prepared_coeff(az_row, 0, n, next);
    }
    true
}

pub fn finalize_mldsa44_row(
    prepared_public_key: &[u8],
    signature: &[u8],
    prepared_signature: &[u8],
    row: usize,
    az_row: &[u8],
    out_w1_row: &mut [u8],
) -> bool {
    if prepared_public_key.len() != MLDSA44_PREPARED_PUBLIC_KEY_LEN
        || signature.len() != MLDSA44_SIGNATURE_LEN
        || prepared_signature.len() != MLDSA44_PREPARED_SIGNATURE_LEN
        || row >= K
        || az_row.len() != MLDSA44_AZ_ROW_LEN
        || out_w1_row.len() != W1_ROW_LEN
    {
        return false;
    }

    let z_start = CTILDE_LEN;
    let hint_start = z_start + L * Z_POLY_LEN;
    let hints = &signature[hint_start..hint_start + HINT_LEN];
    let Ok(hint_offsets) = parse_hint_offsets(hints) else {
        return false;
    };

    let mut az = zero_poly();
    for (n, coeff) in az.iter_mut().enumerate() {
        *coeff = read_prepared_coeff(az_row, 0, n);
    }

    let c_offset = prepared_c_offset();
    let t1_offset = prepared_t1_offset(row);
    for (n, coeff) in az.iter_mut().enumerate() {
        let c = read_prepared_coeff(prepared_signature, c_offset, n);
        let t1 = read_prepared_coeff(prepared_public_key, t1_offset, n);
        *coeff -= mont_reduce(i64::from(c) * i64::from(t1));
    }
    inv_ntt(&mut az);

    out_w1_row.fill(0);
    let bitlen = bit_length(43);
    let mut temp = 0i32;
    let mut bit_index = 0usize;
    let mut out_index = 0usize;
    let mut hint_index = hint_offsets[row];
    let hint_end = hint_offsets[row + 1];
    for (n, coeff) in az.iter().enumerate() {
        let hint = if hint_index < hint_end && usize::from(hints[hint_index]) == n {
            hint_index += 1;
            1
        } else {
            0
        };
        temp |= use_hint(hint, *coeff) << bit_index;
        bit_index += bitlen;
        while bit_index >= 8 {
            out_w1_row[out_index] = temp as u8;
            out_index += 1;
            temp >>= 8;
            bit_index -= 8;
        }
    }
    if bit_index != 0 {
        out_w1_row[out_index] = temp as u8;
    }
    true
}

pub fn finalize_mldsa44_proof(
    prepared_public_key: &[u8],
    signature: &[u8],
    message: &[u8],
    w1: &[u8],
) -> bool {
    if prepared_public_key.len() != MLDSA44_PREPARED_PUBLIC_KEY_LEN
        || signature.len() != MLDSA44_SIGNATURE_LEN
        || w1.len() != W1_LEN
    {
        return false;
    }

    let c_tilde = &signature[..CTILDE_LEN];
    let tr = &prepared_public_key[MLDSA44_PUBLIC_KEY_LEN..MLDSA44_PUBLIC_KEY_LEN + 64];
    let mut mu = [0u8; 64];
    shake256(&mut mu, &[tr, &[0u8], &[0u8], message]);

    let mut expected = [0u8; CTILDE_LEN];
    shake256(&mut expected, &[&mu, w1]);
    expected == c_tilde
}

fn zero_poly() -> Poly {
    vec![0i32; 256]
}

fn prepared_t1_offset(row: usize) -> usize {
    MLDSA44_PUBLIC_KEY_LEN + 64 + row * 256 * 4
}

fn prepared_c_offset() -> usize {
    0
}

fn prepared_z_offset(col: usize) -> usize {
    256 * 4 + col * 256 * 4
}

fn write_prepared_poly(prepared: &mut [u8], offset: usize, poly: &[i32]) {
    for (index, coeff) in poly.iter().enumerate() {
        write_prepared_coeff(prepared, offset, index, *coeff);
    }
}

fn read_prepared_coeff(prepared: &[u8], offset: usize, index: usize) -> i32 {
    let start = offset + index * 4;
    i32::from_le_bytes(prepared[start..start + 4].try_into().unwrap())
}

fn write_prepared_coeff(prepared: &mut [u8], offset: usize, index: usize, coeff: i32) {
    let start = offset + index * 4;
    prepared[start..start + 4].copy_from_slice(&coeff.to_le_bytes());
}

fn shake256(out: &mut [u8], parts: &[&[u8]]) {
    let mut hasher = Shake256::default();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize_xof().read(out);
}

fn sample_in_ball(rho: &[u8]) -> Poly {
    let mut c = zero_poly();
    let mut reader = {
        let mut hasher = Shake256::default();
        hasher.update(rho);
        hasher.finalize_xof()
    };

    let mut signs = [0u8; 8];
    reader.read(&mut signs);

    for i in (256 - TAU)..=255 {
        let mut j = [0u8; 1];
        reader.read(&mut j);
        while usize::from(j[0]) > i {
            reader.read(&mut j);
        }

        c[i] = c[usize::from(j[0])];
        let sign_index = i + TAU - 256;
        let sign_byte = signs[sign_index / 8];
        let sign_bit = (sign_byte >> (sign_index & 7)) & 1;
        c[usize::from(j[0])] = 1 - 2 * i32::from(sign_bit);
    }

    c
}

fn rej_ntt_poly_into(out: &mut [i32], rho: &[u8], col: u8, row: u8) {
    out.fill(0);
    let mut hasher = Shake128::default();
    hasher.update(rho);
    hasher.update(&[col]);
    hasher.update(&[row]);
    let mut reader = hasher.finalize_xof();

    let mut j = 0;
    while j < 256 {
        let mut bytes = [0u8; 3];
        reader.read(&mut bytes);
        if let Some(coeff) = coeff_from_three_bytes(bytes) {
            out[j] = coeff;
            j += 1;
        }
    }
}

fn coeff_from_three_bytes(bytes: [u8; 3]) -> Option<i32> {
    let b2 = i32::from(bytes[2] & 0x7f);
    let z = (b2 << 16) | (i32::from(bytes[1]) << 8) | i32::from(bytes[0]);
    (z < Q).then_some(z)
}

fn parse_hint_offsets(hints: &[u8]) -> Result<[usize; K + 1], ()> {
    if hints.len() != HINT_LEN {
        return Err(());
    }

    let mut offsets = [0usize; K + 1];
    for row in 0..K {
        let next = usize::from(hints[OMEGA + row]);
        if next < offsets[row] || next > OMEGA {
            return Err(());
        }
        let first = offsets[row];
        for index in first..next {
            if index > first && hints[index - 1] >= hints[index] {
                return Err(());
            }
        }
        offsets[row + 1] = next;
    }

    for byte in &hints[offsets[K]..OMEGA] {
        if *byte != 0 {
            return Err(());
        }
    }

    Ok(offsets)
}

fn decode_t1_row_into(out: &mut [i32], public_key: &[u8], row: usize) -> Result<(), ()> {
    let start = 32 + row * 320;
    simple_bit_unpack_into(out, &public_key[start..start + 320], 1023)
}

fn simple_bit_unpack_into(out: &mut [i32], input: &[u8], b: i32) -> Result<(), ()> {
    bit_unpack_into(out, input, 0, b)
}

#[cfg(test)]
fn bit_unpack(input: &[u8], a: i32, b: i32) -> Result<Poly, ()> {
    let mut out = zero_poly();
    bit_unpack_into(&mut out, input, a, b)?;
    Ok(out)
}

fn bit_unpack_into(out: &mut [i32], input: &[u8], a: i32, b: i32) -> Result<(), ()> {
    let bitlen = bit_length(a + b);
    out.fill(0);
    let mut temp = 0i32;
    let mut r_index = 0usize;
    let mut bit_index = 0usize;

    for byte in input {
        temp |= i32::from(*byte) << bit_index;
        bit_index += 8;
        while bit_index >= bitlen {
            if r_index >= 256 {
                return Err(());
            }
            let mask = temp & ((1 << bitlen) - 1);
            out[r_index] = if a == 0 { mask } else { b - mask };
            bit_index -= bitlen;
            temp >>= bitlen;
            r_index += 1;
        }
    }

    let low = (b - (1 << bitlen) + 1).abs();
    if r_index != 256 || !is_in_range(out, low, b) {
        return Err(());
    }
    Ok(())
}

#[cfg(test)]
fn simple_bit_pack(poly: &[i32], b: i32, out: &mut [u8]) {
    out.fill(0);
    let bitlen = bit_length(b);
    let mut temp = 0i32;
    let mut bit_index = 0usize;
    let mut out_index = 0usize;

    for coeff in poly {
        temp |= *coeff << bit_index;
        bit_index += bitlen;
        while bit_index >= 8 {
            out[out_index] = temp as u8;
            out_index += 1;
            temp >>= 8;
            bit_index -= 8;
        }
    }

    if bit_index != 0 {
        out[out_index] = temp as u8;
    }
}

fn bit_length(x: i32) -> usize {
    32 - x.leading_zeros() as usize
}

fn is_in_range(poly: &[i32], low: i32, high: i32) -> bool {
    poly.iter().all(|&x| x >= -low && x <= high)
}

fn infinity_norm(poly: &[i32]) -> i32 {
    poly.iter().map(|&x| center_mod(x).abs()).max().unwrap_or(0)
}

fn center_mod(m: i32) -> i32 {
    let t = full_reduce32(m);
    t - (((Q / 2 - t) >> 31) & Q)
}

fn full_reduce32(a: i32) -> i32 {
    let x = partial_reduce32(a);
    x + ((x >> 31) & Q)
}

fn partial_reduce32(a: i32) -> i32 {
    let x = (a + (1 << 22)) >> 23;
    a - x * Q
}

fn partial_reduce64(a: i64) -> i32 {
    const M: i64 = (1 << 48) / (Q as i64);
    let x = a >> 23;
    let a = a - x * (Q as i64);
    let x = a >> 23;
    let a = a - x * (Q as i64);
    let q = (a * M) >> 48;
    (a - q * (Q as i64)) as i32
}

fn mont_reduce(a: i64) -> i32 {
    const QINV: i32 = 58_728_449;
    let t = (a as i32).wrapping_mul(QINV);
    ((a - (t as i64).wrapping_mul(Q as i64)) >> 32) as i32
}

fn to_mont(poly: &mut [i32]) {
    for coeff in poly {
        *coeff = partial_reduce64(i64::from(*coeff) << 32);
    }
}

fn ntt(poly: &mut [i32]) {
    let mut m = 0;
    let mut len = 128;
    while len >= 1 {
        let mut start = 0;
        while start < 256 {
            m += 1;
            let zeta = i64::from(ZETA_TABLE_MONT[m]);
            for j in start..(start + len) {
                let t = mont_reduce(zeta * i64::from(poly[j + len]));
                poly[j + len] = poly[j] - t;
                poly[j] += t;
            }
            start += len << 1;
        }
        len >>= 1;
    }
}

fn inv_ntt(poly: &mut [i32]) {
    const F_MONT: i64 = 16_382;
    let mut m = 256;
    let mut len = 1;
    while len < 256 {
        let mut start = 0;
        while start < 256 {
            m -= 1;
            let zeta = -i64::from(ZETA_TABLE_MONT[m]);
            for j in start..(start + len) {
                let t = poly[j];
                poly[j] = t + poly[j + len];
                poly[j + len] = mont_reduce(zeta * i64::from(t - poly[j + len]));
            }
            start += len << 1;
        }
        len <<= 1;
    }

    for coeff in poly {
        *coeff = full_reduce32(mont_reduce(F_MONT * i64::from(*coeff)));
    }
}

fn use_hint(hint: i32, r: i32) -> i32 {
    let (r1, r0) = decompose(r);
    if hint == 0 {
        return r1;
    }
    if r0 > 0 {
        if r1 == 43 { 0 } else { r1 + 1 }
    } else if r1 == 0 {
        43
    } else {
        r1 - 1
    }
}

fn decompose(r: i32) -> (i32, i32) {
    let rp = full_reduce32(r);
    let mut r1 = (rp + 127) >> 7;
    r1 = (r1 * 11275 + (1 << 23)) >> 24;
    r1 ^= ((43 - r1) >> 31) & r1;
    let r0 = rp - r1 * 2 * GAMMA2;
    let r0 = r0 - ((((Q - 1) / 2 - r0) >> 31) & Q);
    (r1, r0)
}

const ZETA: i32 = 1753;
const ZETA_TABLE_MONT: [i32; 256] = gen_zeta_table_mont();

const fn gen_zeta_table_mont() -> [i32; 256] {
    let mut result = [0i32; 256];
    let mut x = 1i64;
    let mut i = 0u32;
    while i < 256 {
        result[(i as u8).reverse_bits() as usize] = ((x << 32) % (Q as i64)) as i32;
        x = (x * ZETA as i64) % (Q as i64);
        i += 1;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use fips204_rs::{KeyGen, MlDsa44, SerDes, Signer};

    #[test]
    fn verifies_reference_signature() {
        let (pk, sk) = MlDsa44::keygen_from_seed(&[7u8; 32]);
        let pk_bytes = pk.into_bytes();
        let msg = b"solana pq quorum auth";
        let sig = sk.try_sign(msg, &[]).unwrap();

        assert!(verify_mldsa44(&pk_bytes, &sig, msg));
    }

    #[test]
    fn rejects_modified_signature() {
        let (pk, sk) = MlDsa44::keygen_from_seed(&[9u8; 32]);
        let pk_bytes = pk.into_bytes();
        let msg = b"solana pq quorum auth";
        let mut sig = sk.try_sign(msg, &[]).unwrap();
        sig[100] ^= 1;

        assert!(!verify_mldsa44(&pk_bytes, &sig, msg));
    }

    #[test]
    fn verifies_reference_signature_with_split_rows() {
        let (pk, sk) = MlDsa44::keygen_from_seed(&[12u8; 32]);
        let pk_bytes = pk.into_bytes();
        let msg = b"solana split pq quorum auth";
        let sig = sk.try_sign(msg, &[]).unwrap();
        let mut prepared = vec![0u8; MLDSA44_PREPARED_PUBLIC_KEY_LEN];
        let mut prepared_signature = vec![0u8; MLDSA44_PREPARED_SIGNATURE_LEN];
        let mut w1 = vec![0u8; MLDSA44_W1_LEN];

        assert!(prepare_mldsa44_public_key(&pk_bytes, &mut prepared));
        assert!(prepare_mldsa44_challenge(&sig, &mut prepared_signature));
        for col in 0..MLDSA44_COLUMNS {
            assert!(prepare_mldsa44_z_column(&sig, col, &mut prepared_signature));
        }
        for row in 0..MLDSA44_ROWS {
            let mut az_row = vec![0u8; MLDSA44_AZ_ROW_LEN];
            for col in 0..MLDSA44_COLUMNS {
                assert!(accumulate_mldsa44_column(
                    &prepared,
                    &prepared_signature,
                    row,
                    col,
                    &mut az_row,
                ));
            }
            assert!(finalize_mldsa44_row(
                &prepared,
                &sig,
                &prepared_signature,
                row,
                &az_row,
                &mut w1[row * MLDSA44_W1_ROW_LEN..(row + 1) * MLDSA44_W1_ROW_LEN],
            ));
        }
        assert!(finalize_mldsa44_proof(&prepared, &sig, msg, &w1));
    }
}
