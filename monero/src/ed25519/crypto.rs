/*
 * ed25519/crypto.rs
 *
 * Copyright 2018 Standard Mining
 *
 * Available to be used and modified under the terms of the MIT License.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
 * AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

use super::prelude::*;
use arrayvec::ArrayVec;
use openssl::bn::{BigNum, BigNumContextRef, BigNumRef};
use safemem::prepend;

lazy_static! {
    /* ed25519 constants: */

    /* (2 ** 255) - 19 */
    static ref Q: BigNum = BigNum::from_dec_str(
        "57896044618658097711785492504343953926634992332820282019728792003956564819949",
    ).unwrap();

    /* (2 ** 252) + 27742317777372353535851937790883648493 */
    static ref L: BigNum = BigNum::from_dec_str(
        "7237005577332262213973186563042994240857116359379907606001950938285454250989",
    ).unwrap();

    /* -121665 * inv(121666) */
    static ref D: BigNum = BigNum::from_dec_str(
        "-4513249062541557337682894930092624173785641285191125241628941591882900924598840740",
    ).unwrap();

    /*
     * B_y: 4 * inv(5)
     * B_x: xrecover(B_y)
     * B: (B_x, B_y)
     */
    static ref B: Point = Point {
        x: BigNum::from_dec_str(
           "15112221349535400772501151409588531511454012693041857206046113283949847762202",
        ).unwrap(),
        y: BigNum::from_dec_str(
            "46316835694926478169428394003475163141307993866256225615783033603165251855960",
        ).unwrap(),
    };

    /* Other constants */
    static ref ZERO: BigNum = BigNum::from_u32(0).unwrap();
    static ref ONE: BigNum = BigNum::from_u32(1).unwrap();
}

#[derive(Debug, PartialEq, Eq)]
pub struct Point {
    pub x: BigNum,
    pub y: BigNum,
}

impl Point {
    pub fn to_owned(&self) -> Result<Self> {
        Ok(Point {
            x: self.x.to_owned()?,
            y: self.y.to_owned()?,
        })
    }
}

pub fn sc_reduce32(bytes: &mut [u8; 32], ctx: &mut BigNumContextRef) -> Result<BigNum> {
    // Fix endianness
    #[cfg(target_endian = "little")]
    bytes.reverse();

    // Perform modulo
    let number = BigNum::from_slice(&bytes[..])?;
    let mut reduced = BigNum::new()?;
    reduced.checked_rem(&number, &*L, ctx)?;
    Ok(reduced)
}

pub fn derive_pubkey(bytes: &mut [u8; 32], ctx: &mut BigNumContextRef) -> Result<()> {
    // Fix endianness
    #[cfg(target_endian = "little")]
    bytes.reverse();

    // Run scalar multiplication
    let number = BigNum::from_slice(&bytes[..])?;
    let pt = scalar_mult(&*B, &number, ctx)?;
    encode_point(bytes, &pt);

    Ok(())
}

fn encode_point(bytes: &mut [u8; 32], point: &Point) {
    // Create bitset
    let mut bits = ArrayVec::<[bool; 256]>::new();
    for i in 0..255 {
        bits.push(point.y.is_bit_set(i));
    }
    bits.push(point.x.is_bit_set(0));

    // Pack bytes
    for i in 0..32 {
        let mut byte = 0;
        for j in 0..8 {
            let bit = bits[i * 8 + j] as u8;
            byte |= bit << j;
        }
        bytes[i] = byte;
    }

    bits.dispose();
}

pub fn inv(x: &BigNumRef, ctx: &mut BigNumContextRef) -> Result<BigNum> {
    /* x ** (Q - 2) % Q */

    let mut q2 = Q.to_owned()?;
    q2.sub_word(2)?;
    let mut result = BigNum::new()?;
    result.mod_exp(x, &q2, &*Q, ctx)?;
    Ok(result)
}

pub fn edwards(pt1: &Point, pt2: &Point, ctx: &mut BigNumContextRef) -> Result<Point> {
    /*
     * d_mul = D * x1 * x2 * y1 * y2
     * x3 = (x1 * y2 + x2 * y1) * inv(1 + d_mul)
     * y3 = (y1 * y2 + x1 * x2) * inv(1 - d_mul)
     * -> (x3 % Q, y3 % Q)
     */

    let &Point {
        x: ref x1,
        y: ref y1,
    } = pt1;
    let &Point {
        x: ref x2,
        y: ref y2,
    } = pt2;

    let x_mul = {
        /* x_mul = x1 * y2 + x2 * y1 */
        let mut a = BigNum::new()?;
        a.checked_mul(x1, y2, ctx)?;
        let mut b = BigNum::new()?;
        b.checked_mul(x2, y1, ctx)?;
        let mut result = BigNum::new()?;
        result.checked_add(&a, &b)?;
        result
    };

    let y_mul = {
        /* y_mul = y1 * y2 + x1 * x2 */
        let mut a = BigNum::new()?;
        a.checked_mul(y1, y2, ctx)?;
        let mut b = BigNum::new()?;
        b.checked_mul(x1, x2, ctx)?;
        let mut result = BigNum::new()?;
        result.checked_add(&a, &b)?;
        result
    };

    let d_mul = {
        /* d_mul = D * x1 * x2 * y1 * y2 */
        let mut a = BigNum::new()?;
        a.checked_mul(&*D, x1, ctx)?;
        let mut b = BigNum::new()?;
        b.checked_mul(&a, x2, ctx)?;
        let mut c = BigNum::new()?;
        c.checked_mul(&b, y1, ctx)?;
        let mut result = BigNum::new()?;
        result.checked_mul(&c, y2, ctx)?;
        result
    };

    let x3 = {
        /* x_mul * inv(1 + d_mul) */
        let mut a = BigNum::new()?;
        a.checked_add(&*ONE, &d_mul)?;
        let b = inv(&a, ctx)?;
        let mut result = BigNum::new()?;
        result.checked_mul(&x_mul, &b, ctx)?;
        result
    };

    let y3 = {
        /* y_mul * inv(1 - d_mul) */
        let mut a = BigNum::new()?;
        a.checked_sub(&*ONE, &d_mul)?;
        let b = inv(&a, ctx)?;
        let mut result = BigNum::new()?;
        result.checked_mul(&y_mul, &b, ctx)?;
        result
    };

    let x3_q = {
        let mut result = BigNum::new()?;
        result.checked_rem(&x3, &*Q, ctx)?;
        result
    };

    let y3_q = {
        let mut result = BigNum::new()?;
        result.checked_rem(&y3, &*Q, ctx)?;
        result
    };

    Ok(Point { x: x3_q, y: y3_q })
}

pub fn scalar_mult(p: &Point, e: &BigNumRef, ctx: &mut BigNumContextRef) -> Result<Point> {
    if e == &*ZERO {
        return Ok(Point {
            x: ONE.to_owned()?,
            y: ZERO.to_owned()?,
        });
    }

    let mut e2 = e.to_owned()?;
    e2.div_word(2)?;
    let mut q = scalar_mult(p, &e2, ctx)?;
    q = edwards(&q, &q, ctx)?;

    if e.is_bit_set(0) {
        q = edwards(&q, p, ctx)?;
    }

    q.to_owned()
}

/// Converts an OpenSSL [`BigNumRef`] into a [`Vec<u8>`] in big-endian form,
/// padding it with zero bytes until it is 32 bytes long.
///
/// [`BigNumRef`]: https://docs.rs/openssl/0.10.2/openssl/bn/struct.BigNumRef.html
/// [`Vec<u8>`]: https://doc.rust-lang.org/stable/std/vec/struct.Vec.html
pub fn bn_to_vec32(number: &BigNumRef) -> Vec<u8> {
    // Adds leading zeros
    let mut result = number.to_vec();
    let missing = 32 - result.len();
    let zeroes = &b"00000000000000000000000000000000"[..missing];
    prepend(zeroes, &mut result);
    assert_eq!(result.len(), 32);

    // Fix byte ordering
    #[cfg(target_endian = "little")]
    result.reverse();

    result
}

#[cfg(test)]
use openssl::bn::BigNumContext;

#[test]
fn test_derive_pubkey() {
    let mut ctx = BigNumContext::new().unwrap();
    let mut bytes = [
        0xac, 0xf4, 0x5e, 0x9e, 0x9b, 0x00, 0xda, 0xa8, 0x97, 0x60, 0xb9, 0x82, 0xad, 0xe2, 0x57,
        0xe2, 0x26, 0x82, 0x77, 0x5a, 0x17, 0x70, 0xdb, 0x66, 0xbe, 0xb0, 0x57, 0x82, 0x0b, 0x46,
        0x77, 0x00,
    ];

    derive_pubkey(&mut bytes, &mut ctx).unwrap();
    assert_eq!(
        &bytes[..],
        b"\x15\xf4\x4b\x26\x18\x1c\x20\x1a\x44\x59\x80\xbd\xed\x64\x16\x63\xd8\xf9\x12\xf1\x40\x92\x2f\x69\x09\xf7\x12\x49\x77\xc1\x7c\xc7",
    );
}

#[test]
fn test_encode_point() {
    let mut buffer = [0; 32];
    encode_point(&mut buffer, &*B);
    assert_eq!(
        &buffer[..],
        b"\x58\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66",
    );

    encode_point(
        &mut buffer,
        &Point {
            x: BigNum::from_dec_str("239480239840293842309840923").unwrap(),
            y: BigNum::from_dec_str("58910865193789017923075092").unwrap(),
        },
    );
    assert_eq!(
        &buffer[..],
        b"\x14\x3c\x51\x36\x52\xf2\xbb\x66\xdc\xba\x30\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80",
    );
}

#[test]
fn test_edwards() {
    let mut ctx = BigNumContext::new().unwrap();
    let pt1 = Point {
        x: BigNum::from_dec_str("1923374821399491313195").unwrap(),
        y: BigNum::from_dec_str("886801747184909184381943").unwrap(),
    };
    let pt2 = Point {
        x: BigNum::from_dec_str("6777193769071361351005019").unwrap(),
        y: BigNum::from_dec_str("99681818311341583949189090").unwrap(),
    };

    let Point { x, y } = edwards(&pt1, &pt2, &mut ctx).unwrap();
    assert_eq!(
        &x,
        &BigNum::from_dec_str(
            "19145305399556633246416803965847122123950043313116994625199152792839726592320",
        ).unwrap(),
    );
    assert_eq!(
        &y,
        &BigNum::from_dec_str(
            "1311926177560311914111494945666819815903779764478329976178982182484658429924",
        ).unwrap(),
    );
}

#[test]
fn test_scalar_mult() {
    let mut ctx = BigNumContext::new().unwrap();
    let e = BigNum::from_dec_str("923589108657107938910930183980").unwrap();
    let pt = Point {
        x: BigNum::from_dec_str("38049823940823904823904801805").unwrap(),
        y: BigNum::from_dec_str("90148109258910285903285093819").unwrap(),
    };

    let Point { x, y } = scalar_mult(&pt, &e, &mut ctx).unwrap();
    assert_eq!(
        &x,
        &BigNum::from_dec_str(
            "52693087480432376829905685868955052399509450169404031178816965074041171202152",
        ).unwrap(),
    );
    assert_eq!(
        &y,
        &BigNum::from_dec_str(
            "37289752567154786074414612316137518169923258170068403397141657798034183258505",
        ).unwrap(),
    );
}
