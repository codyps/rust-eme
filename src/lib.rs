#![no_std]

/// EME (ECB-Mix-ECB) constructs a block cipher with a larger block size from a block cipher with a
/// smaller block size.
///
/// It uses a block cipher to create a tweakable cipher.
///
/// C: cipher text
/// P: public text
/// K: secret key
/// T: tweak
///
/// C = E(T, K, P)
/// P = D(T, K, C)
///
/// k: bits in secret key (K)
/// n: bits per block in the chosen block cipher. Also specifies the used GF(2**n) field.
/// mn: plain text & cipher text size
/// m: tweak bits, number of blocks in E,D used
///
/// m is one of 1..n
///
/// EME-32-AES is a specification of EME with parameters fixed:
///
///  - E,D = aes-256-cbc
///  - n = 128 (bits), 16 bytes
///  - m = 32
///  - (derived) message (text) size = 512 bytes
///
/// Our implimentation has the following fixed parameters:
///
///  - n = 128 (bits), 16 bytes
///
///
/// [EME-32-AES draft spec](http://grouper.ieee.org/groups/1619/email/pdf00020.pdf)

extern crate aesti;

//extern crate generic_array;
//use generic_array::{ArrayLength,GenericArray};

#[macro_use]
extern crate index_fixed;

/*
trait Block {
    type BlockSize: ArrayLength<u8>;
}
*/

/// Multiply by 2 in GF(2**128)
///
/// multByTwo proceedure from the EME-32-AES draft spec
fn mult_by_2(out: &mut [u8;16], input: &[u8;16])
{
    out[0] = 2 * input[0];
    if input[15] >= 128 {
        out[0] ^= 135;
    }

    for j in 1..16 {
        out[j] = 2 * input[j];
        if input[j-1] >= 128 {
            out[j] += 1;
        }
    }
}

fn mult_by_2_ip(out: &mut [u8;16])
{
    let x = out.clone();
    mult_by_2(out, &x);
}

fn encrypt_aes(out: &mut [u8;16], k: &[u8], input: &[u8;16])
{
    let aes = aesti::Aes::with_key(k).unwrap();
    aes.encrypt(out, input);
}

fn encrypt_aes_ip(out: &mut [u8;16], k: &[u8])
{
    let x = out.clone();
    encrypt_aes(out, k, &x);
}

fn xor_blocks(out: &mut [u8;16], in1: &[u8;16], in2: &[u8;16])
{
    for (out,(a,b)) in out.iter_mut().zip(in1.iter().zip(in2.iter())) {
        *out = a ^ b;
    }
}

fn xor_blocks_ip(out: &mut [u8;16], in2: &[u8;16])
{
    for (a, b) in out.iter_mut().zip(in2.iter()) {
        *a = *a ^ b;
    }
}

pub fn eme_32_aes_enc(c: &mut [u8;512], k: &[u8], t: &[u8;16], p: &[u8;512])
{
    let mut l = [0u8;16];
    let mut m = [0u8;16];
    let mut mp = [0u8;16];
    let mut mc = [0u8;16];

    let mut zero = [0u8;16];

    encrypt_aes_ip(&mut zero, k);                  /* set l = 2*AES-enc(k; 0) */
    mult_by_2(&mut l, &zero);

    for j in 0..32 {
        xor_blocks(index_fixed!(&mut c[j*16..]; .. 16),
                   index_fixed!(&p[j*16..]; .. 16),
                   &l);
        encrypt_aes_ip(index_fixed!(&mut c[j*16..];..16), k);  /* PPPj = AES-enc(k; PPj)  */
        mult_by_2_ip(&mut l);
    }
    xor_blocks(&mut mp, index_fixed!(&mut c;..16), t);                     /* mp =(xorSum PPPj) xor t */
    for j in 1..32 {
        xor_blocks_ip(&mut mp, index_fixed!(&c[j*16..];..16));
    }
    encrypt_aes(&mut mc, k, &mp);                      /* mc = AES-enc(k; mp)     */
    xor_blocks(&mut m, &mp, &mc);                       /* m = mp xor mc           */
    for j in 1..32 {
        mult_by_2_ip(&mut m);
        xor_blocks_ip(index_fixed!(&mut c[j*16..];..16), &m);  /* CCCj = 2**(j-1)*m xor PPPj */
    }
    xor_blocks(index_fixed!(&mut c; .. 16), &mc, t);           /* CCC1 = (xorSum CCCj) xor t xor mc */

    {
        let (c_first, c_rest) = c.split_at_mut(16);
        let c_first = index_fixed!(&mut c_first;..16);
        for j in 1..32 {
            xor_blocks_ip(c_first, index_fixed!(&c_rest[(j-1)*16..]; .. 16));
        }
    }
    mult_by_2(&mut l, &zero);                       /* reset l = 2*AES-enc(k; 0) */
    for j in 0..32 {
        encrypt_aes_ip(index_fixed!(&mut c[j*16..];..16), k);  /* CCj = AES-enc(k; CCCj)  */
        xor_blocks_ip(index_fixed!(&mut c[j*16..];.. 16), &l);     /* Cj = 2**(j-1)*l xor CCj */
        mult_by_2_ip(&mut l);
    }
}

/*
 * N: bytes in block for encryption algo
 * M: bytes
 */
//fn e<N: ArrayLength<u8>, M: ArrayLenghth<u8>, Eb: Block, P: GenericArray<u8,N>>(plain_text: P) -> GenericArray<u8,N>


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
