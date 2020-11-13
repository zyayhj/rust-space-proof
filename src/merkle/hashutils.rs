// use ring::digest::{digest, Algorithm, Context, Digest};
use super::digest::{Algorithm, Digest};
use ff::{Field, PrimeField, PrimeFieldRepr};
use pairing::{bn256::{Bn256, Fr, FrRepr},Engine};
use sapling_crypto::{
    babyjubjub::{
        JubjubBn256,
    },
};
/// The type of values stored in a `MerkleTree` must implement
/// this trait, in order for them to be able to be fed
/// to a Ring `Context` when computing the hash of a leaf.
///
/// A default instance for types that already implements
/// `AsRef<[u8]>` is provided.
///
/// ## Example
///
/// Here is an example of how to implement `Hashable` for a type
/// that does not (or cannot) implement `AsRef<[u8]>`:
///
/// ```ignore
/// impl Hashable for PublicKey {
///     fn update_context(&self, context: &mut Context) {
///         let bytes: Vec<u8> = self.to_bytes();
///         context.update(&bytes);
///     }
/// }
/// ```
pub trait Hashable {
   
    // fn update_context(&self, context: &mut Context);
    fn get_val(&self) -> &[u8];
}
//&str 实现过 asRef<[u8]>  给 凡是实现过 asRef<[u8]> 的type 实现Hashable
impl<T: AsRef<[u8]>> Hashable for T {
    // fn update_context(&self, context: &mut Context) {
    //     context.update(self.as_ref());
    // }
    fn get_val(&self)-> &[u8] {
        self.as_ref()
    }

}

/// The sole purpose of this trait is to extend the standard
/// `ring::algo::Algorithm` type with a couple utility functions.
pub trait HashUtils {
    /// Compute the hash of the empty string
    fn hash_empty(&'static self) -> Digest;

    /// Compute the hash of the given leaf
    fn hash_leaf<T>(&'static self, bytes: &T) -> Digest
    where
        T: Hashable;

    /// Compute the hash of the concatenation of `left` and `right`.
    // XXX: This is overly generic temporarily to make refactoring easier.
    // TODO: Give `left` and `right` type &Digest.
    fn hash_nodes<T>(&'static self,height: isize, left: &T, right: &T) -> Digest
    where
        T: Hashable;

}

impl HashUtils for Algorithm {
    fn hash_empty(&'static self) -> Digest {
        // digest(self, &[])
        Digest{
            value:vec![],
            algorithm:&Algorithm{}
        }
    }

    fn hash_leaf<T>(&'static self, leaf: &T) -> Digest
    where
        T: Hashable,
    {
        // let mut ctx = Context::new(self);
        // ctx.update(&[0x00]);
        // leaf.update_context(&mut ctx);
        // ctx.finish()
        //可以执行补齐操作 或者 sha2 一次
        Digest{
            value:leaf.get_val().to_vec(),
            algorithm:self
        }
    }

    fn hash_nodes<T>(&'static self,height: isize, left: &T, right: &T) -> Digest
    where
        T: Hashable,
    {
        // let mut ctx = Context::new(self);
        // ctx.update(&[0x01]);
        // left.update_context(&mut ctx);
        // right.update_context(&mut ctx);
        // ctx.finish()
        let params = &JubjubBn256::new();
        //Fr -> bit iterator 
        let mut lhs_bool: Vec<bool> = BitIterator::new(left.get_val()).collect();
        let mut rhs_bool: Vec<bool> = BitIterator::new(right.get_val()).collect();
        lhs_bool.reverse();
        rhs_bool.reverse();
        let personalization = sapling_crypto::baby_pedersen_hash::Personalization::MerkleTree(height as usize);
        let hash = sapling_crypto::baby_pedersen_hash::pedersen_hash::<Bn256, _>(
            personalization,
            lhs_bool.clone().into_iter()
            .take(Fr::NUM_BITS as usize)
            .chain(rhs_bool.clone().into_iter().take(Fr::NUM_BITS as usize)),
            params
        ).into_xy().0;
    
        Digest{
            value:fr_to_vecu8(hash),
            algorithm:&Algorithm{}
        }
    }
    
}
fn fr_to_vecu8(fr: Fr) -> Vec<u8> {
    let mut buf = vec![];
    fr.into_repr().write_le(&mut buf).unwrap();
    buf
}

pub struct BitIterator<E> {
    t: E,
    n: usize,
}

impl<E: AsRef<[u8]>> BitIterator<E> {
    pub fn new(t: E) -> Self {
        let n = t.as_ref().len() * 8;
        BitIterator {t,n}
    }
}

impl<E: AsRef<[u8]>> Iterator for BitIterator<E> {
    type Item = bool;

    fn next(&mut self) -> Option<bool> {
        if self.n == 0 {
            None
        } else {
            self.n -= 1;
            let part = self.n / 8;
            let bit = self.n - (8 * part);

            Some(self.t.as_ref()[part] & (1 << bit) > 0)
        }
    }
}
