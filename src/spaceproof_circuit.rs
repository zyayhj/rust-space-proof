use bellman::{
    Circuit,
    SynthesisError,
    ConstraintSystem,
};

use ff::{Field, PrimeField};
use sapling_crypto::{
    babyjubjub::{
        JubjubEngine,
    },
    circuit::{
        num::{AllocatedNum},
        baby_pedersen_hash,
        boolean::{Boolean, AllocatedBit}
    }
};
use pairing::{bn256::{Bn256, Fr}};

pub struct SpaceProofMerkleTreeCircuit<'a, E: JubjubEngine> {
    ///root hash public 
    
    // merkle tree side info,   public 
    pub position: Option<E::Fr>,
    //key node data, 32 byte   public 
    pub node: Option<E::Fr>,   // determine pospace quality 
    //merkle tree path   private 
    pub proof: Vec<Option<E::Fr>>,
    //
    pub params: &'a E::Params,
}

impl<'a, E: JubjubEngine> Circuit<E> for SpaceProofMerkleTreeCircuit<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs:&mut CS) -> Result<(), SynthesisError> {
        let mut hash = AllocatedNum::alloc(cs.namespace(|| "node"),
            || Ok(match self.node {
                Some(n) => n,
                None => E::Fr::zero(),
            })
        )?;
        //target leaf node 
        hash.inputize(cs.namespace(|| "public input node"))?;
        
        let position = AllocatedNum::alloc(cs.namespace(|| "position"),
            || Ok(match self.position {
                Some(p) => p,
                None => E::Fr::zero(),
            })
        )?;
        position.inputize(cs.namespace(|| "public input position"))?;
        let size_vec = position.into_bits_le_strict(cs.namespace(|| "position into bits"))?;
        for i in 0..self.proof.len() {
            if let Some(ref element) = self.proof[i] {
                let elt = AllocatedNum::alloc(cs.namespace(|| format!("elt {}",i)),
                    || Ok(*element))?;
                let right_side = Boolean::from(AllocatedBit::alloc(
                    cs.namespace(|| format!("position bit {}", i)),
                    size_vec[i].get_value()).unwrap()
                );
                let (xl, xr) = AllocatedNum::conditionally_reverse(cs.namespace(|| format!("conditional reversal of preimage {}", i)),
                    &hash, 
                    &elt,
                    &right_side
                )?;
                let mut preimage = vec![];
                preimage.extend(xl.into_bits_le_strict(cs.namespace(|| format!("xl into bits {}",i)))?);
                preimage.extend(xr.into_bits_le_strict(cs.namespace(|| format!("xr into bits {}",i)))?);

                let personalization = baby_pedersen_hash::Personalization::MerkleTree(i as usize);
                hash = baby_pedersen_hash::pedersen_hash(cs.namespace(||format!("computation of pedersen hash {}", i) ),
                    personalization, 
                    &preimage,
                    self.params
                )?.get_x().clone();
            }
        }
        //root node 
        hash.inputize(cs)?;
        println!("Root hash {:?}", hash.get_value());
        Ok(())
    }
}

