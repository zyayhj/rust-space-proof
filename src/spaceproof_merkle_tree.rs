use std::error::Error;
use rand::{ChaChaRng, SeedableRng};
use bellman::groth16::{Proof, Parameters, verify_proof, create_random_proof, prepare_verifying_key, generate_random_parameters};
use num_bigint::BigInt;
use num_traits::Num;
use bellman::{
    Circuit,
    SynthesisError
    // SynthesisError,
    // ConstraintSystem,
};
// use ff::{Field, PrimeField};
use sapling_crypto::{
    babyjubjub::{
        JubjubEngine,
        JubjubBn256
    },
    circuit::{
        // num::{AllocatedNum},
        // baby_pedersen_hash,
        // boolean::{Boolean, AllocatedBit},
        test::TestConstraintSystem
    }
};
use ff::{Field, PrimeField, PrimeFieldRepr};
use pairing::{bn256::{Bn256, Fr, FrRepr},Engine};

use rand::Rand;
use rand::Rng;
use time::PreciseTime;

use spaceproof_circuit::SpaceProofMerkleTreeCircuit;

use merkle::digest::{Algorithm, Digest};
use merkle::hashutils::{HashUtils, Hashable, BitIterator};
use merkle::merkletree::MerkleTree;
static DIGEST: &Algorithm = &Algorithm{};

#[derive(Serialize)]
pub struct Generate{
    pub params: String
}

#[derive(Serialize)]
pub struct SProof{
    pub proof: String
}

pub fn generate(seed_slice: &[u32], depth: usize) ->  Result<Parameters<Bn256>, SynthesisError> {
    let rng = &mut ChaChaRng::from_seed(seed_slice);
    let j_params = &JubjubBn256::new();
    let mut proof_elts = vec![];
    for _ in 0..depth {
        proof_elts.push(Some(
            pairing::bn256::Fr::zero(),
        ));
    }
     generate_random_parameters::<Bn256, _, _>(
        SpaceProofMerkleTreeCircuit {
            params: j_params,
            position: None,
            node: None,
            proof: proof_elts,
        },
        rng,
    )
}

#[test]
fn test_spaceproof_merkle_circuit() {
    let mut cs = TestConstraintSystem::<Bn256>::new();
    let seed_slice = &[1u32, 1u32, 1u32, 1u32];
    let rng = &mut ChaChaRng::from_seed(seed_slice);
    let start = PreciseTime::now();
    let mut proof_vec = vec![];
    for _ in 0..32 {
        proof_vec.push(
            Some(Fr::rand(rng))
        );
    }

    let j_params = &JubjubBn256::new();
    let sp_circuit = SpaceProofMerkleTreeCircuit {
        params: j_params,
        position: Some(Fr::rand(rng)),
        node: Some(Fr::rand(rng)),
        proof: proof_vec,
    };

    sp_circuit.synthesize(&mut cs).unwrap();
    println!("setup generated in {} s", start.to(PreciseTime::now()).num_milliseconds() as f64 / 1000.0);
    println!("num constraints: {}", cs.num_constraints());
    println!("num inputs: {}", cs.num_inputs());
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Node{
    hash: Fr,
    encoded: Vec<u8>,
}

impl Node{
    fn new(hash : Fr) -> Node{
        let mut buf = vec![];
        hash.into_repr().write_le(&mut buf).unwrap();
        let node = Node {
            hash: hash,
            encoded: buf,
        };
        node
    }

    fn newFromVec(s: Vec<u8>) ->  Result<Node, String> {
        let mut repr = FrRepr::default();
        repr.read_le(&s[..]).map_err(|e| format!("could not read {}", &e))?;
        let fr = Fr::from_repr(repr).map_err(|e| format!("could not convert into prime field: {}", &e))?;
        
        Ok(
            Node::new(fr)
        )
    }
    
    fn newFromStr(s: &str) -> Node {
        Node::new(Fr::from_str(s).unwrap())
    }
}

impl AsRef<[u8]> for Node {
    fn as_ref(&self) -> &[u8] {
        &self.encoded
    }
}

#[test]
fn test_new_from_vec() {
    let n1 = Node::newFromStr("1");
    let n2 = Node::newFromVec(n1.encoded).unwrap();
    println!("{}",n2.hash);
    assert_eq!(n1.hash, n2.hash);
}


#[test]
fn test_fr_isu8() {
    let values = vec![
        Node::newFromStr("1"),
        Node::newFromStr("2"),
        Node::newFromStr("3"),
        Node::newFromStr("4")];

    let tree = MerkleTree::from_vec(DIGEST, values);
    assert_eq!(tree.height(), 2);

}

#[test]
fn test_space_generate_params() {
    let mut start = PreciseTime::now();
    let seed_slice = &[1u32, 1u32, 1u32, 1u32];
    let rng = &mut ChaChaRng::from_seed(seed_slice);
    println!("generating setup..."); 
    let pos_int = 3;//target node position in leafs
    let position = Fr::from_str(&pos_int.to_string());
    // assert_eq
    // let v = position.as_ref();
    // println!("position vec[v8] {}", v.unwrap());
    let mut leaves = vec![];
    for i in 0..16 {
        leaves.push(Node::new(Fr::rand(rng)));
    }
    let node = leaves[pos_int].clone();//target node

    let merkle = MerkleTree::from_vec(DIGEST, leaves);
    println!("merkle tree height: {}, and number of leaf node: {}", merkle.height(), merkle.count());
    println!("merkle tree root: {:?}",merkle.root_hash());
    let root_node = Node::newFromVec(merkle.root_hash().to_vec()).unwrap();
    let root_hex = root_node.hash.to_hex();
    // hex::encode(&v[..]);
    println!("merkle tree root: {}", root_hex);
    //lemma to circuit proof
    let mut fproof :Vec<Option<Fr>> = vec![];
    merkle.gen_proof(node.clone()).map(
        |p|p.get_sibling_vec()
    ).map(
        |proof| 
        for inx in 0..proof.len() {
            if let Some(ref elm) = proof[inx] {
                match Node::newFromVec(elm.to_vec()) {
                    Ok(n) => {
                        fproof.push(Some(n.hash));
                    },
                    Err(e) => {
                        println!("Err: {}", e);
                    }
                }
            }
        }
    );
    assert_eq!(fproof.len(), merkle.height() as usize);
    
    let mut start = PreciseTime::now();
    let params = generate(seed_slice, merkle.height() as usize).unwrap();
    let mut v_params = vec![];
    params.write(&mut v_params).unwrap();
    println!("params length: {} bytes", v_params.len());
    println!("setup generated in {} s", start.to(PreciseTime::now()).num_milliseconds() as f64 / 1000.0);
    
    start = PreciseTime::now();
    let proof = create_random_proof(
        SpaceProofMerkleTreeCircuit {
            params: &JubjubBn256::new(),
            position: position,
            node: Some(node.hash),
            proof: fproof,
        },
        &params,
        rng
    ).unwrap();
    println!("create proof in {} s", start.to(PreciseTime::now()).num_milliseconds() as f64 / 1000.0);

    let mut v = vec![];
    proof.write(&mut v).unwrap();
    let proof_hex = hex::encode(&v[..]);
    println!("zk proof: {}", proof_hex);
    println!("zk proof length: {}", proof_hex.len());

    let pvk = prepare_verifying_key::<Bn256>(&params.vk);

    let root_big = BigInt::from_str_radix(&root_hex, 16).unwrap();
    let root_raw = &root_big.to_str_radix(10);
    let root = Fr::from_str(root_raw).unwrap();
    
    // assert_eq!(root, root_node.hash);

    start = PreciseTime::now();
    let result = verify_proof(
        &pvk,
        &proof,
        &[
            node.hash,
            position.unwrap(),
            root
        ]).unwrap();
    println!("verify in {} ms", start.to(PreciseTime::now()).num_milliseconds() as f64);
    assert!(result);
}