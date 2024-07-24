use super::silly::MySillyCircuit;
use ark_marlin::{ahp::prover::*, *};
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::marlin_pc::MarlinKZG10;
use ark_std::{end_timer, start_timer, test_rng};
use blake2::Blake2s;
use mpc_algebra::honest_but_curious::*;
use mpc_algebra::Reveal;

use light_poseidon::{Poseidon, PoseidonBytesHasher, parameters::bn254_x5};
// use ark_bn254::Fr;

use ark_ff::{BigInteger, PrimeField};

use light_poseidon::PoseidonParameters;


// fn generate_hash() -> PoseidonParameters<ark_bn254::Fr> {
//     // Deterministyczne wartości dla MDS matrix
//     let mds = vec![
//         vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)],
//         vec![Fr::from(4u64), Fr::from(5u64), Fr::from(6u64)],
//         vec![Fr::from(7u64), Fr::from(8u64), Fr::from(9u64)],
//     ];

//     // Deterministyczne wartości dla ark matrix
//     let ark = vec![
//         Fr::from(10u64), Fr::from(11u64), Fr::from(12u64), Fr::from(13u64),
//         Fr::from(14u64), Fr::from(15u64), Fr::from(16u64), Fr::from(17u64),
//         Fr::from(18u64), Fr::from(19u64), Fr::from(20u64), Fr::from(21u64),
//         Fr::from(22u64), Fr::from(23u64), Fr::from(24u64), Fr::from(25u64),
//         Fr::from(26u64), Fr::from(27u64), Fr::from(28u64), Fr::from(29u64),
//         Fr::from(30u64), Fr::from(31u64), Fr::from(32u64), Fr::from(33u64),
//         Fr::from(34u64), Fr::from(35u64), Fr::from(36u64), Fr::from(37u64),
//         Fr::from(38u64), Fr::from(39u64), Fr::from(40u64), Fr::from(41u64),
//         Fr::from(42u64), Fr::from(43u64), Fr::from(44u64), Fr::from(45u64),
//         Fr::from(46u64), Fr::from(47u64), Fr::from(48u64), Fr::from(49u64),
//         Fr::from(50u64), Fr::from(51u64), Fr::from(52u64), Fr::from(53u64),
//         Fr::from(54u64), Fr::from(55u64), Fr::from(56u64), Fr::from(57u64),
//         Fr::from(58u64), Fr::from(59u64), Fr::from(60u64), Fr::from(61u64),
//         Fr::from(62u64), Fr::from(63u64), Fr::from(64u64), Fr::from(65u64),
//         Fr::from(66u64), Fr::from(67u64), Fr::from(68u64), Fr::from(69u64),
//         Fr::from(70u64), Fr::from(71u64), Fr::from(72u64), Fr::from(73u64),
//         Fr::from(74u64), Fr::from(75u64), Fr::from(76u64), Fr::from(77u64),
//         Fr::from(78u64), Fr::from(79u64), Fr::from(80u64), Fr::from(81u64),
//         Fr::from(82u64), Fr::from(83u64), Fr::from(84u64), Fr::from(85u64),
//         Fr::from(86u64), Fr::from(87u64), Fr::from(88u64), Fr::from(89u64),
//         Fr::from(90u64), Fr::from(91u64), Fr::from(92u64), Fr::from(93u64),
//         Fr::from(94u64), Fr::from(95u64), Fr::from(96u64), Fr::from(97u64),
//         Fr::from(98u64), Fr::from(99u64), Fr::from(100u64),
//     ];


// // Parametry dla funkcji PoseidonParameters::new
//     let full_rounds = 8;
//     let partial_rounds = 24; 
//     let width = 2; 
//     let alpha = 31; 

//     PoseidonParameters::<Fr> {
//         ark,
//         mds,
//         full_rounds,
//         partial_rounds,
//         width,
//         alpha,
//     }   
// }

fn prover_message_publicize(
    p: ProverMsg<MpcField<ark_bls12_377::Fr>>,
) -> ProverMsg<ark_bls12_377::Fr> {
    match p {
        ProverMsg::EmptyMessage => ProverMsg::EmptyMessage,
        ProverMsg::FieldElements(d) => {
            ProverMsg::FieldElements(d.into_iter().map(|e| e.reveal()).collect())
        }
    }
}

fn comm_publicize(
    pf: ark_poly_commit::marlin_pc::Commitment<ME>,
) -> ark_poly_commit::marlin_pc::Commitment<E> {
    ark_poly_commit::marlin_pc::Commitment {
        comm: commit_from_mpc(pf.comm),
        shifted_comm: pf.shifted_comm.map(commit_from_mpc),
    }
}

fn commit_from_mpc<'a>(
    p: ark_poly_commit::kzg10::Commitment<MpcPairingEngine<ark_bls12_377::Bls12_377>>,
) -> ark_poly_commit::kzg10::Commitment<ark_bls12_377::Bls12_377> {
    ark_poly_commit::kzg10::Commitment(p.0.reveal())
}
fn pf_from_mpc<'a>(
    pf: ark_poly_commit::kzg10::Proof<MpcPairingEngine<ark_bls12_377::Bls12_377>>,
) -> ark_poly_commit::kzg10::Proof<ark_bls12_377::Bls12_377> {
    ark_poly_commit::kzg10::Proof {
        w: pf.w.reveal(),
        random_v: pf.random_v.map(MpcField::reveal),
    }
}

fn batch_pf_publicize(
    pf: ark_poly_commit::BatchLCProof<MFr, DensePolynomial<MFr>, MpcMarlinKZG10>,
) -> ark_poly_commit::BatchLCProof<Fr, DensePolynomial<Fr>, LocalMarlinKZG10> {
    ark_poly_commit::BatchLCProof {
        proof: pf.proof.into_iter().map(pf_from_mpc).collect(),
        evals: pf
            .evals
            .map(|e| e.into_iter().map(MpcField::reveal).collect()),
    }
}

pub fn pf_publicize(
    k: Proof<MpcField<ark_bls12_377::Fr>, MpcMarlinKZG10>,
) -> Proof<ark_bls12_377::Fr, LocalMarlinKZG10> {
    let pf_timer = start_timer!(|| "publicize proof");
    let r = Proof::<ark_bls12_377::Fr, LocalMarlinKZG10> {
        commitments: k
            .commitments
            .into_iter()
            .map(|cs| cs.into_iter().map(comm_publicize).collect())
            .collect(),
        evaluations: k.evaluations.into_iter().map(|e| e.reveal()).collect(),
        prover_messages: k
            .prover_messages
            .into_iter()
            .map(prover_message_publicize)
            .collect(),
        pc_proof: batch_pf_publicize(k.pc_proof),
    };
    end_timer!(pf_timer);
    r
}

type Fr = ark_bls12_377::Fr;
type E = ark_bls12_377::Bls12_377;
type ME = MpcPairingEngine<ark_bls12_377::Bls12_377>;
type MFr = MpcField<Fr>;
type MpcMarlinKZG10 = MarlinKZG10<ME, DensePolynomial<MFr>>;
type LocalMarlinKZG10 = MarlinKZG10<E, DensePolynomial<Fr>>;
type LocalMarlin = Marlin<Fr, LocalMarlinKZG10, Blake2s>;
type MpcMarlin = Marlin<MFr, MpcMarlinKZG10, Blake2s>;

pub fn mpc_test_prove_and_verify(n_iters: usize) {
    let rng = &mut test_rng();

    let srs = LocalMarlin::universal_setup(100, 50, 100, rng).unwrap();
    let empty_circuit: MySillyCircuit<Fr> = MySillyCircuit { a: None, b: None, c: None };
    let (index_pk, index_vk) = LocalMarlin::index(&srs, empty_circuit.clone()).unwrap();
    let mpc_index_pk = IndexProverKey::from_public(index_pk);

    for _ in 0..n_iters {
        let a = MpcField::<ark_bls12_377::Fr>::from(2u8);
        let b = MpcField::<ark_bls12_377::Fr>::from(2u8);
        let mut c = a;
        c *= &b;
        // let params = generate_hash();

        // let mut poseidon = Poseidon::<Fr>::new_circom(params.width).unwrap();
        // let hash = poseidon.hash_bytes_be(&[&[1u8; 32], &[2u8; 32]]).unwrap();
        // let mut c = a;
        // c *= &b;

        let circ = MySillyCircuit {
            a: Some(a),
            b: Some(b),
            c: Some(c),
        };
        // let mut c = a;
        // c *= &b;
        let inputs = vec![c.reveal()];
        println!("{}\n{}\n{}", a, b, c);
        let mpc_proof = MpcMarlin::prove(&mpc_index_pk, circ, rng).unwrap();
        let proof = pf_publicize(mpc_proof);
        let public_a = a.reveal();
        let is_valid = LocalMarlin::verify(&index_vk, &inputs, &proof, rng).unwrap();
        assert!(is_valid);
        let is_valid = LocalMarlin::verify(&index_vk, &[public_a], &proof, rng).unwrap();
        assert!(!is_valid);
    }
}
