use super::silly::MySillyCircuit;
use ark_ec::PairingEngine;
use ark_groth16::{generate_random_parameters, prepare_verifying_key, verify_proof, ProvingKey};
use ark_std::{test_rng, UniformRand};
use mpc_algebra::*;
use mpc_algebra::Reveal;

use light_poseidon::{Poseidon, PoseidonBytesHasher, parameters::bn254_x5};
use ark_bn254::Fr;

use ark_ff::{BigInteger, PrimeField, Field};

use light_poseidon::PoseidonParameters;

pub mod prover;
pub mod r1cs_to_qap;

pub fn mpc_test_prove_and_verify<E: PairingEngine, S: PairingShare<E>>(n_iters: usize) {
    let rng = &mut test_rng();

    let params =
        generate_random_parameters::<E, _, _>(MySillyCircuit { a: None, b: None, c: None}, rng).unwrap();

    let pvk = prepare_verifying_key::<E>(&params.vk);
    let mpc_params = ProvingKey::from_public(params);

    for _ in 0..n_iters {
        let a = MpcField::<E::Fr, S::FrShare>::rand(rng);
        let b = MpcField::<E::Fr, S::FrShare>::rand(rng);

        let params = generate_hash();

        let mut poseidon = Poseidon::<Fr>::new_circom(params.width).unwrap();
        let hash = poseidon.hash_bytes_be(&[&[1u8; 32], &[2u8; 32]]).unwrap();
        let hash_bytes = hash.to_vec(); // Convert to Vec<u8> if needed

        let field_element = E::Fr::from_random_bytes(&hash_bytes).expect("Failed to convert bytes to field element");
        let mut c = MpcField::<E::Fr, S::FrShare>::new(field_element, true);

        let mpc_proof = prover::create_random_proof::<MpcPairingEngine<E, S>, _, _>(
            MySillyCircuit {
                a: Some(a),
                b: Some(b),
                c: Some(c),
            },
            &mpc_params,
            rng,
        )
        .unwrap();
        let proof = mpc_proof.reveal();
        let pub_a = a.reveal();
        let pub_c = c.reveal();

        assert!(verify_proof(&pvk, &proof, &[pub_c]).unwrap());
        assert!(!verify_proof(&pvk, &proof, &[pub_a]).unwrap());
    }
}



fn generate_hash() -> PoseidonParameters<Fr> {
    // Deterministyczne wartości dla MDS matrix
    let mds = vec![
        vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)],
        vec![Fr::from(4u64), Fr::from(5u64), Fr::from(6u64)],
        vec![Fr::from(7u64), Fr::from(8u64), Fr::from(9u64)],
    ];

    // Deterministyczne wartości dla ark matrix
    let ark = vec![
        Fr::from(10u64), Fr::from(11u64), Fr::from(12u64), Fr::from(13u64),
        Fr::from(14u64), Fr::from(15u64), Fr::from(16u64), Fr::from(17u64),
        Fr::from(18u64), Fr::from(19u64), Fr::from(20u64), Fr::from(21u64),
        Fr::from(22u64), Fr::from(23u64), Fr::from(24u64), Fr::from(25u64),
        Fr::from(26u64), Fr::from(27u64), Fr::from(28u64), Fr::from(29u64),
        Fr::from(30u64), Fr::from(31u64), Fr::from(32u64), Fr::from(33u64),
        Fr::from(34u64), Fr::from(35u64), Fr::from(36u64), Fr::from(37u64),
        Fr::from(38u64), Fr::from(39u64), Fr::from(40u64), Fr::from(41u64),
        Fr::from(42u64), Fr::from(43u64), Fr::from(44u64), Fr::from(45u64),
        Fr::from(46u64), Fr::from(47u64), Fr::from(48u64), Fr::from(49u64),
        Fr::from(50u64), Fr::from(51u64), Fr::from(52u64), Fr::from(53u64),
        Fr::from(54u64), Fr::from(55u64), Fr::from(56u64), Fr::from(57u64),
        Fr::from(58u64), Fr::from(59u64), Fr::from(60u64), Fr::from(61u64),
        Fr::from(62u64), Fr::from(63u64), Fr::from(64u64), Fr::from(65u64),
        Fr::from(66u64), Fr::from(67u64), Fr::from(68u64), Fr::from(69u64),
        Fr::from(70u64), Fr::from(71u64), Fr::from(72u64), Fr::from(73u64),
        Fr::from(74u64), Fr::from(75u64), Fr::from(76u64), Fr::from(77u64),
        Fr::from(78u64), Fr::from(79u64), Fr::from(80u64), Fr::from(81u64),
        Fr::from(82u64), Fr::from(83u64), Fr::from(84u64), Fr::from(85u64),
        Fr::from(86u64), Fr::from(87u64), Fr::from(88u64), Fr::from(89u64),
        Fr::from(90u64), Fr::from(91u64), Fr::from(92u64), Fr::from(93u64),
        Fr::from(94u64), Fr::from(95u64), Fr::from(96u64), Fr::from(97u64),
        Fr::from(98u64), Fr::from(99u64), Fr::from(100u64),
    ];


// Parametry dla funkcji PoseidonParameters::new
    let full_rounds = 8;
    let partial_rounds = 24; 
    let width = 2; 
    let alpha = 31; 

    PoseidonParameters::<Fr> {
        ark,
        mds,
        full_rounds,
        partial_rounds,
        width,
        alpha,
    }   
}