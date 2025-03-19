use anyhow::Result;
use log::{info, LevelFilter};
use plonky2::field::types::{Field};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

use ntt::params::N;

use crate::vtfhe::crypto::ggsw::Ggsw;
use crate::vtfhe::crypto::glwe::Glwe;
use crate::vtfhe::ivc_based_vpbs::{verify_pbs};

use std::fs;
use std::fs::File;
use std::io::Read;
use serde_json::Value;
use crate::vtfhe::crypto::poly::Poly;
use crate::vtfhe::crypto::glev::Glev;
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::plonk::circuit_data::VerifierCircuitData;
use plonky2::plonk::circuit_data::VerifierOnlyCircuitData;
use plonky2::util::serialization::DefaultGateSerializer;
use plonky2::plonk::circuit_data::CommonCircuitData;
use base64::{engine::general_purpose, Engine as _};
use serde::Deserialize;

mod ntt;
mod vec_arithmetic;
mod vtfhe;

#[derive(Deserialize, Debug)]
pub struct JsonProofData {
    pub proof: String,
    pub common: String,
    pub verifier_data: String,
}

fn main() -> Result<()> {
    // optimized parameters, use N=1024 (see ntt/mod.rs)

    // dcecomposition parameters
    const LOGB: usize = 5;
    const ELL: usize = 4;

    const K: usize = 2; // GLWE dimension (K = k + 1)
    const n: usize = 728; // LWE dimension
    const p: usize = 2; // plaintext modulus

    // plonky2 parameters
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    simple_logging::log_to_stderr(LevelFilter::Debug);

    // Read in the bootstrap inputs from the JSON file
    if !fs::metadata("bootstrap_inputs.json").is_ok() {
        panic!("bootstrap_inputs.json file not found");
    }
    let input_data_str = fs::read_to_string("bootstrap_inputs.json")?;
    let input_data: serde_json::Value = serde_json::from_str(&input_data_str)?;

    // Input: ct
    let ct_u64 = input_data["ct"].as_array().unwrap();
    let ct: Vec<F> = ct_u64.iter().map(|x| F::from_canonical_u64(x.as_u64().unwrap())).collect();

    // Input: bsk
    let bsk_ser = input_data["bsk"].as_array().unwrap();
    let bsk: Vec<Ggsw<F, D, N, K, ELL>> = bsk_ser
        .iter()
        .map(
            |ggsw| 
                Ggsw {
                    glevs: ggsw.as_array().unwrap().iter().map(
                        |glev| 
                            Glev {
                                glwes: glev.as_array().unwrap().iter().map(
                                    |glwe| 
                                        Glwe {
                                            polys: glwe.as_array().unwrap().iter().map(
                                                |poly| 
                                                    Poly {
                                                        coeffs: poly.as_array().unwrap().iter().map(|x| F::from_canonical_u64(x.as_u64().unwrap())).collect::<Vec<F>>().try_into().unwrap()
                                                    }
                                            ).collect::<Vec<Poly<F, D, N>>>().try_into().unwrap()
                                        }
                                ).collect::<Vec<Glwe<F, D, N, K>>>().try_into().unwrap()
                            }
                    ).collect::<Vec<Glev<F, D, N, K, ELL>>>().try_into().unwrap()
                }
        )
        .collect();

    // Input: ksk
    let ksk_ser = input_data["ksk"].as_array().unwrap();
    let ksk: Ggsw<F, D, N, K, ELL> = Ggsw {
        glevs: ksk_ser.iter().map(
            |glev| 
                Glev {
                    glwes: glev.as_array().unwrap().iter().map(
                        |glwe| 
                            Glwe {
                                polys: glwe.as_array().unwrap().iter().map(
                                    |poly| 
                                        Poly {
                                            coeffs: poly.as_array().unwrap().iter().map(|x| F::from_canonical_u64(x.as_u64().unwrap())).collect::<Vec<F>>().try_into().unwrap()
                                        }
                                ).collect::<Vec<Poly<F, D, N>>>().try_into().unwrap()
                            }
                    ).collect::<Vec<Glwe<F, D, N, K>>>().try_into().unwrap()
                }
        ).collect::<Vec<Glev<F, D, N, K, ELL>>>().try_into().unwrap()
    };

    // Input: testv
    let testv_coeffs : Vec<u64> = input_data["testv"].as_array().unwrap().iter().map(|x| x.as_u64().unwrap()).collect();
    let testv: Poly<F, D, N> = Poly { coeffs: testv_coeffs.iter().map(|x| F::from_canonical_u64(*x)).collect::<Vec<F>>().try_into().unwrap() };

    // Read in the bootstrap outputs from the JSON file
    if !fs::metadata("bootstrap_outputs.json").is_ok() {
        panic!("bootstrap_outputs.json file not found");
    }
    let output_data_str = fs::read_to_string("bootstrap_outputs.json")?;
    let output_data: serde_json::Value = serde_json::from_str(&output_data_str)?;

    // Output: out_ct
    let out_ct_coeffs_vec : Vec<Vec<u64>> = output_data["out_ct"].as_array().unwrap().iter().map(|x| x.as_array().unwrap().iter().map(|y| y.as_u64().unwrap()).collect()).collect();
    let out_ct_polys: [Poly<F, D, N>; K] = out_ct_coeffs_vec
        .iter()
        .map(|poly|
            Poly {
                // The coeffs member should be of type: [F; N]
                coeffs: poly.iter().map(|x| F::from_canonical_u64(*x)).collect::<Vec<F>>().try_into().unwrap()
            }
        )
        .collect::<Vec<Poly<F, D, N>>>()
        .try_into()
        .unwrap();
    let out_ct: Glwe<F, D, N, K> = Glwe { polys: out_ct_polys };

    // Output: cd - circuit data
    let verifier_cd_bytes : Vec<u8> = output_data["cd"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_u64().unwrap() as u8)
        .collect();

    let vcd : VerifierCircuitData<F, C, D> = VerifierCircuitData::from_bytes(
        verifier_cd_bytes,
        &DefaultGateSerializer,
    ).unwrap();

    // If there is a bootstrap_proof.json file, then we will verify the proof
    if fs::metadata("bootstrap_proof.json").is_ok() {
        info!("Starting verification of [bootstrap_proof.json]");
        // Read in the proof from the JSON file
        let proof_str = fs::read_to_string("bootstrap_proof.json")?;
        let proof: ProofWithPublicInputs<F, C, D> = serde_json::from_str(&proof_str)?;

        // verify the PBS
        verify_pbs::<F, C, D, n, N, K, ELL, LOGB>(&out_ct, &ct, &testv, &bsk, &ksk, &proof, &vcd);
        info!("verification successful!");
    }

    // If there is a sindri_proof.json file, then we will verify the proof
    if fs::metadata("sindri_proof.json").is_ok() {
        info!("Verifying proof from file: [sindri_proof.json]");
        let mut file = File::open("sindri_proof.json").unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();
        let proof_details : Value = serde_json::from_str(&contents).unwrap();
        let proof_object = proof_details.as_object().expect("sindri_proof.json should contain valid proof data");
    
        let proof_data: JsonProofData = if proof_object.contains_key("proof") {
            serde_json::from_value(proof_details["proof"].clone()).unwrap()
        } else {
            serde_json::from_value(proof_details.clone()).unwrap()
        };
    
        let proof_bytes = general_purpose::STANDARD.decode(proof_data.proof).unwrap();
        let common_bytes = general_purpose::STANDARD.decode(proof_data.common).unwrap();
        let verifier_only_bytes = general_purpose::STANDARD
            .decode(proof_data.verifier_data)
            .unwrap();
    
        let default_gate_serializer = DefaultGateSerializer;
    
        let common =
            CommonCircuitData::<F, D>::from_bytes(common_bytes, &default_gate_serializer).unwrap();
        let proof = ProofWithPublicInputs::<F, C, D>::from_bytes(proof_bytes, &common).unwrap();
        let verifier_data = VerifierOnlyCircuitData::<C, D>::from_bytes(verifier_only_bytes).unwrap();
    
        let verifier: VerifierCircuitData<F, C, D> = VerifierCircuitData {
            verifier_only: verifier_data,
            common: common,
        };

        // verify the PBS
        verify_pbs::<F, C, D, n, N, K, ELL, LOGB>(&out_ct, &ct, &testv, &bsk, &ksk, &proof, &verifier);
        info!("verification successful!");
    }
    Ok(())
}
