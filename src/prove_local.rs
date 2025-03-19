use anyhow::Result;
use log::{info, LevelFilter};
use plonky2::field::types::{Field, PrimeField64};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

use ntt::params::N;

use crate::vtfhe::crypto::ggsw::Ggsw;
use crate::vtfhe::crypto::glwe::Glwe;
use crate::vtfhe::ivc_based_vpbs::{verified_pbs};

use std::fs;
use crate::vtfhe::crypto::poly::Poly;
use plonky2::util::serialization::DefaultGateSerializer;
use crate::vtfhe::crypto::glev::Glev;

mod ntt;
mod vec_arithmetic;
mod vtfhe;

fn main() -> Result<()> {
    // optimized parameters, use N=1024 (see ntt/mod.rs)

    // dcecomposition parameters
    const LOGB: usize = 5;
    const ELL: usize = 4;

    const K: usize = 2; // GLWE dimension (K = k + 1)
    const n: usize = 728; // LWE dimension

    // plonky2 parameters
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    simple_logging::log_to_stderr(LevelFilter::Debug);

    // Load the proof inputs from the JSON file
    let bootstrap_inputs_str = fs::read_to_string("bootstrap_inputs.json")?;
    let bootstrap_inputs: serde_json::Value = serde_json::from_str(&bootstrap_inputs_str)?;

    // Input: ct
    let ct_u64 = bootstrap_inputs["ct"].as_array().unwrap();
    let ct: Vec<F> = ct_u64.iter().map(|x| F::from_canonical_u64(x.as_u64().unwrap())).collect();

    // Input: testv
    let testv_coeffs : Vec<u64> = bootstrap_inputs["testv"].as_array().unwrap().iter().map(|x| x.as_u64().unwrap()).collect();
    let testv: Poly<F, D, N> = Poly { coeffs: testv_coeffs.iter().map(|x| F::from_canonical_u64(*x)).collect::<Vec<F>>().try_into().unwrap() };

    // Input: bsk
    let bsk_ser = bootstrap_inputs["bsk"].as_array().unwrap();
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
    let ksk_ser = bootstrap_inputs["ksk"].as_array().unwrap();
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

    // prove a PBS
    let (out_ct, proof, cd) =
        verified_pbs::<F, C, D, n, N, K, ELL, LOGB>(&ct, &testv, &bsk, &ksk, None, None, None);

    // Turn the proof and outputs into serializable JSON objects
    let proof_json = serde_json::to_string(&proof)?;
    fs::write("bootstrap_proof.json", proof_json)?;

    let out_ct_polys : &[Poly<F, D, N>; K] = &out_ct.polys;
    let out_ct_coeffs : Vec<Vec<u64>> = out_ct_polys.iter().map(|poly| poly.coeffs.iter().map(|x| x.to_canonical_u64()).collect::<Vec<u64>>()).collect();

    // cd is of type CircuitData<F, C, D>
    // Get the corresponding VerifierCircuitData because prover_only object is huge
    let verifier_cd_bytes = cd.verifier_data().to_bytes(&DefaultGateSerializer).unwrap();

    // Write the final constructed proof to a JSON file
    let json_bootstrap_outputs = serde_json::json!({
        "out_ct"       : &out_ct_coeffs,
        "cd"           : &verifier_cd_bytes,
    });
    let json_bootstrap_outputs_str = serde_json::to_string(&json_bootstrap_outputs)?;
    fs::write("bootstrap_outputs.json", json_bootstrap_outputs_str)?;

    info!("outputs written to bootstrap_outputs.json; proof written to bootstrap_proof.json");
    Ok(())
}
