use anyhow::Result;
use log::{info, LevelFilter};
use plonky2::field::types::{Field, PrimeField64};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

use ntt::params::N;

use crate::vtfhe::crypto::glwe::Glwe;
use crate::vtfhe::crypto::lwe::{get_delta};

use std::fs;
use crate::vtfhe::crypto::poly::Poly;

mod ntt;
mod vec_arithmetic;
mod vtfhe;

fn main() -> Result<()> {
    // optimized parameters, use N=1024 (see ntt/mod.rs)

    // dcecomposition parameters
    const K: usize = 2; // GLWE dimension (K = k + 1)
    const p: usize = 2; // plaintext modulus
    
    // plonky2 parameters
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    simple_logging::log_to_stderr(LevelFilter::Debug);

    let delta = get_delta::<F, D>(2 * p);

    // Read in the output ciphertext from the JSON file
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

    // Read the secret key s_to (Vec<Poly<F, D, N>>) and message m (F) from the JSON file
    let secrets : serde_json::Value = serde_json::from_str(&fs::read_to_string("secrets.json")?)?;

    // Secret: s_to (key)
    let s_to_coeffs_vec : Vec<Vec<u64>> = secrets["s_to"].as_array().unwrap().iter().map(|x| x.as_array().unwrap().iter().map(|y| y.as_u64().unwrap()).collect()).collect();
    let s_to_polys: [Poly<F, D, N>; K] = s_to_coeffs_vec
        .iter()
        .map(|poly|
            Poly {
                coeffs: poly.iter().map(|x| F::from_canonical_u64(*x)).collect::<Vec<F>>().try_into().unwrap()
            }
        )
        .collect::<Vec<Poly<F, D, N>>>()
        .try_into()
        .unwrap();
    let s_to: Vec<Poly<F, D, N>> = s_to_polys.to_vec();

    // Secret: m (plaintext)
    let m = F::from_canonical_u64(secrets["m"].as_u64().unwrap());

    let dec_out_ct_coeffs = out_ct.decrypt(&s_to).coeffs;
    let dec_out_ct = F::from_canonical_usize(
        ((dec_out_ct_coeffs[0].to_canonical_u64() as f64) / (delta.to_canonical_u64() as f64)).round() as usize
            % (2 * p),
    );

    info!("plaintext: {m} dec(output_ciphertext): {dec_out_ct}");
    Ok(())
}
