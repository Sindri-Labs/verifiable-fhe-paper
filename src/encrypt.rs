use anyhow::Result;
use log::{info, LevelFilter};
use plonky2::field::types::{Field, PrimeField64};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use rand::random;

use ntt::params::N;

use crate::vtfhe::crypto::ggsw::Ggsw;
use crate::vtfhe::crypto::glwe::Glwe;
use crate::vtfhe::crypto::lwe::{encrypt, get_delta};
use crate::vtfhe::crypto::{compute_bsk, get_testv};

use std::fs;
use crate::vtfhe::crypto::poly::Poly;

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
    const p: usize = 2; // plaintext modulus
    let sigma_glwe = 4.99027217501041e-8; // GLWE noise
    let sigma_lwe = 0.0000117021618159313; // LWE noise

    // plonky2 parameters
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    simple_logging::log_to_stderr(LevelFilter::Debug);

    // partial GLWE key corresponding to LWE key
    let s_to = Glwe::<F, D, N, K>::partial_key(n);
    let s_lwe = Glwe::<F, D, N, K>::flatten_partial_key(&s_to, n);
    info!("s_lwe: {:?}", s_lwe);

    let s_glwe = Glwe::<F, D, N, K>::key_gen();
    let bsk = compute_bsk::<F, D, N, K, ELL, LOGB>(&s_lwe, &s_glwe, sigma_glwe);
    let ksk = Ggsw::<F, D, N, K, ELL>::compute_ksk::<LOGB>(&s_to, &s_glwe, sigma_lwe);

    let delta = get_delta::<F, D>(2 * p);
    let testv : Poly<F, D, N> = get_testv(p, delta);
    let m = F::from_canonical_usize(random::<usize>() % p);
    let ct : Vec<F> = encrypt::<F, D, n>(&s_lwe, &(delta * m), sigma_lwe);

    // Write the secret values m and s_to to a JSON file
    // s_to is of type Vec<Poly<F, D, N>>
    let json_secret_values = serde_json::json!({
        "m" : m.to_canonical_u64(),
        "s_to" : s_to.iter().map(|poly| poly.coeffs.iter().map(|x| x.to_canonical_u64()).collect::<Vec<u64>>()).collect::<Vec<Vec<u64>>>()
    });
    let json_secret_values_str = serde_json::to_string(&json_secret_values)?;
    fs::write("secrets.json", json_secret_values_str)?;
    info!("secret values written to secrets.json");

    // Turn the proof inputs into serializable JSON objects
    let ct_u64 = ct.iter().map(|x| x.to_canonical_u64()).collect::<Vec<u64>>();
    let testv_coeffs : Vec<u64> = testv.coeffs.iter().map(|x| x.to_canonical_u64()).collect::<Vec<u64>>();

    // bsk is of type [Ggsw<F, D, N, K, ELL>].
    // Each Ggsw contains the member glevs of type [Glev<F, D, N, K, ELL>; K]
    // Each Glev contains the member glwes of type [Glwe<F, D, N, K>; ELL]
    // Each Glwe contains the member polys of type [Poly<F, D, N>; K] just like out_ct
    let bsk_ser  = bsk
        .iter()
        .map(
            |ggsw|
                ggsw.glevs.iter()
                .map(|glev|
                    glev.glwes.iter()
                    .map(|glwe|
                        glwe.polys.iter()
                        .map(|poly|
                            poly.coeffs.iter()
                            .map(|x| x.to_canonical_u64())
                            .collect::<Vec<u64>>()
                        )
                        .collect::<Vec<Vec<u64>>>()
                    )
                    .collect::<Vec<Vec<Vec<u64>>>>()
                )
                .collect::<Vec<Vec<Vec<Vec<u64>>>>>()
        )
        .collect::<Vec<Vec<Vec<Vec<Vec<u64>>>>>>();

    // ksk is of type Ggsw<F, D, N, K, ELL>
    let ksk_ser = ksk.glevs.iter()
        .map(|glev|
            glev.glwes.iter()
            .map(|glwe|
                glwe.polys.iter()
                .map(|poly|
                    poly.coeffs.iter()
                    .map(|x| x.to_canonical_u64())
                    .collect::<Vec<u64>>()
                )
                .collect::<Vec<Vec<u64>>>()
            )
            .collect::<Vec<Vec<Vec<u64>>>>()
        )
        .collect::<Vec<Vec<Vec<Vec<u64>>>>>();

    // Write the proof inputs to a JSON file
    let json_bootstrap_inputs = serde_json::json!({
        "ct"           : &ct_u64,
        "testv"        : &testv_coeffs,
        "bsk"          : &bsk_ser,
        "ksk"          : &ksk_ser,
    });
    let json_bootstrap_inputs_str = serde_json::to_string(&json_bootstrap_inputs)?;
    fs::write("bootstrap_inputs.json", json_bootstrap_inputs_str)?;

    info!("inputs written to bootstrap_inputs.json");
    Ok(())
}
