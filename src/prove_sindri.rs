use anyhow::Result;
use log::{info, LevelFilter};
use plonky2::field::types::{Field, PrimeField64};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};


use ntt::params::N;

use crate::vtfhe::crypto::ggsw::Ggsw;
use crate::vtfhe::crypto::glwe::Glwe;
use serde::{Deserialize, Serialize};

use std::fs;
use crate::vtfhe::crypto::poly::Poly;
use plonky2::util::serialization::DefaultGateSerializer;
use crate::vtfhe::crypto::glev::Glev;

mod ntt;
mod vec_arithmetic;
mod vtfhe;

const LOGB: usize = 5;
const ELL: usize = 4;

const K: usize = 2; // GLWE dimension (K = k + 1)
const n: usize = 728; // LWE dimension
const p: usize = 2; // plaintext modulus

// plonky2 parameters
pub const D: usize = 2;
pub type C = PoseidonGoldilocksConfig;
pub type F = <C as GenericConfig<D>>::F;

// These structs are also duplicated in lib.rs:
pub struct InputDataCT {
    pub ct: Vec<F>,
}

impl Serialize for InputDataCT {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.ct.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for InputDataCT {
    fn deserialize<D>(deserializer: D) -> Result<InputDataCT, D::Error>
    where
        D: serde::Deserializer<'de> {
        let ct: Vec<F> = Vec::deserialize(deserializer)?;
        Ok(InputDataCT { ct })
    }
}

pub struct InputDataPoly {
    pub poly: Poly<F, D, N>
}

impl Serialize for InputDataPoly {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.poly.coeffs.to_vec().serialize(serializer)                           
    }
}

impl<'de> Deserialize<'de> for InputDataPoly {
    fn deserialize<D>(deserializer: D) -> Result<InputDataPoly, D::Error>
    where
        D: serde::Deserializer<'de> {
        let poly_coeffs: Vec<F> = Vec::deserialize(deserializer)?;
        let poly = Poly { coeffs: poly_coeffs.try_into().unwrap() };
        Ok(InputDataPoly { poly })
    }
}

pub struct InputDataBSK {
    pub bsk: Vec<Ggsw<F, D, N, K, ELL>>
}

impl Serialize for InputDataBSK {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bsk_ser : Vec<Vec<Vec<Vec<Vec<u64>>>>> = self.bsk
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
        bsk_ser.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for InputDataBSK {
    fn deserialize<DD>(deserializer: DD) -> Result<InputDataBSK, DD::Error>
    where
        DD: serde::Deserializer<'de> {
        let bsk_ser: Vec<Vec<Vec<Vec<Vec<u64>>>>> = Vec::deserialize(deserializer)?;
        let bsk: Vec<Ggsw<F, D, N, K, ELL>> = bsk_ser
            .iter()
            .map(
                |ggsw| 
                    Ggsw {
                        glevs: ggsw.iter().map(
                            |glev| 
                                Glev {
                                    glwes: glev.iter().map(
                                        |glwe| 
                                            Glwe {
                                                polys: glwe.iter().map(
                                                    |poly| 
                                                        Poly {
                                                            coeffs: poly.iter().map(
                                                                |x| F::from_canonical_u64(*x)
                                                            ).collect::<Vec<F>>().try_into().unwrap()
                                                        }
                                                ).collect::<Vec<Poly<F, D, N>>>().try_into().unwrap()
                                            }
                                    ).collect::<Vec<Glwe<F, D, N, K>>>().try_into().unwrap()
                                }
                        ).collect::<Vec<Glev<F, D, N, K, ELL>>>().try_into().unwrap()
                    }
            )
            .collect();

        Ok(InputDataBSK { bsk })
    }
}

pub struct InputDataKSK {
    pub ksk: Ggsw<F, D, N, K, ELL>
}

impl Serialize for InputDataKSK {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let ksk_ser : Vec<Vec<Vec<Vec<u64>>>>
            = self.ksk.glevs.iter()
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
        ksk_ser.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for InputDataKSK {
    fn deserialize<DD>(deserializer: DD) -> Result<InputDataKSK, DD::Error>
    where
        DD: serde::Deserializer<'de> {
        let ksk_ser: Vec<Vec<Vec<Vec<u64>>>>
            = Vec::deserialize(deserializer)?;
        let ksk: Ggsw<F, D, N, K, ELL> = Ggsw {
            glevs: ksk_ser.iter()
            .map(|glev|
                Glev {
                    glwes: glev.iter()
                    .map(|glwe|
                        Glwe {
                            polys: glwe.iter()
                            .map(|poly|
                                Poly {
                                    coeffs: poly.iter()
                                    .map(|x| F::from_canonical_u64(*x))
                                    .collect::<Vec<F>>()
                                    .try_into()
                                    .unwrap()
                                }
                            )
                            .collect::<Vec<Poly<F, D, N>>>()
                            .try_into()
                            .unwrap()
                        }
                    )
                    .collect::<Vec<Glwe<F, D, N, K>>>()
                    .try_into()
                    .unwrap()
                }
            )
            .collect::<Vec<Glev<F, D, N, K, ELL>>>()
            .try_into()
            .unwrap()
        };
        Ok(InputDataKSK { ksk })
    }
}

pub struct InputDataGlwe {
    pub glwe: Glwe<F, D, N, K>
}

impl Serialize for InputDataGlwe {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let out_ct_coeffs_vec : Vec<Vec<u64>> = self.glwe.polys.iter().map(|poly| poly.coeffs.iter().map(|x| x.to_canonical_u64()).collect()).collect();
        out_ct_coeffs_vec.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for InputDataGlwe {
    fn deserialize<DD>(deserializer: DD) -> Result<InputDataGlwe, DD::Error>
    where
        DD: serde::Deserializer<'de> {
        let out_ct_coeffs_vec : Vec<Vec<u64>> = Vec::deserialize(deserializer)?;
        let out_ct_polys: [Poly<F, D, N>; K] = out_ct_coeffs_vec
            .iter()
            .map(|poly|
                Poly {
                    coeffs: poly.iter().map(|x| F::from_canonical_u64(*x)).collect::<Vec<F>>().try_into().unwrap()
                }
            )
            .collect::<Vec<Poly<F, D, N>>>()
            .try_into()
            .unwrap();
        let out_ct: Glwe<F, D, N, K> = Glwe { polys: out_ct_polys };
        Ok(InputDataGlwe { glwe: out_ct })
    }
}

// The user configures the InputData struct with the necessary fields.
#[derive(Serialize, Deserialize)]
pub struct InputData {
    pub ct: InputDataCT,
    pub testv: InputDataPoly,
    pub bsk: InputDataBSK,
    pub ksk: InputDataKSK,
    pub out_ct: InputDataGlwe,
}

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

    // Read in the bootstrap output ciphertext from the JSON file
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

    // Construct an InputData struct with the necessary fields
    let input_data = InputData {
        ct: InputDataCT { ct },
        testv: InputDataPoly { poly: testv },
        bsk: InputDataBSK { bsk },
        ksk: InputDataKSK { ksk },
        out_ct: InputDataGlwe { glwe: out_ct }
    };

    // Write the InputData struct to a JSON file
    let input_data_str = serde_json::to_string(&input_data)?;
    fs::write("sindri_input.json", input_data_str)?;

    info!("Bootstrap inputs and ouput written to sindri_input.json");
    Ok(())
}
