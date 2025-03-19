use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

use ntt::params::N;

use crate::vtfhe::crypto::ggsw::Ggsw;
use crate::vtfhe::crypto::glwe::Glwe;
use crate::vtfhe::ivc_based_vpbs::{verified_pbs};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::plonk::circuit_data::VerifierOnlyCircuitData;
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2::field::types::{Field, PrimeField64};

use std::fs;
use crate::vtfhe::crypto::poly::Poly;
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

// At minimum, we need to implement a method to read the input data from a JSON file.
impl InputData {
    pub fn from_json(path: &str) -> Self {
        let contents = fs::read_to_string(path).expect("Something went wrong reading the file");
        serde_json::from_str(&contents).unwrap()
    }
}

// Users should rename the struct depending on the circuit they are proving, but the fields of the 
// struct must remain unchanged. 
pub struct BootstrapCircuit {
    pub proof: ProofWithPublicInputs<F, C, D>,
    pub verifier_only: VerifierOnlyCircuitData<C, D>,
    pub common: CommonCircuitData<F, D>,
}

// Users only implement one method called "prove" for their circuit struct.
// The prove method should include importing the InputData struct, creating the circuit, creating 
// the partial witness, and proving the circuit.
impl BootstrapCircuit {
    pub fn prove(path: &str) -> Self {
        let input_data = InputData::from_json(path);


        // prove a PBS
        let (out_ct, proof, cd) =
            verified_pbs::<F, C, D, n, N, K, ELL, LOGB>(&input_data.ct.ct, &input_data.testv.poly, &input_data.bsk.bsk, &input_data.ksk.ksk, None, None, None);

        // FIXME: This should be done within the circuit building code
        // verify that input_data.out_ct.glwe == out_ct
        assert_eq!(input_data.out_ct.glwe, out_ct);

        BootstrapCircuit {
            proof,
            verifier_only: cd.verifier_only,
            common: cd.common
        }
    }
}