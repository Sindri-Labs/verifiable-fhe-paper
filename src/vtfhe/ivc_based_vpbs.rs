use crate::ntt::params::N;
use crate::vtfhe::crypto::lwe::{self, mod_switch_ct};
use crate::vtfhe::{glwe_select, rotate_glwe};
use anyhow::{ensure, Result};
use log::{info, Level};
use plonky2::field::extension::Extendable;
use plonky2::gates::noop::NoopGate;
use plonky2::hash::hash_types::{HashOut, HashOutTarget, RichField, NUM_HASH_OUT_ELTS};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, CommonCircuitData};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, Hasher};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::plonk::prover::prove;
use plonky2::recursion::cyclic_recursion::check_cyclic_proof_verifier_data;
use plonky2::recursion::dummy_circuit::cyclic_base_proof;
use plonky2::timed;
use plonky2::util::timing::TimingTree;
use std::iter::once;

use super::crypto::ggsw::Ggsw;
use super::crypto::glwe::Glwe;
use super::crypto::poly::Poly;
use super::ggsw_ct::GgswCt;
use super::glwe_ct::GlweCt;

// Generates `CommonCircuitData` usable for recursion.
fn common_data_for_recursion<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>() -> CommonCircuitData<F, D>
where
    C::Hasher: AlgebraicHasher<F>,
{
    let config = CircuitConfig::standard_recursion_config();
    let builder = CircuitBuilder::<F, D>::new(config);
    let data = builder.build::<C>();
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let proof = builder.add_virtual_proof_with_pis(&data.common);
    let verifier_data = builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
    builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
    let data = builder.build::<C>();

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let proof = builder.add_virtual_proof_with_pis(&data.common);
    let verifier_data = builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
    builder.verify_proof::<C>(&proof, &verifier_data, &data.common);

    // IMPORTANT: this number needs to be adjusted according to circuit size.
    // For small circuits it is (1 << 12), but with growing circuit size (e.g. for large N)
    // this can go up to (1 << 16) or even higher. Use try and error.
    let circuit_size = if N == 8 { 1 << 12 } else { 1 << 15 };
    while builder.num_gates() < circuit_size {
        builder.add_gate(NoopGate, vec![]);
    }
    builder.build::<C>().common
}

fn verify_hash_output<F: RichField>(hash_data: &[Vec<F>], claimed_hash: HashOut<F>) -> Result<()> {
    let mut hash = HashOut::ZERO;

    for data in hash_data {
        let data_in: Vec<F> = hash
            .elements
            .into_iter()
            .chain(data.into_iter().map(|&d| d))
            .collect();
        hash = PoseidonHash::hash_no_pad(&data_in);
    }
    ensure!(hash == claimed_hash);

    Ok(())
}

fn build_step_circuit<
    F: RichField + Extendable<D>,
    const D: usize,
    const LOGB: usize,
    const N: usize,
    const K: usize,
    const ELL: usize,
    const n: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    w_1: &F,
    w_2: &F,
) -> (
    Target,
    Target,
    GlweCt<N, K>,
    GgswCt<N, K, ELL>,
    GlweCt<N, K>,
    Target,
    HashOutTarget,
    HashOutTarget,
    HashOutTarget,
) {
    let acc_init = GlweCt::<N, K>::new_from_builder(builder);
    let ggsw = GgswCt::<N, K, ELL>::new_from_builder(builder);
    acc_init.register(builder);
    let current_acc_in = GlweCt::<N, K>::new_from_builder(builder);
    let counter = builder.add_virtual_public_input();
    let one = builder.one();
    let first_step = builder.is_equal(counter, one);
    let n_target = builder.constant(F::from_canonical_usize(n + 2));
    let last_step = builder.is_equal(counter, n_target);

    // create targets for the LWE sample elements
    let mask_element_1 = builder.add_virtual_target();
    let mask_element_2 = builder.add_virtual_target();

    // create constant targets for the ciphertext weights (the same weights is applied to each LWE sample element)
    let weight_1 = builder.constant(*w_1);
    let weight_2 = builder.constant(*w_2);

    // multiply the LWE sample elements by their respective weights
    let weighted_mask_element_1 = builder.mul(weight_1, mask_element_1);
    let weighted_mask_element_2 = builder.mul(weight_2, mask_element_2);

    // add the LWE sample elements
    let mask_element = builder.add(weighted_mask_element_1, weighted_mask_element_2);

    // in the first step we need to negate the mask element, because it is actually the body
    let neg_mask = builder.neg(mask_element);
    let first_negated_mask = builder.select(first_step, neg_mask, mask_element);

    let shifted_glwe = rotate_glwe(builder, &current_acc_in, first_negated_mask);
    let diff_glwe = shifted_glwe.sub(builder, &current_acc_in);
    let xprod_in = glwe_select(builder, last_step, &current_acc_in, &diff_glwe);
    let xprod_out = ggsw.external_product::<F, D, LOGB>(builder, &xprod_in);
    let cmux_out = xprod_out.add(builder, &current_acc_in);

    // in the last step we don't do a cmux, but just an external product for key switch
    let cmux_or_exprod = glwe_select(builder, last_step, &xprod_out, &cmux_out);

    // in the first step (body) we don't apply the full CMUX, just the rotation
    let current_acc_out = glwe_select(builder, first_step, &shifted_glwe, &cmux_or_exprod);
    current_acc_out.register(builder);

    let current_bsk_hash_in = builder.add_virtual_hash();
    let current_bsk_hash_out = builder.hash_n_to_hash_no_pad::<PoseidonHash>(
        current_bsk_hash_in
            .elements
            .into_iter()
            .chain(ggsw.flatten().into_iter())
            .collect(),
    );

    let current_lwe_hash_in_1 = builder.add_virtual_hash();
    let current_lwe_hash_out_1 = builder.hash_n_to_hash_no_pad::<PoseidonHash>(
        current_lwe_hash_in_1
            .elements
            .into_iter()
            .chain(once(mask_element_1))
            .collect(),
    );

    let current_lwe_hash_in_2 = builder.add_virtual_hash();
    let current_lwe_hash_out_2 = builder.hash_n_to_hash_no_pad::<PoseidonHash>(
        current_lwe_hash_in_2
            .elements
            .into_iter()
            .chain(once(mask_element_2))
            .collect(),
    );

    builder.register_public_inputs(&current_bsk_hash_out.elements);
    builder.register_public_inputs(&current_lwe_hash_out_1.elements);
    builder.register_public_inputs(&current_lwe_hash_out_2.elements);

    (
        mask_element_1,
        mask_element_2,
        acc_init,
        ggsw,
        current_acc_in,
        counter,
        current_bsk_hash_in,
        current_lwe_hash_in_1,
        current_lwe_hash_in_2,
    )
}

pub fn verified_pbs<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
    const n: usize,
    const N: usize,
    const K: usize,
    const ELL: usize,
    const LOGB: usize,
>(
    ct_1: &[F],
    ct_2: &[F],
    weight_1: &F,
    weight_2: &F,
    testv: &Poly<F, D, N>,
    bsk: &[Ggsw<F, D, N, K, ELL>],
    ksk: &Ggsw<F, D, N, K, ELL>,
    debug_glwe_key: &[Poly<F, D, N>],
    debug_lwe_key: &[F],
    debug_ksk_key: &[Poly<F, D, N>],
) -> (
    Glwe<F, D, N, K>,
    ProofWithPublicInputs<F, C, D>,
    CircuitData<F, C, D>,
)
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    C: 'static,
{
    info!(
        "Parameters: n={n}, N={N}, k={}, logB={LOGB}, ell={ELL}",
        K - 1
    );

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config.clone());
    let one = builder.one();

    let (
        lwe_ct_1,
        lwe_ct_2,
        acc_init,
        ggsw,
        current_acc_in,
        counter,
        current_bsk_hash_in,
        current_lwe_hash_in_1,
        current_lwe_hash_in_2,
    ) = build_step_circuit::<F, D, LOGB, N, K, ELL, n>(&mut builder, weight_1, weight_2);
    let acc_init_range = (0, GlweCt::<N, K>::num_targets());
    let counter_idx = acc_init_range.1;
    let latest_acc_range = (
        counter_idx + 1,
        counter_idx + 1 + GlweCt::<N, K>::num_targets(),
    );

    let hash_bsk_out_range = (latest_acc_range.1, latest_acc_range.1 + NUM_HASH_OUT_ELTS);
    let hash_lwe_out_range_1 = (
        hash_bsk_out_range.1,
        hash_bsk_out_range.1 + NUM_HASH_OUT_ELTS,
    );
    let hash_lwe_out_range_2 = (
        hash_lwe_out_range_1.1,
        hash_lwe_out_range_1.1 + NUM_HASH_OUT_ELTS,
    );

    let mut common_data = common_data_for_recursion::<F, C, D>();
    let verifier_data_target = builder.add_verifier_data_public_inputs();
    common_data.num_public_inputs = builder.num_public_inputs();

    // Unpack inner proof's public inputs.
    let inner_cyclic_proof_with_pis = builder.add_virtual_proof_with_pis(&common_data);
    let inner_cyclic_pis = &inner_cyclic_proof_with_pis.public_inputs;
    let inner_cyclic_acc_init = &inner_cyclic_pis[acc_init_range.0..acc_init_range.1];
    let inner_cyclic_counter = inner_cyclic_pis[counter_idx];
    let inner_cyclic_latest_acc =
        GlweCt::new_from_targets(&inner_cyclic_pis[latest_acc_range.0..latest_acc_range.1]);
    let inner_cyclic_latest_bsk_hash =
        HashOutTarget::try_from(&inner_cyclic_pis[hash_bsk_out_range.0..hash_bsk_out_range.1])
            .unwrap();
    let inner_cyclic_latest_lwe_hash_1 =
        HashOutTarget::try_from(&inner_cyclic_pis[hash_lwe_out_range_1.0..hash_lwe_out_range_1.1])
            .unwrap();
    let inner_cyclic_latest_lwe_hash_2 =
        HashOutTarget::try_from(&inner_cyclic_pis[hash_lwe_out_range_2.0..hash_lwe_out_range_2.1])
            .unwrap();

    for (initial_target, inner_cyclic_initial_target) in acc_init
        .flatten()
        .iter()
        .zip(inner_cyclic_acc_init.into_iter())
    {
        builder.connect(*initial_target, *inner_cyclic_initial_target);
    }

    // base case or not
    let condition = builder.add_virtual_bool_target_safe();
    let actual_acc_in = glwe_select(&mut builder, condition, &inner_cyclic_latest_acc, &acc_init);
    for (left, right) in current_acc_in
        .flatten()
        .iter()
        .zip(actual_acc_in.flatten().iter())
    {
        builder.connect(*left, *right);
    }

    let zero = builder.zero();
    let actual_bsk_hash_in = inner_cyclic_latest_bsk_hash
        .elements
        .map(|t| builder.select(condition, t, zero));
    let actual_lwe_hash_in_1 = inner_cyclic_latest_lwe_hash_1
        .elements
        .map(|t| builder.select(condition, t, zero));
    let actual_lwe_hash_in_2 = inner_cyclic_latest_lwe_hash_2
        .elements
        .map(|t| builder.select(condition, t, zero));

    builder.connect_hashes(
        current_bsk_hash_in,
        HashOutTarget::try_from(actual_bsk_hash_in).unwrap(),
    );
    builder.connect_hashes(
        current_lwe_hash_in_1,
        HashOutTarget::try_from(actual_lwe_hash_in_1).unwrap(),
    );
    builder.connect_hashes(
        current_lwe_hash_in_2,
        HashOutTarget::try_from(actual_lwe_hash_in_2).unwrap(),
    );

    let new_counter = builder.mul_add(condition.target, inner_cyclic_counter, one);
    builder.connect(counter, new_counter);

    builder
        .conditionally_verify_cyclic_proof_or_dummy::<C>(
            condition,
            &inner_cyclic_proof_with_pis,
            &common_data,
        )
        .unwrap();

    let cyclic_circuit_data = builder.build::<C>();

    let mut testv_check = testv.clone();
    let weighted_ct_1 = lwe::multiply_constant(ct_1, weight_1);
    let weighted_ct_2 = lwe::multiply_constant(ct_2, weight_2);
    let ct = lwe::add(&weighted_ct_1, &weighted_ct_2);
    let ct_switched = mod_switch_ct(&ct, N);

    let mut pw = PartialWitness::new();
    let initial_pis = vec![F::ZERO; N * (K - 1)]
        .into_iter()
        .chain(testv.coeffs.into_iter())
        .enumerate()
        .collect();
    pw.set_bool_target(condition, false);

    ggsw.assign(&mut pw, &Ggsw::dummy_ct());

    pw.set_target(lwe_ct_1, ct_1[n]);
    pw.set_target(lwe_ct_2, ct_2[n]);

    pw.set_proof_with_pis_target::<C, D>(
        &inner_cyclic_proof_with_pis,
        &cyclic_base_proof(
            &common_data,
            &cyclic_circuit_data.verifier_only,
            initial_pis,
        ),
    );
    pw.set_verifier_data_target(&verifier_data_target, &cyclic_circuit_data.verifier_only);
    let mut timing = TimingTree::new("prove step 0", Level::Info);
    let mut proof = prove::<F, C, D>(
        &cyclic_circuit_data.prover_only,
        &cyclic_circuit_data.common,
        pw,
        &mut timing,
    )
    .unwrap();
    timing.print();
    testv_check = testv_check.left_shift(ct_switched[n]);
    let mut current_acc: Glwe<F, D, N, K> =
        Glwe::from_slice(&proof.public_inputs[latest_acc_range.0..latest_acc_range.1]);

    info!(
        "Avg error: {}",
        current_acc.get_avg_error(&debug_glwe_key, &testv_check)
    );
    info!(
        "Max error: {}",
        current_acc.get_max_error(&debug_glwe_key, &testv_check)
    );

    for x in 0..n {
        println!("loop {x}");
        let mut pw = PartialWitness::new();
        pw.set_bool_target(condition, true);
        ggsw.assign(&mut pw, &bsk[x]);
        pw.set_target(lwe_ct_1, ct_1[x]);
        pw.set_target(lwe_ct_2, ct_2[x]);
        pw.set_proof_with_pis_target(&inner_cyclic_proof_with_pis, &proof);
        pw.set_verifier_data_target(&verifier_data_target, &cyclic_circuit_data.verifier_only);
        let root_name = format!("prove step {x}");
        let mut timing = TimingTree::new(&root_name, Level::Info);
        proof = prove::<F, C, D>(
            &cyclic_circuit_data.prover_only,
            &cyclic_circuit_data.common,
            pw,
            &mut timing,
        )
        .unwrap();
        timing.print();
        testv_check = testv_check
            .right_shift(ct_switched[x] * (debug_lwe_key[x].to_canonical_u64() as usize));
        current_acc =
            Glwe::from_slice(&proof.public_inputs[latest_acc_range.0..latest_acc_range.1]);
        info!(
            "Avg error: {}",
            current_acc.get_avg_error(&debug_glwe_key, &testv_check)
        );
        info!(
            "Max error: {}",
            current_acc.get_max_error(&debug_glwe_key, &testv_check)
        );
    }

    // key switch
    let mut pw = PartialWitness::new();
    pw.set_bool_target(condition, true);
    ggsw.assign(&mut pw, &ksk);
    pw.set_target(lwe_ct_1, F::ZERO);
    pw.set_target(lwe_ct_2, F::ZERO);
    pw.set_proof_with_pis_target(&inner_cyclic_proof_with_pis, &proof);
    pw.set_verifier_data_target(&verifier_data_target, &cyclic_circuit_data.verifier_only);
    let root_name = format!("key switch");
    let mut timing = TimingTree::new(&root_name, Level::Info);
    proof = prove::<F, C, D>(
        &cyclic_circuit_data.prover_only,
        &cyclic_circuit_data.common,
        pw,
        &mut timing,
    )
    .unwrap();
    timing.print();

    current_acc = Glwe::from_slice(&proof.public_inputs[latest_acc_range.0..latest_acc_range.1]);
    info!(
        "Avg error: {}",
        current_acc.get_avg_error(&debug_ksk_key, &testv_check)
    );
    info!(
        "Max error: {}",
        current_acc.get_max_error(&debug_glwe_key, &testv_check)
    );

    let acc_out_slice = &proof.public_inputs[latest_acc_range.0..latest_acc_range.1];
    let acc_out = Glwe::<F, D, N, K>::from_slice(&acc_out_slice);
    (acc_out, proof, cyclic_circuit_data)
}

pub fn verify_pbs<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
    const n: usize,
    const N: usize,
    const K: usize,
    const ELL: usize,
    const LOGB: usize,
>(
    out_ct: &Glwe<F, D, N, K>,
    ct_1: &[F],
    ct_2: &[F],
    testv: &Poly<F, D, N>,
    bsk: &[Ggsw<F, D, N, K, ELL>],
    ksk: &Ggsw<F, D, N, K, ELL>,
    proof: &ProofWithPublicInputs<F, C, D>,
    cd: &CircuitData<F, C, D>,
) where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    C: 'static,
{
    let acc_init_range = (0, GlweCt::<N, K>::num_targets());
    let counter_idx = acc_init_range.1;
    let latest_acc_range = (
        counter_idx + 1,
        counter_idx + 1 + GlweCt::<N, K>::num_targets(),
    );
    let hash_bsk_out_range = (latest_acc_range.1, latest_acc_range.1 + NUM_HASH_OUT_ELTS);
    let hash_lwe_out_range_1 = (
        hash_bsk_out_range.1,
        hash_bsk_out_range.1 + NUM_HASH_OUT_ELTS,
    );
    let hash_lwe_out_range_2 = (
        hash_lwe_out_range_1.1,
        hash_lwe_out_range_1.1 + NUM_HASH_OUT_ELTS,
    );

    let claimed_testv = &proof.public_inputs[acc_init_range.0..acc_init_range.1];
    for x in &claimed_testv[..N * (K - 1)] {
        assert_eq!(F::ZERO, *x);
    }
    for (x, y) in testv
        .coeffs
        .into_iter()
        .zip(claimed_testv[N * (K - 1)..].into_iter())
    {
        assert_eq!(x, *y);
    }

    assert_eq!(
        F::from_canonical_usize(n + 2),
        proof.public_inputs[counter_idx]
    );

    let claimed_out_ct =
        Glwe::from_slice(&proof.public_inputs[latest_acc_range.0..latest_acc_range.1]);
    assert_eq!(*out_ct, claimed_out_ct);

    let mut timing = TimingTree::new("verify", Level::Info);
    let _ = timed!(
        timing,
        "verifying Step 1",
        cd.verify(proof.clone()).unwrap()
    );
    let _ = timed!(
        timing,
        "verifying Step 2",
        check_cyclic_proof_verifier_data(&proof, &cd.verifier_only, &cd.common,).unwrap()
    );

    // add the LWE sample elements
    // let weighted_ct_1 = lwe::multiply_constant(ct_1, weight_1);
    // let weighted_ct_2 = lwe::multiply_constant(ct_2, weight_2);
    // let ct = lwe::add(&weighted_ct_1, &weighted_ct_2);

    let hash_bsk_out =
        HashOut::try_from(&proof.public_inputs[hash_bsk_out_range.0..hash_bsk_out_range.1])
            .unwrap();
    let hash_lwe_out_1 =
        HashOut::try_from(&proof.public_inputs[hash_lwe_out_range_1.0..hash_lwe_out_range_1.1])
            .unwrap();
    let hash_lwe_out_2 =
        HashOut::try_from(&proof.public_inputs[hash_lwe_out_range_2.0..hash_lwe_out_range_2.1])
            .unwrap();
    let mut hash_bsk_data: Vec<Vec<F>> = Vec::new();
    let mut hash_lwe_data_1: Vec<Vec<F>> = Vec::new();
    let mut hash_lwe_data_2: Vec<Vec<F>> = Vec::new();
    hash_bsk_data.push(Ggsw::<F, D, N, K, ELL>::dummy_ct().flatten());
    hash_lwe_data_1.push(vec![ct_1[n]]);
    hash_lwe_data_2.push(vec![ct_2[n]]);

    for ((ggsw, mask_1), mask_2) in bsk.iter().zip(ct_1[..n].iter()).zip(ct_2[..n].iter()) {
        hash_bsk_data.push(ggsw.flatten());
        hash_lwe_data_1.push(vec![*mask_1]);
        hash_lwe_data_2.push(vec![*mask_2]);
    }

    // add ksk to hash data
    hash_bsk_data.push(ksk.flatten());
    hash_lwe_data_1.push(vec![F::ZERO]);
    hash_lwe_data_2.push(vec![F::ZERO]);

    // we don't include check of the BSK hash in the timing, because we assume that the hash
    // was precomputed
    verify_hash_output(&hash_bsk_data, hash_bsk_out).unwrap();

    let _ = timed!(
        timing,
        "verifying Step 3.1",
        verify_hash_output(&hash_lwe_data_1, hash_lwe_out_1).unwrap()
    );
    timing.print();

    let _ = timed!(
        timing,
        "verifying Step 3.2",
        verify_hash_output(&hash_lwe_data_2, hash_lwe_out_2).unwrap()
    );
    timing.print();

    let counter = proof.public_inputs[counter_idx];

    info!("number of steps: {}", counter);

    info!("proof size: {} bytes", proof.to_bytes().len());
}

#[cfg(test)]
mod tests {
    use std::array::from_fn;

    use super::*;
    use crate::ntt::params::N;
    use crate::vtfhe::crypto::compute_bsk;
    use crate::vtfhe::crypto::glwe::Glwe;
    use crate::vtfhe::crypto::lwe::encrypt;
    use crate::vtfhe::crypto::poly::Poly;

    use plonky2::field::types::Field;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2::util::log2_ceil;
    use rand::random;

    fn check_rotation<F: RichField + Extendable<D>, const D: usize, const N: usize>(
        in_poly: &Poly<F, D, N>,
        out_poly: &Poly<F, D, N>,
        mask_element: &F,
    ) {
        let mut shift = mask_element.to_canonical_u64() as usize;
        shift >>= F::BITS - log2_ceil(N) - 2;
        let carry = shift % 2;
        shift >>= 1;
        shift += carry;

        let mut poly = in_poly;
        let neg_poly = &in_poly.scalar_mul(&(-F::ONE));
        if shift > N {
            shift = shift % N;
            poly = neg_poly;
        }

        for i in 0..N - shift {
            assert_eq!(
                poly.coeffs[i],
                out_poly.coeffs[i + shift],
                "poly not rotated correctly."
            )
        }
        for i in 0..shift {
            assert_eq!(
                poly.coeffs[N - shift + i],
                -out_poly.coeffs[i],
                "poly not rotated correctly."
            )
        }
    }

    #[test]
    fn test_ivc_blind_rot() {
        const LOGB: usize = 8;
        const ELL: usize = 8;
        const K: usize = 2;
        const D: usize = 2;
        const n: usize = 1;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let s_to = Glwe::<F, D, N, K>::partial_key(n);
        let s_lwe = Glwe::<F, D, N, K>::flatten_partial_key(&s_to, n);
        println!("s_lwe: {:?}", s_lwe);
        let s_glwe = Glwe::<F, D, N, K>::key_gen();
        let bsk = compute_bsk::<F, D, N, K, ELL, LOGB>(&s_lwe, &s_glwe, 0f64);

        let ksk = Ggsw::<F, D, N, K, ELL>::compute_ksk::<LOGB>(&s_to, &s_glwe, 0f64);

        let testv = Poly::<F, D, N> {
            coeffs: from_fn(|i| F::from_canonical_usize(i)),
        };
        println!("testv: {:?}", testv);
        let delta = F::from_noncanonical_biguint(F::order() >> log2_ceil(2 * N));
        let m_1 = F::from_canonical_u64(random::<u64>() % (N as u64));
        let w_1 = F::ONE;
        let w_2 = F::TWO;
        let m_2 = F::from_canonical_u64(random::<u64>() % (N as u64));
        println!("message 1: {delta} * {m_1} = {}", delta * m_1);
        println!("weight 1: {w_1}");
        println!("message 2: {delta} * {m_2} = {}", delta * m_2);
        println!("weight 2: {w_2}");
        let ct_1 = encrypt::<F, D, n>(&s_lwe, &(delta * m_1), 0f64);
        let ct_2 = encrypt::<F, D, n>(&s_lwe, &(delta * m_2), 0f64);
        println!("ct_1: {:?}", ct_1);
        println!("ct_2: {:?}", ct_2);
        let (out_ct, proof, cd) = verified_pbs::<F, C, D, n, N, K, ELL, LOGB>(
            &ct_1, &ct_2, &w_1, &w_2, &testv, &bsk, &ksk, &s_glwe, &s_lwe, &s_to,
        );

        verify_pbs::<F, C, D, n, N, K, ELL, LOGB>(
            &out_ct, &ct_1, &ct_2, &testv, &bsk, &ksk, &proof, &cd,
        );
        let m_out = out_ct.decrypt(&s_to);
        println!("output ct: {:?}", out_ct);
        println!("output poly: {:?}", m_out);
        println!("in: {m_1} * {w_1} + {m_2} * {w_2} out: {}", m_out.coeffs[0]);

        check_rotation(&testv, &m_out, &(-delta * m_1));
        check_rotation(&testv, &m_out, &(-delta * m_2));
    }
}
