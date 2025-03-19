# Remote Execution with Verification, At Last

> Note: This is a complex circuit taking approx 45 minutes to prove.

Suppose you have a small device, with not much compute power, holding sensitive data. You want to perform a computation on the data, but for whatever reasons want to outsource that computation to the cloud. How do you verify that the cloud actually performed the computation you wanted? How do you do this without revealing your sensitive data?

Both of these problems have already been solved. Fully Homomorphic Encryption (FHE) allows you to perform computation on encrypted values, but the recipient of the output has limited assurance as to what the computation actually was. Zero Knowledge (ZK) Proofs allow you to gain assurance as to a computation being performed, but the prover necessarily sees the underlying data. Putting these two solutions together allows you to outsource computation without sacrificing confidentiality. Sounds good, right? So why aren't we all just doing that?

1. It's expensive. The worst case ZK overhead multiplied by the worst case FHE overhead is very very costly.
2. It won't always work. Some FHE schemes seem fundamentally incapable of being combined with ZK proofs.
3. It hasn't actually been done yet...or has it?

## Combining FHE and ZK

It is possible to verifiably remotely compute really trivial circuits. But why would you want to outsource such a computation? The reason for the size limitation is that FHE is noisy. All FHE schemes combine their plaintexts with random noise to create ciphertext. Operations on those ciphertexts increase the noise level - after too many operations, the noise gets too much and you can no longer be sure that you can correctly decrypt the answer.

The answer to this noise problem is also the biggest obstacle to verifiable FHE in practice: the bootstrapping operation. In this, we encode the decryption operation in terms of FHE operations on the ciphertext - the output of this bootstrapping circuit will map to the same plaintext as its input, but the output has tight bounds on its noise level.

> Aside: If you're interested in learning about TFHE, check out this [video presentation](https://www.youtube.com/watch?v=npoHSR6-oRw) by one of its authors, and her [detailed writeup of TFHE](https://www.zama.ai/post/tfhe-deep-dive-part-1).

Presented at ZK12, [Towards Verifiable FHE in Practice](https://www.youtube.com/watch?v=81xAuSQ78EM&list=PLj80z0cJm8QFy2umHqu77a8dbZSqpSH54&index=20) changes this landscape, with an actual ZK proof of the TFHE bootstrapping circuit ([paper](https://eprint.iacr.org/2024/451.pdf)). The code for this project is stored in this [repository](https://github.com/Sindri-Labs/verifiable-fhe-paper), which is a fork of their work. The upstream [verifiable FHE code repository](https://github.com/zama-ai/verifiable-fhe-paper) contains a full implementation of the bootstrapping circuit proving and verification. Be forewarned, this is a prototype, proving time is slow - this is a complex, recursive proving circuit - but the point is that the capability now exists. And things can only get better from here.

> Aside: Bootstrapping has an interesting history - Gentry's [original FHE scheme](https://crypto.stanford.edu/craig/craig-thesis.pdf), was theoretically bootstrappable, but the projected overheads were very high, and it wasn't implemented in practice. The next generation of schemes in the 2010s opted to avoid bootstrapping altogether, instead providing schemes that could be leveled to a fixed noise operating budget or computation size. [TFHE](https://tfhe.github.io/tfhe/) stands out as a fast FHE scheme with an actually performant bootstrapping operation.

## What Is This Project About?

Our goal with this project is to build upon the verifiable FHE work by decoupling the different parties to such a computation. The entity performing the computation needn't be the one generating or verifying the proof, or the one generating the keys and plaintext, and separating them out into individual programs forces us to examine and justify any communication between them, so that we can limit disclosure as much as possible. The final set of steps will include:

| Entity       | Runs This Program  | To Perfom This Operation
|--------------|--------------------|-------------------------------------------------------------
| data owner   | vfhe_encrypt       | create keys, plaintext, and ciphertext, and write to files
| anybody      | vfhe_bootstrap     | perform just the bootstrapping locally (not implemented yet)
| compute node | vfhe_prove_local   | perform bootstrapping and generate proof of correctness locally
| anybody      | vfhe_prove_sindri  | same as above, but outsourcing the proving to [Sindri](https://sindri.app)
| anybody      | vfhe_verify        | verify a proof generated locally or remotely
| data owner   | vfhe_decrypt       | read keys and ciphertext, and decrypt
| all in one   | vfhe_plonky2       | the upstream code, as unmodified as possible

The first stage of decoupling the parties just required some minor Rust code, to save the final proof and public inputs to local files, such that they can be read in again and verified by a different program. The only barriers here are serializing and deserializing the various rust structures used for inputs and outputs.

The second stage is outsourcing the proof generation to a different entity. This project will use [Sindri](https://sindri.app)'s proving infrastructure as a service. Currently, the `vfhe_prove_sindri` program merely constructs the input data to be sent to the proving service via the [Sindri CLI](https://sindri.app/docs/getting-started/cli/), future versions will use the API directly.

The final stage of decoupling - not yet completed - is to claw back the basic computation. The `bootstrap_inputs.json` can be supplied to any third party who should be able to perform just the bootstrapping computation (with `vfhe_bootstrap`) and generate the inputs to the remote proving service. It should also only pass the bare minimum of information to the proving service in the process.

Once fully decoupled, we hope to investigate the programmable aspect of TFHE's bootstrapping operation, in which the final step can incorporate function evaluation - so instead of getting a low-noise copy of the original ciphertext, you get a low-noise ciphertext that decrypts to `function(plaintext)`. This is the perfect building block for arbitrary remote execution that is confidential but verifiable. An individual ciphertext generated by one party value can verifiably be combined with other ciphertexts from other parties (with simple logical/arithmetic operations), and the result can be put through a known function via the bootstrapping step, with another layer of recursion to chain all the proofs into one.

## Data Replication

To perform the [Sindri](https://sindri.app)-powered step, you will need a free account, and you can use the [Sindri CLI](https://sindri.app/docs/getting-started/cli/) to login or create an API key via the website. Either way, your API key should be in the variable `SINDRI_API_KEY`.

The code and data can be obtained in two ways:

```
git clone https://github.com/Sindri-Labs/verifiable-fhe-paper
sindri clone syntacticnet/verifiable_fhe
```

The code can be built locally with:

```
cargo build --release
```

The `data` directory contains the output of a single run through the steps. Each binary is run without arguments, and the files in the data directory were captured as follows:

```
vfhe_encrypt      > logs/1_vfhe_encrypt.txt      2>&1
vfhe_prove_local  > logs/2_vfhe_prove_local.txt  2>&1
vfhe_prove_sindri > logs/3_vfhe_prove_sindri.txt 2>&1
cat sindri_input.json | sindri proof create --verify > sindri_proof.json 2>logs/4_sindri_proof_create.txt
vfhe_verify       > logs/5_vfhe_verify.txt       2>&1
vfhe_decrypt      > logs/6_vfhe_decrypt.txt      2>&1
```

## Disclaimer
This implementation is purely for academic purposes and not meant for production.

## License
This software is distributed under the **BSD-3-Clause-Clear** license, and is heavily derived from Zama-AI's upstream [repository](https://github.com/zama-ai/verifiable-fhe-paper).