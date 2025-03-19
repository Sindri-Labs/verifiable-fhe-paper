# Remote Execution with Verification, At Last

Suppose you have a small device, with not much compute power, holding sensitive data. You want to perform a computation on the data, but for whatever reasons want to outsource that computation to the cloud. How do you verify that the cloud actually performed the computation you wanted? How do you do this without revealing your sensitive data?

Both of these problems have already been solved. Fully Homomorphic Encryption (FHE) allows you to perform computation on encrypted values, but the recipient of the output has limited assurance as to what the computation actually was. Zero Knowledge (ZK) Proofs allow you to gain assurance as to a computation being performed, but the prover necessarily sees the underlying data. Putting these two solutions together allows you to outsource computation without sacrificing confidentiality. Sounds good, right? So why aren't we all just doing that?

1. It's expensive. The worst case ZK overhead multiplied by the worst case FHE overhead is very very costly.
2. It won't always work. Some FHE schemes seem fundamentally incapable of being combined with ZK proofs.
3. It hasn't actually been done yet...or has it?

It is possible to verifiably remotely compute really trivial circuits. But why would you want to outsource such a computation? The reason for the size limitation is that FHE is noisy. All FHE schemes combine their plaintexts with random noise to create ciphertext. Operations on those ciphertexts increase the noise level - after too many operations, the noise gets too much and you can no longer be sure that you can correctly decrypt the answer.

The answer to this noise problem is also the biggest obstacle to verifiable FHE in practice: the bootstrapping operation. In this, we encode the decryption operation in terms of FHE operations on the ciphertext - the output of this bootstrapping circuit will map to the same plaintext as its input, but the output has tight bounds on its noise level.

> Aside: Bootstrapping has an interesting history - Gentry's [original FHE scheme](https://crypto.stanford.edu/craig/craig-thesis.pdf), was theoretically bootstrappable, but the projected overheads were very high, and it wasn't implemented in practice. Later schemes of the 2010s opted to avoid bootstrapping altogether, instead providing schemes that could be leveled to a fixed noise operating budget. [TFHE](https://tfhe.github.io/tfhe/) stands out as a fast FHE scheme with an actually performant bootstrapping operation.

Presented at ZK12, [Towards Verifiable FHE in Practice](https://www.youtube.com/watch?v=81xAuSQ78EM&list=PLj80z0cJm8QFy2umHqu77a8dbZSqpSH54&index=20) changes this landscape, with an actual ZK proof of the TFHE bootstrapping circuit ([paper](https://eprint.iacr.org/2024/451.pdf)). The code for this project is stored in this [repository](https://github.com/Sindri-Labs/verifiable-fhe-paper), which is a fork of their work. The upstream [verifiable FHE code repository](https://github.com/zama-ai/verifiable-fhe-paper) contains a full implementation of the bootstrapping circuit proving and verification. Be forewarned, this is a prototype, proving time is slow - this is a complex, recursive proving circuit - but the point is that the capability now exists. And things can only get better from here.

Our goal with this project is to build upon the verifiable FHE work by decoupling the different parties to such a computation. The entity performing the computation needn't be the one generating or verifying the proof, or the one generating the keys and plaintext. When built with `cargo`, the final set of binaries will include:
    * vfhe_encrypt      - create keys, plaintext, and ciphertext, and write to files
    * vfhe_prove_local  - perform bootstrapping and generate proof of correctness
    * vfhe_prove_sindri - same as above, but via [Sindri](https://sindri.app)
    * vfhe_verify       - verify a proof generated locally or remotely
    * vfhe_decrypt      - read keys and ciphertext, and decrypt
    * vfhe_plonky2      - the upstream code, as unmodified as possible

The first stage of decoupling the parties just requires some minor Rust code, to save the final proof and public inputs to local files, such that they can be read in again and verified by a different program. The only barriers here are serializing and deserializing the various rust structures used for inputs and outputs.

The second stage - still in progress - is outsourcing the proof generation to a different entity. This project will use [Sindri](https://sindri.app)'s proving infrastructure as a service, and the `vfhe_compute_sindri` program performs the computation and uses this remote proving service to generate the proof.

The final stage of decoupling - not yet started - is to claw back the basic computation, so that the holder of the key and plaintext performs just the bootstrapping computation locally, and doesn't need to be involved in proof construction. It should also only pass the bare minimum of information to the proving service.

## Disclaimer
This implementation is purely for academic purposes and not meant for production.

## License
This software is distributed under the **BSD-3-Clause-Clear** license, and is heavily derived from Zama-AI's upstream [repostiory](https://github.com/zama-ai/verifiable-fhe-paper).