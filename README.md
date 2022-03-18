# Efficient bitsliced implementations of SKINNY-128 tweakable block ciphers

SKINNY is a tweakable block cipher family that operates either on 64-bit or 128-bit blocks. For more information on SKINNY, see: https://sites.google.com/site/skinnycipher/. It has been used in used in several [NIST LWC competition](https://csrc.nist.gov/projects/lightweight-cryptography) candidates, including [Romulus](https://romulusae.github.io/romulus) and [SKINNY-AEAD](https://sites.google.com/site/skinnycipher/nist-lwc-submission/skinny).

This repository contains efficient bitsliced implementations of SKINNY-128 on 32-bit platforms. More precisely, it provides two versions:
- `crypto_tbc/skinny128/1_block`:  a single block is processed a time
- `crypto_tbc/skinny128/2_blocks`: two blocks are processed in parallel.

More details on the implementation tricks can be found in the paper [Fixslicing AES-like Ciphers](https://eprint.iacr.org/2020/1123.pdf) regarding the SKINNY-128 round function, and in [Fixslicing: Application to Some NIST LWC Round 2 Candidates](https://csrc.nist.gov/CSRC/media/Events/lightweight-cryptography-workshop-2020/documents/papers/fixslicing-lwc2020.pdf) regarding the tweakey schedule.

This repository also provides implementations of the following variants of Romulus and SKINNY-AEAD algorithms:

- `crypto_aead/romulus-n`
- `crypto_aead/romulus-m`
- `crypto_aead/romulus-t`
- `crypto_hash/romulus-h`
- `crypto_aead_hash/romulus-n-h`
- `crypto_aead/skinnyaead-m1`
- `crypto_aead/skinnyaead-m1+`.

Note that the goal of the `crypto_aead_hash` directory is to provide an implementation which supports both AEAD and hash functionalities. Because the tweakey schedule in `crypto_aead/romulus-n/m` takes advantage of the fact that half of TK1 is always null for Romulus-N/M, the code slightly differs in `crypto_aead_hash` to be compliant with Romulus-H.

For each algorithm, one can find:

- `opt32`: 32-bit word oriented C implementation  
- `armv7m`: ARMv7-M assembly implementation for Cortex-M processors.

Note that one can also find an implementation of SKINNY-128 using Intel SSE instructions in `crypto_tbc/skinny128/1_block/sse`.

# Interface

Romulus and SKINNY-AEAD implementations use the inferface defined in the [NIST LWC call for algorithms](https://csrc.nist.gov/CSRC/media/Projects/Lightweight-Cryptography/documents/final-lwc-submission-requirements-august2018.pdf) for benchmarking purposes.

# Compilation

ARM implementations have been compiled using the [arm-none-eabi toolchain](https://developer.arm.com/tools-and-software/open-source-software/developer-tools/gnu-toolchain/gnu-rm) (version 9.2.1) and loaded/tested on the STM32L100C and STM32F407VG development boards using the [libopencm3](https://github.com/libopencm3/libopencm3) project.

Regarding C implementations, test vectors for NIST LWC candidates can be executed using the [NIST LWC test vector generation code](https://csrc.nist.gov/CSRC/media/Projects/Lightweight-Cryptography/documents/TestVectorGen.zip).
