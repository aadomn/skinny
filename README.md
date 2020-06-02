# Efficient bitsliced implementations of SKINNY-128 tweakable block ciphers

SKINNY is a tweakable block cipher family that operates either on 64-bit or 128-bit blocks. For more information on SKINNY, see: https://sites.google.com/site/skinnycipher/. It has been used in used in several [NIST LWC competition](https://csrc.nist.gov/projects/lightweight-cryptography) candidates, including [Romulus](https://romulusae.github.io/romulus) and [SKINNY-AEAD](https://sites.google.com/site/skinnycipher/nist-lwc-submission/skinny).

This repository contains efficient bitsliced implementations of SKINNY-128 on 32-bit platforms. More precisely, it provides two versions:
- `crypto_tbc/skinny128/1_block`:  a single block is processed a time
- `crypto_tbc/skinny128/2_blocks`: two blocks are processed in parallel.

It also provides implementations of the following variants of Romulus and SKINNY-AEAD:

- `crypto_aead/romulusn1v1`
- `crypto_aead/romulusn1+v1`
- `crypto_aead/romulusm1v1`
- `crypto_aead/romulusm1+v1`
- `crypto_aead/skinnyaeadm1v11`
- `crypto_aead/skinnyaeadm1+v11`.

For each algorithm, one can find:

- `opt32`: 32-bit word oriented C implementation  
- `armcortexm`: ARM assembly implementation for Cortex-M processors.

# Interface

Romulus and SKINNY-AEAD implementations use the inferface defined in the [NIST LWC call for algorithms](https://csrc.nist.gov/CSRC/media/Projects/Lightweight-Cryptography/documents/final-lwc-submission-requirements-august2018.pdf) for benchmarking purposes.

# Compilation

ARM implementations have been compiled using the [arm-none-eabi toolchain](https://developer.arm.com/tools-and-software/open-source-software/developer-tools/gnu-toolchain/gnu-rm) (version 9.2.1) and loaded/tested on the STM32L100C and STM32F407VG development boards using the [libopencm3](https://github.com/libopencm3/libopencm3) project.

Regarding C implementations, test vectors for NIST LWC candidates can be executed using the [NIST LWC test vector generation code](https://csrc.nist.gov/CSRC/media/Projects/Lightweight-Cryptography/documents/TestVectorGen.zip).
