# Efficient constant-time software implementations of Skinny-128 tweakable block ciphers and Romulus AEAD schemes

[Skinny](https://sites.google.com/site/skinnycipher/) is a tweakable block cipher family that operates either on 64-bit or 128-bit blocks which is used in the [Romulus AEAD scheme](https://romulusae.github.io/romulus), a [NIST LWC finalist](https://csrc.nist.gov/Projects/lightweight-cryptography/finalists).

This repository provides efficient constant-time software implementations of Skinny-128 on various platforms.
The implementations are aimed to be used in sequential operating modes. For parallel modes of operation, there is a very fast [bitsliced AVX2 implementation](https://github.com/kste/skinny_avx) from Stefan Kölbl which processes 64 128-bit blocks at a time (i.e. 1KiB).
This repositories contain two types of implementations:
* Optimized bitsliced (or *fixsliced*), detailed in [Fixslicing AES-like Ciphers](https://eprint.iacr.org/2020/1123.pdf) and [Fixslicing: Application to Some NIST LWC Round 2 Candidates](https://csrc.nist.gov/CSRC/media/Events/lightweight-cryptography-workshop-2020/documents/papers/fixslicing-lwc2020.pdf), which process either
    * a single block at a time (`crypto_tbc/skinny128/bitsliced/1_block`)
    * two blocks at a time (`crypto_tbc/skinny128/bitsliced/2_blocks`) which can be useful for redundant computations against fault attacks
* Byte-wise SIMD, detailed in [Fast Skinny-128 SIMD Implementations for Sequential Modes of Operation](), which process a single block at a time and are written for 3 different platforms with SIMD units
    * ARMv7-A (`crypto_tbc/skinny128/simd/armv7a`)
    * ARMv8-A (`crypto_tbc/skinny128/simd/armv8a`)
    * x86 SSSE3 (`crypto_tbc/skinny128/simd/x86`)

This repository also provides implementations of the following variants of Romulus:

- `crypto_aead/romulus-n`
- `crypto_aead/romulus-m`
- `crypto_aead/romulus-t`
- `crypto_hash/romulus-h`
- `crypto_aead_hash/romulus-n-h`
- `crypto_aead_hash/romulus-t-h`
- `crypto_aead_hash/romulus-m-h`

Note that the goal of the `crypto_aead_hash` directory is to provide an implementation which supports both AEAD and hash functionalities. Because the tweakey schedule in `crypto_aead/romulus-n/m` takes advantage of the fact that half of TK1 is always null for Romulus-N/M, the code slightly differs in `crypto_aead_hash` to be compliant with Romulus-H.

For each algorithm, one can find:

- `opt32`: 32-bit word oriented C implementation  
- `armv7m`: ARMv7-M assembly implementation for Cortex-M processors.
- `armv7a`: ARMv7-A assembly implementation for AArch32 Cortex-A processors.
- `armv8a`: ARMv8-A assembly implementation for AArch64 Cortex-A processors.
- `x86`: SSSE3 intrinsics implementation for x86 processors with support of SSSE3 instructions.

Note that the Romulus implementations have also been submitted to the [SUPERCOP benchmarking suite](https://bench.cr.yp.to/index.html).
