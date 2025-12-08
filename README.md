# Tiny HMAC

**Tiny HMAC** is a lightweight, configurable C library for computing HMACs using multiple SHA and SHA3 variants.  
It builds on [Tiny SHA](tiny-sha) and allows optional direct use of Tiny SHA functions.

---

## Features

- Header-only and portable across C/C++ compilers.
- Configurable HMAC support for multiple hash algorithms:
  - **SHA-1 / SHA-2**: SHA1, SHA224, SHA256, SHA384, SHA512, SHA512/224, SHA512/256
  - **SHA-3**: SHA3-224, SHA3-256, SHA3-384, SHA3-512
- One-shot HMAC computation or incremental update/finalize interface.
- Context cloning and heap allocation support.
- Function name prefixing for integration into larger projects.
- Key size up to 512 bytes.
- Safe Constant-time lexicographic HMAC comparison using 'HMAC_ConstTimeCompareOrder', returning -1/0/1 without leaking timing
- Handles endianness automatically

> SHA variants in Tiny SHA can also be used directly, but SHAKE and raw Keccak are disabled by default.

---

## Configuration

Before including the header, users can configure feature flags:

```c
#define ENABLE_SHA1       1   // enable SHA1 HMAC
#define ENABLE_SHA256     1   // enable SHA256 HMAC
#define ENABLE_SHA3_512   0   // disable SHA3-512 HMAC
#define TSHASH_PREFIX     mylib_ // optional prefix for exported functions
```

You can also define it via compiler flags:

```bash
gcc -DTSHASH_PREFIX=MyLib_ -DTINY_SHA_IMPLEMENTATION tiny_sha.c test_sha.c -o test_sha
```

> ⚠️ Note: `TSHASH_PREFIX` must be defined **before including the header**. If not defined, functions will have no prefix (default behavior).

---

## Internal HMAC Table

The library uses an internal table to map HMAC algorithms to their properties and Tiny SHA function pointers:

```c
static const struct _HMAC_TABLE {
    hmac_alg_t alg;                        // Algorithm identifier
    size_t digest_size;                     // Digest length in bytes
    size_t block_size;                      // Internal block size
    size_t ctx_size;                        // Size of hash context
    bool (*hash_init)(void*);               // Hash init function pointer
    bool (*hash_update)(void*, const uint8_t*, size_t);  // Hash update pointer
    bool (*hash_final)(void*, uint8_t*, size_t);         // Hash final pointer
    bool (*hash_squeeze)(void*, uint8_t*, size_t);       // Hash squeeze pointer
} HMAC_TABLE[];
```

This table is used internally by `HMAC_Init` to configure the context according to the selected algorithm.

---

## Usage

### Including the library

```c
#include "tiny_hmac.h"
```

### One-shot HMAC

```c
uint8_t digest[64]; // max digest size
HMAC_Compute(HMAC_SHA256, key, key_len, data, data_len, digest, sizeof(digest));
```

### Incremental HMAC

```c
HMAC_CTX ctx;
HMAC_Init(&ctx, HMAC_SHA256, key, key_len);
HMAC_Update(&ctx, data_part1, len1);
HMAC_Update(&ctx, data_part2, len2);
HMAC_Final(&ctx, digest, sizeof(digest));
HMAC_Free(&ctx);
```

### Heap-allocated context

```c
HMAC_CTX *ctx = HMAC_InitAlloc(HMAC_SHA256, key, key_len);
HMAC_Update(ctx, data, data_len);
HMAC_Final(ctx, digest, sizeof(digest));
HMAC_FreeAlloc(&ctx);
```

---

## API Reference

### Types

```c
typedef enum {
    HMAC_SHA1, HMAC_SHA224, HMAC_SHA256,
    HMAC_SHA384, HMAC_SHA512, HMAC_SHA512_224, HMAC_SHA512_256,
    HMAC_SHA3_224, HMAC_SHA3_256, HMAC_SHA3_384, HMAC_SHA3_512
} hmac_alg_t;

typedef struct _HMAC_CTX {
    hmac_alg_t alg;
    void *ipad_ctx;
    void *opad_ctx;
    size_t ctx_buf_size;
    size_t ctx_block_size;
    size_t out_len;
    bool (*hash_init)(void*);
    bool (*hash_update)(void*, const uint8_t*, size_t);
    bool (*hash_final)(void*, uint8_t*, size_t);
    bool (*hash_squeeze)(void*, uint8_t*, size_t);
    uint8_t key[512];
    size_t key_len;
    int isFinalized;
    int isHeapAlloc;
} HMAC_CTX;
```

### Functions

| Function | Description |
|----------|-------------|
| `HMAC_Init` | Initialize a pre-allocated HMAC context |
| `HMAC_InitAlloc` | Initialize and allocate a heap HMAC context |
| `HMAC_Update` | Feed data into the HMAC |
| `HMAC_Final` | Finalize HMAC and write digest |
| `HMAC_Free` | Free internal buffers for pre-allocated context |
| `HMAC_FreeAlloc` | Free heap-allocated context |
| `HMAC_Compute` | One-shot HMAC computation |
| `HMAC_CloneCtx` | Clone an existing HMAC context into a destination context |
| `HMAC_CloneCtxAlloc` | Clone an HMAC context into a new heap-allocated context |
| `HMAC_ConstTimeCompareOrder` | Constant-time digest comparison returning ordering (-1,0,+1) |
| `HMAC_DigestSize` | Get the digest size of a hash algorithm |
| `HMAC_Name` | Get the human-readable name of the algorithm |

---

## Example

```c
#include "tiny_hmac.h"
#include <stdio.h>

int main() {
    uint8_t key[] = "secret";
    uint8_t data[] = "hello world";
    uint8_t digest[SHA256_DIGEST_SIZE];

    if(HMAC_Compute(HMAC_SHA256, key, sizeof(key)-1, data, sizeof(data)-1, digest, sizeof(digest))) {
        printf("HMAC-SHA256 computed successfully!\n");
    } else {
        printf("HMAC computation failed\n");
    }
    return 0;
}
```

---

## Sources

- [RFC 6234 – US Secure Hash Algorithms (SHA and SHA‑based HMAC and HKDF), May 2011](https://datatracker.ietf.org/doc/html/rfc6234)
- [FIPS PUB 202 – SHA‑3 Standard: Permutation-Based Hash and Extendable-Output Functions, August 2015](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)
- [RFC 5869 – HMAC-based Extract-and-Expand Key Derivation Function (HKDF), May 2010](https://datatracker.ietf.org/doc/html/rfc5869)

---

## License

This project is released under the **MIT License**. See [LICENSE](LICENSE) for full text.

