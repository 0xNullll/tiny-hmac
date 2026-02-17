/*
 * File: tiny_hmac.h
 * Author: 0xNullll
 * Description: This header provides the public interface for the Tiny HMAC library.
 *              It defines context structs, function prototypes, feature flags,
 *              and inline helpers for computing HMACs using all SHA and SHA-3 variants
 *              provided by the Tiny SHA library:
 *              SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256,
 *              as well as SHA3-224, SHA3-256, SHA3-384, SHA3-512.
 *              Supports one-shot HMAC computation, incremental update/finalize,
 *              context cloning, optional heap allocation, and constant-time digest comparison.
 *              Implementation is in tiny_hmac.c.
 * License: MIT
 */


#ifndef TINY_HMAC_H
#define TINY_HMAC_H

#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _MSC_VER
#define FORCE_INLINE __forceinline
#else
#define FORCE_INLINE inline __attribute__((always_inline))
#endif

#if (defined(_WIN32) || defined(_WIN64)) && !defined(__MINGW32__)
# define U64(C) C##UI64
#elif defined(__arch64__)
# define U64(C) C##UL
#else
# define U64(C) C##ULL
#endif

/* ------------------------
   Feature Flags
   Users can define these as 0 (disable) or 1 (enable)
   before including the header, or via compiler -D flags.
   ------------------------ */

/* ------------------------
   SHA-1 / SHA-2 variants
   ------------------------ */
#ifndef ENABLE_SHA1
#define ENABLE_SHA1 1          /* enable SHA-1 by default */
#endif

#ifndef ENABLE_SHA224
#define ENABLE_SHA224 1        /* enable SHA-224 by default */
#endif

#ifndef ENABLE_SHA256
#define ENABLE_SHA256 1        /* enable SHA-256 by default */
#endif

#ifndef ENABLE_SHA384
#define ENABLE_SHA384 1        /* enable SHA-384 by default */
#endif

#ifndef ENABLE_SHA512
#define ENABLE_SHA512 1        /* enable SHA-512 by default */
#endif

#ifndef ENABLE_SHA512_224
#define ENABLE_SHA512_224 1    /* enable SHA-512/224 by default */
#endif

#ifndef ENABLE_SHA512_256
#define ENABLE_SHA512_256 1    /* enable SHA-512/256 by default */
#endif

/* ------------------------
   SHA-3 variants
   ------------------------ */
#ifndef ENABLE_SHA3_224
#define ENABLE_SHA3_224 1      /* enable SHA3-224 by default */
#endif

#ifndef ENABLE_SHA3_256
#define ENABLE_SHA3_256 1      /* enable SHA3-256 by default */
#endif

#ifndef ENABLE_SHA3_384
#define ENABLE_SHA3_384 1      /* enable SHA3-384 by default */
#endif

#ifndef ENABLE_SHA3_512
#define ENABLE_SHA3_512 1      /* enable SHA3-512 by default */
#endif

/* ------------------------
   Function name prefix support
   ------------------------ */
#ifndef TSHASH_PREFIX
#define TSHASH_PREFIX /* empty by default */
#endif

#define _TS_CAT(a,b) a##b
#define _TS_CAT2(a,b) _TS_CAT(a,b)
#define TSHASH_FN(name) _TS_CAT2(TSHASH_PREFIX, name)

#include "../tiny-sha/src/tiny_sha.h"

typedef enum {
#if ENABLE_SHA1
    HMAC_SHA1,
#endif
#if ENABLE_SHA224
    HMAC_SHA224,
#endif
#if ENABLE_SHA256
    HMAC_SHA256,
#endif
#if ENABLE_SHA384
    HMAC_SHA384,
#endif
#if ENABLE_SHA512
    HMAC_SHA512,
#endif
#if ENABLE_SHA512_224
    HMAC_SHA512_224,
#endif
#if ENABLE_SHA512_256
    HMAC_SHA512_256,
#endif
#if ENABLE_SHA3_224
    HMAC_SHA3_224,
#endif
#if ENABLE_SHA3_256
    HMAC_SHA3_256,
#endif
#if ENABLE_SHA3_384
    HMAC_SHA3_384,
#endif
#if ENABLE_SHA3_512
    HMAC_SHA3_512,
#endif
} hmac_alg_t;

// ============================
// HMAC context structure
// ============================
#define MAX_HMAC_KEY_SIZE 512
#define MAX_HMAC_BLOCK_SIZE 144
#define MAX_HMAC_DIGEST_SIZE 64

typedef struct _HMAC_CTX {
    hmac_alg_t alg;           // Selected hash algorithm
    void *ipad_ctx;           // Inner hash state/context
    void *opad_ctx;           // Outer hash state/context
    size_t ctx_buf_size;      // Size of the allocated hash context buffer
    size_t ctx_block_size;
    size_t out_len;

    // function pointers for this algorithm
    bool (*hash_init)(void *ctx);
    bool (*hash_update)(void *ctx, const uint8_t *data, size_t len);
    bool (*hash_final)(void *ctx, uint8_t *digest, size_t digest_size);
    bool (*hash_squeeze)(void *ctx, uint8_t *output, size_t outlen);

    uint8_t key[MAX_HMAC_KEY_SIZE];
    size_t key_len;

    int isFinalized;
    int isHeapAlloc; // 1 if allocated by library (heap), 0 if user stack    
} HMAC_CTX;

// ============================
// HMAC low-level function prototypes
// ============================
#define HMAC_Init                       TSHASH_FN(HMAC_Init)
#define HMAC_InitAlloc                  TSHASH_FN(HMAC_InitAlloc)
#define HMAC_Update                     TSHASH_FN(HMAC_Update)
#define HMAC_Final                      TSHASH_FN(HMAC_Final)
#define HMAC_Free                       TSHASH_FN(HMAC_Free)
#define HMAC_FreeAlloc                  TSHASH_FN(HMAC_FreeAlloc)
#define HMAC_Compute                    TSHASH_FN(HMAC_Compute)
#define HMAC_CloneCtx                   TSHASH_FN(HMAC_CloneCtx)
#define HMAC_CloneCtxAlloc              TSHASH_FN(HMAC_CloneCtxAlloc)
#define HMAC_DigestSize                 TSHASH_FN(HMAC_DigestSize)
#define HMAC_Name                       TSHASH_FN(HMAC_Name)
#define HMAC_ConstTimeCompare           TSHASH_FN(HMAC_ConstTimeCompare)

bool HMAC_Init(HMAC_CTX *ctx, hmac_alg_t alg, const uint8_t *key, size_t key_len);

HMAC_CTX* HMAC_InitAlloc(hmac_alg_t alg, const uint8_t *key, size_t key_len);

bool HMAC_Update(HMAC_CTX *ctx, const uint8_t *data, size_t data_len);

// Finalizes the HMAC and writes the digest to the output buffer.
// digest_len should be at least the hash's digest_size.
bool HMAC_Final(HMAC_CTX *ctx, uint8_t *digest, size_t digest_len);

// Frees internal buffers of a pre-allocated context
bool HMAC_Free(HMAC_CTX *ctx);

// Frees internal buffers + the heap-allocated context
bool HMAC_FreeAlloc(HMAC_CTX **p_ctx);

// ============================
// HMAC one-shot compute
// ============================
static FORCE_INLINE bool HMAC_Compute(hmac_alg_t alg,
                                const uint8_t *key, size_t key_len,
                                const uint8_t *data, size_t data_len,
                                uint8_t *digest, size_t digest_len) {
    HMAC_CTX ctx;

    // Initialize the HMAC context
    if (!HMAC_Init(&ctx, alg, key, key_len)) {
        return false;
    }

    // Update with data
    if (!HMAC_Update(&ctx, data, data_len)) {
        HMAC_Free(&ctx);
        return false;
    }

    // Finalize and get digest
    if (!HMAC_Final(&ctx, digest, digest_len)) {
        HMAC_Free(&ctx);
        return false;
    }

    // Free internal buffers
    if (!HMAC_Free(&ctx)) {
        return false;
    }

    return true;
}

// Clone HMAC context into an existing destination context
bool HMAC_CloneCtx(HMAC_CTX *ctx_dest, const HMAC_CTX *ctx_src);

// Clone HMAC context and allocate a new heap context
HMAC_CTX *HMAC_CloneCtxAlloc(const HMAC_CTX *ctx_src);

static size_t HMAC_DigestSize(hmac_alg_t alg) {
    switch (alg) {
#if ENABLE_SHA1
        case HMAC_SHA1:     return SHA1_DIGEST_SIZE;
#endif
#if ENABLE_SHA224
        case HMAC_SHA224:   return SHA224_DIGEST_SIZE;
#endif
#if ENABLE_SHA256
        case HMAC_SHA256:   return SHA256_DIGEST_SIZE;
#endif
#if ENABLE_SHA384
        case HMAC_SHA384:   return SHA384_DIGEST_SIZE;
#endif
#if ENABLE_SHA512
        case HMAC_SHA512:   return SHA512_DIGEST_SIZE;
#endif
#if ENABLE_SHA512_224
        case HMAC_SHA512_224:   return SHA512_224_DIGEST_SIZE;
#endif
#if ENABLE_SHA512_256
        case HMAC_SHA512_256:   return SHA512_256_DIGEST_SIZE;
#endif
#if ENABLE_SHA3_224
        case HMAC_SHA3_224: return SHA3_224_DIGEST_SIZE;
#endif
#if ENABLE_SHA3_256
        case HMAC_SHA3_256: return SHA3_256_DIGEST_SIZE;
#endif
#if ENABLE_SHA3_384
        case HMAC_SHA3_384: return SHA3_384_DIGEST_SIZE;
#endif
#if ENABLE_SHA3_512
        case HMAC_SHA3_512: return SHA3_512_DIGEST_SIZE;
#endif
        default:
            return 0;
    }
}

static const char* HMAC_Name(hmac_alg_t alg) {
    switch (alg) {
#if ENABLE_SHA1
        case HMAC_SHA1:     return "HMAC-SHA1";
#endif
#if ENABLE_SHA224
        case HMAC_SHA224:   return "HMAC-SHA224";
#endif
#if ENABLE_SHA256
        case HMAC_SHA256:   return "HMAC-SHA256";
#endif
#if ENABLE_SHA384
        case HMAC_SHA384:   return "HMAC-SHA384";
#endif
#if ENABLE_SHA512
        case HMAC_SHA512:   return "HMAC-SHA512";
#endif
#if ENABLE_SHA512_224
        case HMAC_SHA512_224:   return "HMAC-SHA512-224";
#endif
#if ENABLE_SHA512_256
        case HMAC_SHA512_256:   return "HMAC-SHA512-256";
#endif
#if ENABLE_SHA3_224
        case HMAC_SHA3_224: return "HMAC-SHA3-224";
#endif
#if ENABLE_SHA3_256
        case HMAC_SHA3_256: return "HMAC-SHA3-256";
#endif
#if ENABLE_SHA3_384
        case HMAC_SHA3_384: return "HMAC-SHA3-384";
#endif
#if ENABLE_SHA3_512
        case HMAC_SHA3_512: return "HMAC-SHA3-512";
#endif
        default:
            return "UNKNOWN";
    }
}

/* ------------------------------------------------------------------
 * Constant-Time Equality Comparator
 * Compares two byte buffers in constant time to prevent timing attacks.
 *
 * Parameters:
 *  - a: pointer to first buffer
 *  - b: pointer to second buffer
 *  - alg: HMAC algorithm (used to determine digest length)
 *
 * Returns:
 *  - 1 if buffers are equal
 *  - 0 if buffers differ or if a/b are NULL
 *
 * Notes:
 *  - Entire buffer is scanned regardless of differences (no early return)
 *  - Uses bitwise operations only, safe against timing attacks
 *  - Includes compiler-specific memory barriers to prevent optimization
 * ------------------------------------------------------------------ */
static int HMAC_ConstTimeCompare(const uint8_t *a, const uint8_t *b, hmac_alg_t alg) {
    if (!a || !b) return 0;

    size_t len = HMAC_DigestSize(alg);
    if (len == 0) return 1;

    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }

#if defined(__GNUC__) || defined(__clang__)
    __asm__ volatile("" : "+r"(diff) : : "memory");
#elif defined(_MSC_VER)
    _ReadWriteBarrier();
#else
    (void)diff;
#endif

    return diff == 0;
}

#ifdef __cplusplus
}
#endif

#endif // TINY_HMAC_H