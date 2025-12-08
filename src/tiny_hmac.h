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
#define HMAC_ConstTimeCompareOrder      TSHASH_FN(HMAC_ConstTimeCompareOrder)
#define HMAC_DigestSize                 TSHASH_FN(HMAC_DigestSize)
#define HMAC_Name                       TSHASH_FN(HMAC_Name)

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

/* ------------------------------------------------------------------
 * Constant Time lexicographic comparator
 * Returns: -1 if a < b, 0 if a == b, +1 if a > b
 *
 * Notes:
 *  - Scans the whole buffer (no early return).
 *  - Uses only integer/bit ops; no data-dependent branches.
 *  - Works for any length up to size_t.
 * ------------------------------------------------------------------ */
static FORCE_INLINE int HMAC_ConstTimeCompareOrder(const uint8_t *a, const uint8_t *b, hmac_alg_t alg) {
    if (!a || !b)
        return 0;

        /* this function record whether it had already seen a difference (seen),
        * and record whether that first difference indicated a<b (lt)
        * or a>b (gt).  At the end result = gt - lt -> {1,0,-1}. */
        size_t len = HMAC_DigestSize(alg);
        if (len == 0) return 0;
        
        uint32_t lt = 0;
        uint32_t gt = 0;
        uint32_t seen = 0;
        
        for (size_t i = 0; i < len; ++i) {
                /* Work with zero-extended 16-bit values to compute borrow on subtraction:
                * If ai < bi then (uint16_t)(ai - bi) will underflow and its top bit (bit 15)
                * will be 1. */
                uint16_t ai = (uint16_t)a[i];
                uint16_t bi = (uint16_t)b[i];

                uint16_t d1 = (uint16_t)(ai - bi); /* top bit 1 if ai < bi */
                uint16_t d2 = (uint16_t)(bi - ai); /* top bit 1 if bi < ai */

                uint32_t is_lt = (uint32_t)(d1 >> 15); /* 1 if ai < bi else 0 */
                uint32_t is_gt = (uint32_t)(d2 >> 15); /* 1 if ai > bi else 0 */

                uint32_t diff = is_lt | is_gt;         /* 1 iff bytes differ at this position */
                uint32_t new_diff_mask = (~seen) & diff; /* 1 iff this is the first differing byte */

                /* Only set lt/gt from the first differing byte; subsequent bytes ignored. */
                lt |= is_lt & new_diff_mask;
                gt |= is_gt & new_diff_mask;

                /* mark we have seen a difference (once set it stays set) */
                seen |= diff;
        }

        /* result: 1 if gt set, -1 if lt set, 0 otherwise.
        * Compute without branching. */
        return (int)gt - (int)lt;
}

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

#ifdef __cplusplus
}
#endif

#endif // TINY_HMAC_H