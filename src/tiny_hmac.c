#define TINY_HMAC_IMPLEMENTATION

#include "tiny_hmac.h"

#ifdef TINY_HMAC_IMPLEMENTATION

static FORCE_INLINE int is_sha3(int id) {
#if ENABLE_SHA3_224
    if (id == HMAC_SHA3_224) return 1;
#endif
#if ENABLE_SHA3_256
    if (id == HMAC_SHA3_256) return 1;
#endif
#if ENABLE_SHA3_384
    if (id == HMAC_SHA3_384) return 1;
#endif
#if ENABLE_SHA3_512
    if (id == HMAC_SHA3_512) return 1;
#endif
    return 0;
}


bool HMAC_Init(HMAC_CTX *ctx, hmac_alg_t alg, const uint8_t *key, size_t key_len) {
    if (!ctx || !key || key_len == 0 || key_len > MAX_HMAC_KEY_SIZE)
        return false;

    ctx->alg = alg;

    switch (alg) {
#if ENABLE_SHA1
        case HMAC_SHA1:
            ctx->out_len = SHA1_DIGEST_SIZE;
            ctx->ipad_ctx = malloc(sizeof(SHA1_CTX));
            ctx->opad_ctx = malloc(sizeof(SHA1_CTX));
            ctx->ctx_buf_size = sizeof(SHA1_CTX);
            ctx->ctx_block_size  = SHA1_BLOCK_SIZE;

            ctx->hash_init   = (bool (*)(void*))SHA1Init;
            ctx->hash_update = (bool (*)(void*, const uint8_t*, size_t))SHA1Update;
            ctx->hash_final  = (bool (*)(void*, uint8_t*, size_t))SHA1Final;
            ctx->hash_squeeze = NULL;  // SHA-1 does not need squeeze
            break;
#endif
#if ENABLE_SHA224
        case HMAC_SHA224:
            ctx->out_len = SHA224_DIGEST_SIZE;
            ctx->ipad_ctx = malloc(sizeof(SHA224_CTX));
            ctx->opad_ctx = malloc(sizeof(SHA224_CTX));
            ctx->ctx_buf_size = sizeof(SHA224_CTX);
            ctx->ctx_block_size  = SHA224_BLOCK_SIZE;

            ctx->hash_init   = (bool (*)(void*))SHA224Init;
            ctx->hash_update = (bool (*)(void*, const uint8_t*, size_t))SHA224Update;
            ctx->hash_final  = (bool (*)(void*, uint8_t*, size_t))SHA224Final;
            ctx->hash_squeeze = NULL;  // SHA-2 does not need squeeze
            break;
#endif
#if ENABLE_SHA256
        case HMAC_SHA256:
            ctx->out_len = SHA256_DIGEST_SIZE;
            ctx->ipad_ctx = malloc(sizeof(SHA256_CTX));
            ctx->opad_ctx = malloc(sizeof(SHA256_CTX));
            ctx->ctx_buf_size = sizeof(SHA256_CTX);
            ctx->ctx_block_size  = SHA256_BLOCK_SIZE;

            ctx->hash_init   = (bool (*)(void*))SHA256Init;
            ctx->hash_update = (bool (*)(void*, const uint8_t*, size_t))SHA256Update;
            ctx->hash_final  = (bool (*)(void*, uint8_t*, size_t))SHA256Final;
            ctx->hash_squeeze = NULL;  // SHA-2 does not need squeeze
            break;
#endif
#if ENABLE_SHA384
        case HMAC_SHA384:
            ctx->out_len = SHA384_DIGEST_SIZE;
            ctx->ipad_ctx = malloc(sizeof(SHA384_CTX));
            ctx->opad_ctx = malloc(sizeof(SHA384_CTX));
            ctx->ctx_buf_size = sizeof(SHA384_CTX);
            ctx->ctx_block_size  = SHA384_BLOCK_SIZE;

            ctx->hash_init   = (bool (*)(void*))SHA384Init;
            ctx->hash_update = (bool (*)(void*, const uint8_t*, size_t))SHA384Update;
            ctx->hash_final  = (bool (*)(void*, uint8_t*, size_t))SHA384Final;
            ctx->hash_squeeze = NULL;  // SHA-2 does not need squeeze
            break;
#endif
#if ENABLE_SHA512
        case HMAC_SHA512:
            ctx->out_len = SHA512_DIGEST_SIZE;
            ctx->ipad_ctx = malloc(sizeof(SHA512_CTX));
            ctx->opad_ctx = malloc(sizeof(SHA512_CTX));
            ctx->ctx_buf_size = sizeof(SHA512_CTX);
            ctx->ctx_block_size  = SHA512_BLOCK_SIZE;

            ctx->hash_init   = (bool (*)(void*))SHA512Init;
            ctx->hash_update = (bool (*)(void*, const uint8_t*, size_t))SHA512Update;
            ctx->hash_final  = (bool (*)(void*, uint8_t*, size_t))SHA512Final;
            ctx->hash_squeeze = NULL;  // SHA-2 does not need squeeze
            break;
#endif
#if ENABLE_SHA512_224
        case HMAC_SHA512_224:
            ctx->out_len = SHA512_224_DIGEST_SIZE;
            ctx->ipad_ctx = malloc(sizeof(SHA512_224_CTX));
            ctx->opad_ctx = malloc(sizeof(SHA512_224_CTX));
            ctx->ctx_buf_size = sizeof(SHA512_224_CTX);
            ctx->ctx_block_size  = SHA512_224_BLOCK_SIZE;

            ctx->hash_init   = (bool (*)(void*))SHA512_224Init;
            ctx->hash_update = (bool (*)(void*, const uint8_t*, size_t))SHA512_224Update;
            ctx->hash_final  = (bool (*)(void*, uint8_t*, size_t))SHA512_224Final;
            ctx->hash_squeeze = NULL;  // SHA-2 does not need squeeze
            break;
#endif
#if ENABLE_SHA512_256
        case HMAC_SHA512_256:
            ctx->out_len = SHA512_256_DIGEST_SIZE;
            ctx->ipad_ctx = malloc(sizeof(SHA512_256_CTX));
            ctx->opad_ctx = malloc(sizeof(SHA512_256_CTX));
            ctx->ctx_buf_size = sizeof(SHA512_256_CTX);
            ctx->ctx_block_size  = SHA512_256_BLOCK_SIZE;

            ctx->hash_init   = (bool (*)(void*))SHA512_256Init;
            ctx->hash_update = (bool (*)(void*, const uint8_t*, size_t))SHA512_256Update;
            ctx->hash_final  = (bool (*)(void*, uint8_t*, size_t))SHA512_256Final;
            ctx->hash_squeeze = NULL;  // SHA-2 does not need squeeze
            break;
#endif
#if ENABLE_SHA3_224
        case HMAC_SHA3_224:
            ctx->out_len = SHA3_224_DIGEST_SIZE;
            ctx->ipad_ctx = malloc(sizeof(SHA3_224_CTX));
            ctx->opad_ctx = malloc(sizeof(SHA3_224_CTX));
            ctx->ctx_buf_size = sizeof(SHA3_224_CTX);
            ctx->ctx_block_size  = SHA3_224_BLOCK_SIZE;

            ctx->hash_init   = (bool (*)(void*))SHA3_224Init;
            ctx->hash_update = (bool (*)(void*, const uint8_t*, size_t))SHA3_224Absorb;
            ctx->hash_final  = (bool (*)(void*, uint8_t*, size_t))SHA3_224Final;
            ctx->hash_squeeze = (bool (*)(void*, uint8_t*, size_t))SHA3_224Squeeze;
            break;
#endif
#if ENABLE_SHA3_256
        case HMAC_SHA3_256:
            ctx->out_len = SHA3_256_DIGEST_SIZE;
            ctx->ipad_ctx = malloc(sizeof(SHA3_256_CTX));
            ctx->opad_ctx = malloc(sizeof(SHA3_256_CTX));
            ctx->ctx_buf_size = sizeof(SHA3_256_CTX);
            ctx->ctx_block_size  = SHA3_256_BLOCK_SIZE;

            ctx->hash_init   = (bool (*)(void*))SHA3_256Init;
            ctx->hash_update = (bool (*)(void*, const uint8_t*, size_t))SHA3_256Absorb;
            ctx->hash_final  = (bool (*)(void*, uint8_t*, size_t))SHA3_256Final;
            ctx->hash_squeeze = (bool (*)(void*, uint8_t*, size_t))SHA3_256Squeeze;
            break;
#endif
#if ENABLE_SHA3_384
        case HMAC_SHA3_384:
            ctx->out_len = SHA3_384_DIGEST_SIZE;
            ctx->ipad_ctx = malloc(sizeof(SHA3_384_CTX));
            ctx->opad_ctx = malloc(sizeof(SHA3_384_CTX));
            ctx->ctx_buf_size = sizeof(SHA3_384_CTX);
            ctx->ctx_block_size  = SHA3_384_BLOCK_SIZE;

            ctx->hash_init   = (bool (*)(void*))SHA3_384Init;
            ctx->hash_update = (bool (*)(void*, const uint8_t*, size_t))SHA3_384Absorb;
            ctx->hash_final  = (bool (*)(void*, uint8_t*, size_t))SHA3_384Final;
            ctx->hash_squeeze = (bool (*)(void*, uint8_t*, size_t))SHA3_384Squeeze;
            break;
#endif
#if ENABLE_SHA3_512
        case HMAC_SHA3_512:
            ctx->out_len = SHA3_512_DIGEST_SIZE;
            ctx->ipad_ctx = malloc(sizeof(SHA3_512_CTX));
            ctx->opad_ctx = malloc(sizeof(SHA3_512_CTX));
            ctx->ctx_buf_size = sizeof(SHA3_512_CTX);
            ctx->ctx_block_size  = SHA3_512_BLOCK_SIZE;

            ctx->hash_init   = (bool (*)(void*))SHA3_512Init;
            ctx->hash_update = (bool (*)(void*, const uint8_t*, size_t))SHA3_512Absorb;
            ctx->hash_final  = (bool (*)(void*, uint8_t*, size_t))SHA3_512Final;
            ctx->hash_squeeze = (bool (*)(void*, uint8_t*, size_t))SHA3_512Squeeze;
            break;
#endif
        default:
            return false;
    }

    if (!ctx->ipad_ctx || !ctx->opad_ctx)
        return false;

    // normalize key
    if (key_len > ctx->ctx_block_size) {
        if (!ctx->hash_init(ctx->ipad_ctx) ||
            !ctx->hash_update(ctx->ipad_ctx, key, key_len) ||
            !ctx->hash_final(ctx->ipad_ctx, ctx->key, ctx->out_len)) {
            goto cleanup;
        }
        if (ctx->hash_squeeze && !ctx->hash_squeeze(ctx->ipad_ctx, ctx->key, ctx->out_len))
            goto cleanup;

        key_len = ctx->out_len;
    } else {
        // copy short key
        memcpy(ctx->key, key, key_len);
    }

    if (key_len < ctx->ctx_block_size)
        memset(ctx->key + key_len, 0, ctx->ctx_block_size - key_len);
    ctx->key_len = ctx->ctx_block_size;

    // apply XOR pads
    uint8_t ipad[MAX_HMAC_BLOCK_SIZE], opad[MAX_HMAC_BLOCK_SIZE];
    for (size_t i = 0; i < ctx->ctx_block_size; i++) {
        ipad[i] = ctx->key[i] ^ 0x36;
        opad[i] = ctx->key[i] ^ 0x5c;
    }

    // init hash contexts and feed pads
    if (!ctx->hash_init(ctx->ipad_ctx) ||
        !ctx->hash_init(ctx->opad_ctx))
        goto cleanup;

    if (!ctx->hash_update(ctx->ipad_ctx, ipad, ctx->ctx_block_size) ||
        !ctx->hash_update(ctx->opad_ctx, opad, ctx->ctx_block_size))
        goto cleanup;

    memset(ipad, 0, MAX_HMAC_BLOCK_SIZE);
    memset(opad, 0, MAX_HMAC_BLOCK_SIZE);

    ctx->isHeapAlloc = 0;
    ctx->isFinalized = 0;
    return true;

cleanup:
    if (ctx->ipad_ctx) {
        memset(ctx->ipad_ctx, 0, ctx->ctx_buf_size);
        free(ctx->ipad_ctx);
        ctx->ipad_ctx == NULL;
    }

    if (ctx->opad_ctx) {
        memset(ctx->opad_ctx, 0, ctx->ctx_buf_size);
        free(ctx->opad_ctx);
        ctx->opad_ctx == NULL;
    }

    return false;
}

HMAC_CTX* HMAC_InitAlloc(hmac_alg_t alg, const uint8_t *key, size_t key_len) {
    HMAC_CTX *ctx = (HMAC_CTX *)calloc(1, sizeof(HMAC_CTX));
    if (!ctx) {
        return NULL;
    }

    bool st = HMAC_Init(ctx, alg, key, key_len);
    if (st != true) {
        free(ctx);
        ctx == NULL;
        return NULL;
    }

    ctx->isHeapAlloc = 1;
    return ctx;
}

bool HMAC_Update(HMAC_CTX *ctx, const uint8_t *data, size_t data_len) {
    if (!ctx || !ctx->ipad_ctx || (data_len > 0 && !data) || ctx->isFinalized || data_len == 0)
        return false;

    if (!ctx->hash_update(ctx->ipad_ctx, data, data_len))
        return false;

    return true;
}

bool HMAC_Final(HMAC_CTX *ctx, uint8_t *digest, size_t digest_len) {
    if (!ctx || !ctx->ipad_ctx || !ctx->opad_ctx || !digest ||
        (digest_len == 0 && ctx->out_len == 0) || ctx->isFinalized)
        return false;

    const size_t hash_len = ctx->out_len;
    uint8_t inner_hash[MAX_HMAC_DIGEST_SIZE];

    // compute inner hash
    if (!ctx->hash_final(ctx->ipad_ctx, inner_hash, ctx->out_len))
        return false;

    // For SHA3 variants that require squeezing
    if (ctx->hash_squeeze && is_sha3(ctx->alg)) {
        if (!ctx->hash_squeeze(ctx->ipad_ctx, inner_hash, ctx->out_len))
            return false;
    }

    // feed inner hash into opad context
    if (!ctx->hash_update(ctx->opad_ctx, inner_hash, ctx->out_len))
        return false;

    // compute final HMAC
    if (!ctx->hash_final(ctx->opad_ctx, digest, hash_len))
        return false;

    // For SHA3 variants that require squeezing
    if (ctx->hash_squeeze && is_sha3(ctx->alg)) {
        if (!ctx->hash_squeeze(ctx->opad_ctx, digest, hash_len))
            return false;
    }

    memset(inner_hash, 0, sizeof(inner_hash));
    ctx->isFinalized = 1;

    return true;
}


bool HMAC_Free(HMAC_CTX *ctx) {
    if (!ctx)
        return false;

    // Zero and free inner (ipad) and outer (opad) contexts
    if (ctx->ipad_ctx) {
        memset(ctx->ipad_ctx, 0, ctx->ctx_buf_size);
        free(ctx->ipad_ctx);
        ctx->ipad_ctx = NULL;
    }

    if (ctx->opad_ctx) {
        memset(ctx->opad_ctx, 0, ctx->ctx_buf_size);
        free(ctx->opad_ctx);
        ctx->opad_ctx = NULL;
    }

    // Zero key material and reset fields
    memset(ctx->key, 0, sizeof(ctx->key));
    ctx->key_len = 0;
    ctx->out_len = 0;
    ctx->isFinalized = 0;
    ctx->isHeapAlloc = 0;

    return true;
}

bool HMAC_FreeAlloc(HMAC_CTX **p_ctx) {
    if (!p_ctx || !*p_ctx)
        return false;

    HMAC_CTX *ctx = *p_ctx;
    int wasHeapAlloc = ctx->isHeapAlloc;  // save flag

    // Reuse Free to clean internals
    HMAC_Free(ctx);

    // Free the outer struct if heap-allocated
    if (wasHeapAlloc) {
        memset(ctx, 0, sizeof(HMAC_CTX));
        free(ctx);
        *p_ctx = NULL;
    }

    return true;
}


bool HMAC_CloneCtx(HMAC_CTX *ctx_dest, const HMAC_CTX *ctx_src) {
    if (!ctx_dest || !ctx_src)
        return false;

    // Copy MD pointer
    ctx_dest->alg = ctx_src->alg;

    // Copy the inner and outer contexts as raw memory
    if (ctx_src->ctx_buf_size > 0) {
        // Free existing destination buffers if allocated
        if (ctx_dest->ipad_ctx) {
            memset(ctx_dest->ipad_ctx, 0, ctx_src->ctx_buf_size);
            free(ctx_dest->ipad_ctx);
            ctx_dest->ipad_ctx = NULL;
        }
        if (ctx_dest->opad_ctx) {
            memset(ctx_dest->opad_ctx, 0, ctx_src->ctx_buf_size);
            free(ctx_dest->opad_ctx);
            ctx_dest->opad_ctx = NULL;
        }

        // Allocate new memory for destination
        ctx_dest->ipad_ctx = calloc(1, ctx_src->ctx_buf_size);
        ctx_dest->opad_ctx = calloc(1, ctx_src->ctx_buf_size);
        if (!ctx_dest->ipad_ctx || !ctx_dest->opad_ctx)
            return false;

        // Copy the memory from source
        memcpy(ctx_dest->ipad_ctx, ctx_src->ipad_ctx, ctx_src->ctx_buf_size);
        memcpy(ctx_dest->opad_ctx, ctx_src->opad_ctx, ctx_src->ctx_buf_size);
    }

    // Copy simple fields
    memcpy(ctx_dest->key, ctx_src->key, ctx_src->key_len);
    ctx_dest->key_len     = ctx_src->key_len;
    ctx_dest->out_len     = ctx_src->out_len;
    ctx_dest->isFinalized = ctx_src->isFinalized;
    ctx_dest->isHeapAlloc = 0; // pre-allocated, no dynamic memory inside

    return true;
}

HMAC_CTX *HMAC_CloneCtxAlloc(const HMAC_CTX *ctx_src) {
    if (!ctx_src) {
        return NULL;
    }

    // Allocate the destination context
    HMAC_CTX *ctx_dest = (HMAC_CTX *)calloc(1, sizeof(HMAC_CTX));
    if (!ctx_dest) {
        return NULL;
    }

    // Use the in-place clone function
    bool ret = HMAC_CloneCtx(ctx_dest, ctx_src);
    if (ret != true) {
        memset(ctx_dest, 0, sizeof(ctx_dest));
        free(ctx_dest);
        return NULL;
    }

    // Mark as heap-allocated
    ctx_dest->isHeapAlloc = 1;

    return ctx_dest;
}

#endif // TINY_HMAC_IMPLEMENTATION