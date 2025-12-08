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

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4054 4055) // for pointer conversion
#elif defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-function-type"
#endif


static const struct _HMAC_TABLE{
    hmac_alg_t alg;
    size_t digest_size;
    size_t block_size;
    size_t ctx_size;
    bool (*hash_init)(void*);
    bool (*hash_update)(void*, const uint8_t*, size_t);
    bool (*hash_final)(void*, uint8_t*, size_t);
    bool (*hash_squeeze)(void*, uint8_t*, size_t);
} HMAC_TABLE[] = {
#if ENABLE_SHA1
    { HMAC_SHA1, SHA1_DIGEST_SIZE, SHA1_BLOCK_SIZE, sizeof(SHA1_CTX),
      (bool(*)(void*))SHA1Init,
      (bool(*)(void*, const uint8_t*, size_t))SHA1Update,
      (bool(*)(void*, uint8_t*, size_t))SHA1Final,
      NULL },
#endif

#if ENABLE_SHA224
    { HMAC_SHA224, SHA224_DIGEST_SIZE, SHA224_BLOCK_SIZE, sizeof(SHA224_CTX),
      (bool(*)(void*))SHA224Init,
      (bool(*)(void*, const uint8_t*, size_t))SHA224Update,
      (bool(*)(void*, uint8_t*, size_t))SHA224Final,
      NULL },
#endif

#if ENABLE_SHA256
    { HMAC_SHA256, SHA256_DIGEST_SIZE, SHA256_BLOCK_SIZE, sizeof(SHA256_CTX),
      (bool(*)(void*))SHA256Init,
      (bool(*)(void*, const uint8_t*, size_t))SHA256Update,
      (bool(*)(void*, uint8_t*, size_t))SHA256Final,
      NULL },
#endif

#if ENABLE_SHA384
    { HMAC_SHA384, SHA384_DIGEST_SIZE, SHA384_BLOCK_SIZE, sizeof(SHA384_CTX),
      (bool(*)(void*))SHA384Init,
      (bool(*)(void*, const uint8_t*, size_t))SHA384Update,
      (bool(*)(void*, uint8_t*, size_t))SHA384Final,
      NULL },
#endif

#if ENABLE_SHA512
    { HMAC_SHA512, SHA512_DIGEST_SIZE, SHA512_BLOCK_SIZE, sizeof(SHA512_CTX),
      (bool(*)(void*))SHA512Init,
      (bool(*)(void*, const uint8_t*, size_t))SHA512Update,
      (bool(*)(void*, uint8_t*, size_t))SHA512Final,
      NULL },
#endif

#if ENABLE_SHA512_224
    { HMAC_SHA512_224, SHA512_224_DIGEST_SIZE, SHA512_224_BLOCK_SIZE, sizeof(SHA512_224_CTX),
      (bool(*)(void*))SHA512_224Init,
      (bool(*)(void*, const uint8_t*, size_t))SHA512_224Update,
      (bool(*)(void*, uint8_t*, size_t))SHA512_224Final,
      NULL },
#endif

#if ENABLE_SHA512_256
    { HMAC_SHA512_256, SHA512_256_DIGEST_SIZE, SHA512_256_BLOCK_SIZE, sizeof(SHA512_256_CTX),
      (bool(*)(void*))SHA512_256Init,
      (bool(*)(void*, const uint8_t*, size_t))SHA512_256Update,
      (bool(*)(void*, uint8_t*, size_t))SHA512_256Final,
      NULL },
#endif

#if ENABLE_SHA3_224
    { HMAC_SHA3_224, SHA3_224_DIGEST_SIZE, SHA3_224_BLOCK_SIZE, sizeof(SHA3_224_CTX),
      (bool(*)(void*))SHA3_224Init,
      (bool(*)(void*, const uint8_t*, size_t))SHA3_224Absorb,
      (bool(*)(void*, uint8_t*, size_t))SHA3_224Final,
      (bool(*)(void*, uint8_t*, size_t))SHA3_224Squeeze },
#endif

#if ENABLE_SHA3_256
    { HMAC_SHA3_256, SHA3_256_DIGEST_SIZE, SHA3_256_BLOCK_SIZE, sizeof(SHA3_256_CTX),
      (bool(*)(void*))SHA3_256Init,
      (bool(*)(void*, const uint8_t*, size_t))SHA3_256Absorb,
      (bool(*)(void*, uint8_t*, size_t))SHA3_256Final,
      (bool(*)(void*, uint8_t*, size_t))SHA3_256Squeeze },
#endif

#if ENABLE_SHA3_384
    { HMAC_SHA3_384, SHA3_384_DIGEST_SIZE, SHA3_384_BLOCK_SIZE, sizeof(SHA3_384_CTX),
      (bool(*)(void*))SHA3_384Init,
      (bool(*)(void*, const uint8_t*, size_t))SHA3_384Absorb,
      (bool(*)(void*, uint8_t*, size_t))SHA3_384Final,
      (bool(*)(void*, uint8_t*, size_t))SHA3_384Squeeze },
#endif

#if ENABLE_SHA3_512
    { HMAC_SHA3_512, SHA3_512_DIGEST_SIZE, SHA3_512_BLOCK_SIZE, sizeof(SHA3_512_CTX),
      (bool(*)(void*))SHA3_512Init,
      (bool(*)(void*, const uint8_t*, size_t))SHA3_512Absorb,
      (bool(*)(void*, uint8_t*, size_t))SHA3_512Final,
      (bool(*)(void*, uint8_t*, size_t))SHA3_512Squeeze },
#endif
};

#ifdef _MSC_VER
#pragma warning(pop)
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

// Return pointer to algorithm info or NULL if not found
static const typeof(HMAC_TABLE[0])* HMAC_Lookup(hmac_alg_t alg) {
    size_t count = sizeof(HMAC_TABLE) / sizeof(HMAC_TABLE[0]);
    for (size_t i = 0; i < count; i++) {
        if (HMAC_TABLE[i].alg == alg)
            return &HMAC_TABLE[i];
    }
    return NULL;
}


bool HMAC_Init(HMAC_CTX *ctx, hmac_alg_t alg, const uint8_t *key, size_t key_len) {
    if (!ctx || !key || key_len == 0 || key_len > MAX_HMAC_KEY_SIZE)
        return false;

    const struct _HMAC_TABLE *info = HMAC_Lookup(alg);
    if (!info)
        return false;

    ctx->alg = alg;
    ctx->out_len = info->digest_size;
    ctx->ctx_block_size = info->block_size;
    ctx->ctx_buf_size = info->ctx_size;

    ctx->ipad_ctx = malloc(info->ctx_size);
    ctx->opad_ctx = malloc(info->ctx_size);

    if (!ctx->ipad_ctx || !ctx->opad_ctx)
        return false;

    ctx->hash_init    = info->hash_init;
    ctx->hash_update  = info->hash_update;
    ctx->hash_final   = info->hash_final;
    ctx->hash_squeeze = info->hash_squeeze;

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
        ctx->ipad_ctx = NULL;
    }

    if (ctx->opad_ctx) {
        memset(ctx->opad_ctx, 0, ctx->ctx_buf_size);
        free(ctx->opad_ctx);
        ctx->opad_ctx = NULL;
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
        ctx = NULL;
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
        memset(ctx_dest, 0, sizeof(*ctx_dest));
        free(ctx_dest);
        return NULL;
    }

    // Mark as heap-allocated
    ctx_dest->isHeapAlloc = 1;

    return ctx_dest;
}

#endif // TINY_HMAC_IMPLEMENTATION