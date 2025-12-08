#include <stdio.h>
#include "tiny_hmac.h"

// Print hex
static void print_hex(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++)
        printf("%02x", buf[i]);
    printf("\n");
}

// Structure describing one testable algorithm
typedef struct {
    uint32_t id;
    bool enabled;
} AlgoInfo;

// Build a table automatically based on your flags
static const AlgoInfo algos[] = {
#if ENABLE_SHA1
    { HMAC_SHA1, true },
#endif
#if ENABLE_SHA224
    { HMAC_SHA224, true },
#endif
#if ENABLE_SHA256
    { HMAC_SHA256, true },
#endif
#if ENABLE_SHA384
    { HMAC_SHA384, true },
#endif
#if ENABLE_SHA512
    { HMAC_SHA512, true },
#endif
#if ENABLE_SHA512_224
    { HMAC_SHA512_224, true },
#endif
#if ENABLE_SHA512_256
    { HMAC_SHA512_256, true },
#endif
#if ENABLE_SHA3_224
    { HMAC_SHA3_224, true },
#endif
#if ENABLE_SHA3_256
    { HMAC_SHA3_256, true },
#endif
#if ENABLE_SHA3_384
    { HMAC_SHA3_384, true },
#endif
#if ENABLE_SHA3_512
    { HMAC_SHA3_512, true },
#endif
};

static const size_t algo_count = sizeof(algos) / sizeof(algos[0]);

int main(int argc, char **argv) {
    if (argc < 3) {
        printf("Usage: %s <key> <message>\n", argv[0]);
        return 1;
    }


    const uint8_t *key = (const uint8_t *)argv[1];
    const uint8_t *msg = (const uint8_t *)argv[2];

    size_t key_len = strlen(argv[1]);
    size_t msg_len = strlen(argv[2]);

    uint8_t out[MAX_HMAC_DIGEST_SIZE];
    size_t out_len = 0;

    printf("=== Tiny HMAC Test ===\n");
    printf("Key: \"%s\" (%zu)\n", key, key_len);
    printf("Msg: \"%s\" (%zu)\n\n", msg, msg_len);

    for (size_t i = 0; i < algo_count; i++) {
        const AlgoInfo *A = &algos[i];
        if (!A->enabled)
            continue;

        printf("[%s] ", HMAC_Name(A->id));
        out_len = HMAC_DigestSize(A->id);

        if (!HMAC_Compute(A->id, key, key_len, msg, msg_len, out, out_len)) {
            printf("FAILED\n");
            continue;
        }

        printf("(%zu bytes): ", out_len);
        print_hex(out, out_len);
    }

    return 0;
}