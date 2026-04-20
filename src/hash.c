#include "bloomd.h"

#include <string.h>

static uint64_t bloomd_rotl64(uint64_t x, unsigned bits) {
    return (x << bits) | (x >> (64U - bits));
}

static uint64_t bloomd_load64_le(const uint8_t *src) {
    uint64_t out = 0;

    for (size_t i = 0; i < 8; ++i) {
        out |= ((uint64_t)src[i] << (8U * i));
    }
    return out;
}

static void bloomd_store64_le(uint8_t *dst, uint64_t value) {
    for (size_t i = 0; i < 8; ++i) {
        dst[i] = (uint8_t)((value >> (8U * i)) & 0xffU);
    }
}

static inline void bloomd_sipround(uint64_t *v0, uint64_t *v1, uint64_t *v2, uint64_t *v3) {
    *v0 += *v1;
    *v1 = bloomd_rotl64(*v1, 13);
    *v1 ^= *v0;
    *v0 = bloomd_rotl64(*v0, 32);
    *v2 += *v3;
    *v3 = bloomd_rotl64(*v3, 16);
    *v3 ^= *v2;
    *v0 += *v3;
    *v3 = bloomd_rotl64(*v3, 21);
    *v3 ^= *v0;
    *v2 += *v1;
    *v1 = bloomd_rotl64(*v1, 17);
    *v1 ^= *v2;
    *v2 = bloomd_rotl64(*v2, 32);
}

static uint64_t bloomd_tail64(const uint8_t *data, size_t len) {
    uint64_t out = ((uint64_t)len) << 56;

    switch (len & 7U) {
    case 7:
        out |= ((uint64_t)data[6] << 48);
        __attribute__((fallthrough));
    case 6:
        out |= ((uint64_t)data[5] << 40);
        __attribute__((fallthrough));
    case 5:
        out |= ((uint64_t)data[4] << 32);
        __attribute__((fallthrough));
    case 4:
        out |= ((uint64_t)data[3] << 24);
        __attribute__((fallthrough));
    case 3:
        out |= ((uint64_t)data[2] << 16);
        __attribute__((fallthrough));
    case 2:
        out |= ((uint64_t)data[1] << 8);
        __attribute__((fallthrough));
    case 1:
        out |= data[0];
        __attribute__((fallthrough));
    default:
        break;
    }
    return out;
}

static void bloomd_siphash128_dual(const uint8_t *data, size_t len, uint64_t k0, uint64_t k1,
                                   uint64_t k2, uint64_t k3, uint64_t *lo_out, uint64_t *hi_out) {
    uint64_t a0 = UINT64_C(0x736f6d6570736575) ^ k0;
    uint64_t a1 = UINT64_C(0x646f72616e646f6d) ^ k1;
    uint64_t a2 = UINT64_C(0x6c7967656e657261) ^ k0;
    uint64_t a3 = UINT64_C(0x7465646279746573) ^ k1;
    uint64_t b0 = UINT64_C(0x736f6d6570736575) ^ k2;
    uint64_t b1 = UINT64_C(0x646f72616e646f6d) ^ k3;
    uint64_t b2 = UINT64_C(0x6c7967656e657261) ^ k2;
    uint64_t b3 = UINT64_C(0x7465646279746573) ^ k3;
    const uint8_t *end = data + (len & ~((size_t)7));
    uint64_t final;

    while (data != end) {
        uint64_t m = bloomd_load64_le(data);

        a3 ^= m;
        b3 ^= m;
        bloomd_sipround(&a0, &a1, &a2, &a3);
        bloomd_sipround(&b0, &b1, &b2, &b3);
        bloomd_sipround(&a0, &a1, &a2, &a3);
        bloomd_sipround(&b0, &b1, &b2, &b3);
        a0 ^= m;
        b0 ^= m;
        data += 8;
    }

    final = bloomd_tail64(data, len);
    a3 ^= final;
    b3 ^= final;
    bloomd_sipround(&a0, &a1, &a2, &a3);
    bloomd_sipround(&b0, &b1, &b2, &b3);
    bloomd_sipround(&a0, &a1, &a2, &a3);
    bloomd_sipround(&b0, &b1, &b2, &b3);
    a0 ^= final;
    b0 ^= final;
    a2 ^= 0xffU;
    b2 ^= 0xffU;
    bloomd_sipround(&a0, &a1, &a2, &a3);
    bloomd_sipround(&b0, &b1, &b2, &b3);
    bloomd_sipround(&a0, &a1, &a2, &a3);
    bloomd_sipround(&b0, &b1, &b2, &b3);
    bloomd_sipround(&a0, &a1, &a2, &a3);
    bloomd_sipround(&b0, &b1, &b2, &b3);
    bloomd_sipround(&a0, &a1, &a2, &a3);
    bloomd_sipround(&b0, &b1, &b2, &b3);
    *lo_out = a0 ^ a1 ^ a2 ^ a3;
    *hi_out = b0 ^ b1 ^ b2 ^ b3;
}

void bloomd_digest_payload(const void *data, size_t len, uint8_t out[BLOOMD_DIGEST_SIZE]) {
    static const uint64_t k0 = UINT64_C(0x0706050403020100);
    static const uint64_t k1 = UINT64_C(0x0f0e0d0c0b0a0908);
    static const uint64_t k2 = UINT64_C(0x1716151413121110);
    static const uint64_t k3 = UINT64_C(0x1f1e1d1c1b1a1918);
    uint64_t lo;
    uint64_t hi;

    bloomd_siphash128_dual(data, len, k0, k1, k2, k3, &lo, &hi);
    bloomd_store64_le(out, lo);
    bloomd_store64_le(out + 8, hi);
}
