/* speck.c */
#include "speck.h"

/* 64-bit circular rotates */
static inline uint64_t rotr64(uint64_t x, unsigned r) {
  return (x >> r) | (x << (64 - r));
}
static inline uint64_t rotl64(uint64_t x, unsigned r) {
  return (x << r) | (x >> (64 - r));
}

/* One SPECK encryption round; updates (x,y) with round key k */
#define R(x,y,k)   \
  do {             \
    x = rotr64(x, 8);     \
    x = x + y;            \
    x = x ^ (k);          \
    y = rotl64(y, 3);     \
    y = y ^ x;            \
  } while(0)

/* One SPECK decryption (inverse) round; updates (x,y) with round key k */
#define D(x,y,k)   \
  do {             \
    y = y ^ (x);           \
    y = rotr64(y, 3);      \
    x = x ^ (k);           \
    x = x - y;             \
    x = rotl64(x, 8);      \
  } while(0)

void speck_key_expand(const uint64_t k[2],
                      uint64_t subkeys[2 * SPECK_ROUNDS])
{
  uint64_t a = k[0], b = k[1];
  for(unsigned i = 0; i < SPECK_ROUNDS; i++) {
    subkeys[2*i]     = b;
    subkeys[2*i + 1] = a;
    R(b, a, i);
  }
}

void speck_encrypt(const uint64_t pt[2],
                   uint64_t ct[2],
                   const uint64_t key[2])
{
  uint64_t x = pt[1], y = pt[0];
  uint64_t sub[2 * SPECK_ROUNDS];
  speck_key_expand(key, sub);
  for(unsigned i = 0; i < SPECK_ROUNDS; i++) {
    R(x, y, sub[2*i + 1]);
  }
  ct[1] = x;
  ct[0] = y;
}

void speck_decrypt(const uint64_t ct[2],
                   uint64_t pt[2],
                   const uint64_t key[2])
{
  uint64_t x = ct[1], y = ct[0];
  uint64_t sub[2 * SPECK_ROUNDS];
  speck_key_expand(key, sub);
  for(int i = SPECK_ROUNDS - 1; i >= 0; i--) {
    D(x, y, sub[2*i + 1]);
  }
  pt[1] = x;
  pt[0] = y;
}
