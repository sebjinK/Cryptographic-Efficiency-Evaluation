/* ascon.c */
#include "ascon.h"

/* ------------------------------------------------------------------ */
/*  Internal helpers (static)                                         */
/* ------------------------------------------------------------------ */

static const bit64 RC[16] = {
  0xf0ULL, 0xe1ULL, 0xd2ULL, 0xc3ULL,
  0xb4ULL, 0xa5ULL, 0x96ULL, 0x87ULL,
  0x78ULL, 0x69ULL, 0x5aULL, 0x4bULL,
  0x3cULL, 0x2dULL, 0x1eULL, 0x0fULL
};

static inline bit64 rot(bit64 x, int r) {
  return (x >> r) | (x << (64 - r));
}

static void add_constant(bit64 s[5], int round, int a) {
  s[2] ^= RC[12 - a + round];
}

static void sbox_layer(bit64 s[5]) {
  bit64 t[5];
  /* substitution layer */
  s[0] ^= s[4];  s[4] ^= s[3];  s[2] ^= s[1];
  for(int i = 0; i < 5; i++) t[i] = ~s[i];
  t[0] &= s[1];  t[1] &= s[2];  t[2] &= s[3];
  t[3] &= s[4];  t[4] &= s[0];
  s[0] ^= t[1];  s[1] ^= t[2];  s[2] ^= t[3];
  s[3] ^= t[4];  s[4] ^= t[0];
  s[1] ^= s[0];  s[0] ^= s[4];  s[3] ^= s[2];
  s[2] = ~s[2];
}

static void linear_layer(bit64 s[5]) {
  /* diffusion layer */
  s[0] ^= rot(s[0], 19) ^ rot(s[0], 28);
  s[1] ^= rot(s[1], 61) ^ rot(s[1], 39);
  s[2] ^= rot(s[2],  1) ^ rot(s[2],  6);
  s[3] ^= rot(s[3], 10) ^ rot(s[3], 17);
  s[4] ^= rot(s[4],  7) ^ rot(s[4], 41);
}

static void p_perm(bit64 s[5], int rounds) {
  for(int r = 0; r < rounds; r++){
    add_constant(s, r, rounds);
    sbox_layer(s);
    linear_layer(s);
  }
}

/* ------------------------------------------------------------------ */
/*  Public API implementations                                        */
/* ------------------------------------------------------------------ */

void ascon_initialization(bit64 s[5], const bit64 k[2]) {
  /* IV = rate||capacity||a||b etc, here baked into number of rounds */
  p_perm(s, 12);
  s[3] ^= k[0];
  s[4] ^= k[1];
}

void ascon_associated_data(bit64 s[5],
                           const bit64 *ad, int ad_len) {
  for(int i = 0; i < ad_len; i++) {
    s[0] ^= ad[i];
    p_perm(s, 6);
  }
  /* domain separation */
  s[4] ^= 1;
}

void ascon_encrypt(bit64 s[5],
                   const bit64 *pt, bit64 *ct, int len) {
  /* encrypt first block */
  ct[0] = pt[0] ^ s[0];
  s[0]  = ct[0];
  /* remaining blocks */
  for(int i = 1; i < len; i++) {
    p_perm(s, 6);
    ct[i] = pt[i] ^ s[0];
    s[0]  = ct[i];
  }
}

void ascon_decrypt(bit64 s[5],
                   const bit64 *ct, bit64 *pt, int len) {
  pt[0] = ct[0] ^ s[0];
  s[0]  = ct[0];
  for(int i = 1; i < len; i++) {
    p_perm(s, 6);
    pt[i] = ct[i] ^ s[0];
    s[0]  = ct[i];
  }
}

void ascon_finalization(bit64 s[5], const bit64 k[2]) {
  s[1] ^= k[0];
  s[2] ^= k[1];
  p_perm(s, 12);
  s[3] ^= k[0];
  s[4] ^= k[1];
}
