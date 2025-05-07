/* present.c */
#include "present.h"
#include <stdio.h>
#include <string.h>

/* ---- S-box, inverse S-box, permutation table ---- */
static const uint8_t S[16] = {
  0xC,0x5,0x6,0xB, 0x9,0x0,0xA,0xD,
  0x3,0xE,0xF,0x8, 0x4,0x7,0x1,0x2
};
static const uint8_t invS[16] = {
  0x5,0xE,0xF,0x8, 0xC,0x1,0x2,0xD,
  0xB,0x4,0x6,0x3, 0x0,0x7,0x9,0xA
};
static const uint8_t P[64] = {
   0,16,32,48, 1,17,33,49, 2,18,34,50, 3,19,35,51,
   4,20,36,52, 5,21,37,53, 6,22,38,54, 7,23,39,55,
   8,24,40,56, 9,25,41,57,10,26,42,58,11,27,43,59,
  12,28,44,60,13,29,45,61,14,30,46,62,15,31,47,63
};


uint64_t present_fromHexStringToLong(const char *hex) {
  uint64_t v = 0;
  for(int i = 0; i < 16; i++) {
    uint8_t d = (hex[i] <= '9') ? hex[i] - '0' : hex[i] - 'a' + 10;
    v = (v << 4) | (d & 0xF);
  }
  return v;
}

static byte *longToBytes(uint64_t x) {
  byte *b = malloc(8 * sizeof(*b));
  for(int i = 7; i >= 0; i--) {
    b[i].nibble2 = x & 0xF; x >>= 4;
    b[i].nibble1 = x & 0xF; x >>= 4;
  }
  return b;
}

char *present_fromLongToHexString(uint64_t block, char *out) {
  sprintf(out, "%016" PRIx64, block);
  return out;
}

/* ---- S-box and permutation helpers ---- */
static inline uint8_t applyS(uint8_t v)       { return S[v & 0xF]; }
static inline uint8_t applyInvS(uint8_t v)    { return invS[v & 0xF]; }

static uint64_t permute(uint64_t s) {
  uint64_t r = 0;
  for(int i = 0; i < 64; i++) {
    r |= ((s >> (63 - i)) & 1ULL) << (63 - P[i]);
  }
  return r;
}
static uint64_t inversepermute(uint64_t s) {
  uint64_t r = 0;
  for(int i = 0; i < 64; i++) {
    r = (r << 1) | ((s >> (63 - P[i])) & 1ULL);
  }
  return r;
}

/* ---- Key schedule (80-bit key over 32 rounds) ---- */
static uint16_t getKeyLow(const char *k) {
  uint16_t kl = 0;
  for(int i = 16; i < 20; i++) {
    uint8_t d = (k[i] <= '9') ? k[i] - '0' : k[i] - 'a' + 10;
    kl = (kl << 4) | (d & 0xF);
  }
  return kl;
}
static uint64_t *generateSubkeys(const char *key_hex) {
  uint64_t *subs = malloc(32 * sizeof(*subs));
  uint64_t kh = present_fromHexStringToLong(key_hex);
  uint16_t kl = getKeyLow(key_hex);
  subs[0] = kh;
  for(int i = 1; i < 32; i++) {
    uint64_t th = kh, new_h;
    uint16_t tl = kl;
    /* rotate left 61 */
    new_h = (th << 61) | ((uint64_t)tl << 45) | (th >> 19);
    kl    = th >> 3;
    kh    = new_h;
    /* S-box MS nibble */
    uint8_t ms = applyS(kh >> 60);
    kh = (kh & 0x0FFFFFFFFFFFFFFFULL) | ((uint64_t)ms << 60);
    /* round counter */
    kl ^= (i & 1) << 15;
    kh ^= (i >> 1);
    subs[i] = kh;
  }
  return subs;
}

/* ---- Public encrypt/decrypt ---- */
char *present_encrypt(const char *pt_hex, const char *key_hex) {
  uint64_t *sub = generateSubkeys(key_hex);
  uint64_t s = present_fromHexStringToLong(pt_hex);

  for(int r = 0; r < 31; r++) {
    s ^= sub[r];
    /* S-box layer */
    byte *bs = longToBytes(s);
    for(int i = 0; i < 8; i++) {
      bs[i].nibble1 = applyS(bs[i].nibble1);
      bs[i].nibble2 = applyS(bs[i].nibble2);
    }
    uint64_t t = 0;
    for(int i = 0; i < 8; i++) {
      t = (t << 4) | (bs[i].nibble1 & 0xF);
      t = (t << 4) | (bs[i].nibble2 & 0xF);
    }
    free(bs);
    s = permute(t);
  }
  s ^= sub[31];
  free(sub);

  char *out = malloc(17);
  return present_fromLongToHexString(s, out);
}

char *present_decrypt(const char *ct_hex, const char *key_hex) {
  uint64_t *sub = generateSubkeys(key_hex);
  uint64_t s = present_fromHexStringToLong(ct_hex);

  for(int r = 31; r > 0; r--) {
    s ^= sub[r];
    s = inversepermute(s);
    byte *bs = longToBytes(s);
    for(int i = 0; i < 8; i++) {
      bs[i].nibble1 = applyInvS(bs[i].nibble1);
      bs[i].nibble2 = applyInvS(bs[i].nibble2);
    }
    uint64_t t = 0;
    for(int i = 0; i < 8; i++) {
      t = (t << 4) | (bs[i].nibble1 & 0xF);
      t = (t << 4) | (bs[i].nibble2 & 0xF);
    }
    free(bs);
    s = t;
  }
  s ^= sub[0];
  free(sub);

  char *out = malloc(17);
  return present_fromLongToHexString(s, out);
}