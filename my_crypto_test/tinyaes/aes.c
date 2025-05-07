/* tinyaes/aes.c */

#include <string.h>     // for memcpy, memset
#include "aes.h"

// Number of columns comprising a state in AES
#define Nb 4

// Key length and #rounds
#if defined(AES256) && AES256 == 1
  #define Nk 8
  #define Nr 14
#elif defined(AES192) && AES192 == 1
  #define Nk 6
  #define Nr 12
#else
  #define Nk 4
  #define Nr 10
#endif

// Forward S-box
static const uint8_t sbox[256] = {
  /* 0x0 */ 0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  /* 0x10 */0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  /* 0x20 */0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  /* 0x30 */0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  /* 0x40 */0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  /* 0x50 */0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  /* 0x60 */0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  /* 0x70 */0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  /* 0x80 */0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  /* 0x90 */0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  /* 0xa0 */0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  /* 0xb0 */0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  /* 0xc0 */0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  /* 0xd0 */0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  /* 0xe0 */0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  /* 0xf0 */0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

/* Round constants */
static const uint8_t Rcon[11] = {
  0x8d,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36
};

/* State type */
typedef uint8_t state_t[4][4];

#define getSBoxValue(num) (sbox[(num)])

/* Key expansion */
static void KeyExpansion(uint8_t *RoundKey, const uint8_t *Key) {
  uint8_t tempa[4];
  int i, j;

  // first round key = Key
  for(i = 0; i < Nk; ++i) {
    RoundKey[4*i + 0] = Key[4*i + 0];
    RoundKey[4*i + 1] = Key[4*i + 1];
    RoundKey[4*i + 2] = Key[4*i + 2];
    RoundKey[4*i + 3] = Key[4*i + 3];
  }
  // generate rest
  for(i = Nk; i < Nb*(Nr+1); ++i) {
    for(j = 0; j < 4; j++) tempa[j] = RoundKey[4*(i-1) + j];
    if(i % Nk == 0) {
      // RotWord
      uint8_t t = tempa[0];
      tempa[0] = tempa[1];
      tempa[1] = tempa[2];
      tempa[2] = tempa[3];
      tempa[3] = t;
      // SubWord
      tempa[0] = getSBoxValue(tempa[0]);
      tempa[1] = getSBoxValue(tempa[1]);
      tempa[2] = getSBoxValue(tempa[2]);
      tempa[3] = getSBoxValue(tempa[3]);
      tempa[0] ^= Rcon[i/Nk];
    }
    for(j = 0; j < 4; j++) {
      RoundKey[4*i + j] = RoundKey[4*(i-Nk) + j] ^ tempa[j];
    }
  }
}

void AES_init_ctx(struct AES_ctx *ctx, const uint8_t *key) {
  KeyExpansion(ctx->RoundKey, key);
}

#if (CBC == 1) || (CTR == 1)
void AES_init_ctx_iv(struct AES_ctx *ctx, const uint8_t *key, const uint8_t *iv) {
  KeyExpansion(ctx->RoundKey, key);
  memcpy(ctx->Iv, iv, AES_BLOCKLEN);
}
void AES_ctx_set_iv(struct AES_ctx *ctx, const uint8_t *iv) {
  memcpy(ctx->Iv, iv, AES_BLOCKLEN);
}
#endif

/* AddRoundKey, SubBytes, ShiftRows, MixColumns, etc. */
static void AddRoundKey(uint8_t round, state_t state, const uint8_t *RoundKey) {
  for(int c=0; c<4; c++)
    for(int r=0; r<4; r++)
      state[r][c] ^= RoundKey[round*4*4 + c*4 + r];
}

static void SubBytes(state_t state) {
  for(int r=0; r<4; r++)
    for(int c=0; c<4; c++)
      state[r][c] = getSBoxValue(state[r][c]);
}

static void ShiftRows(state_t state) {
  uint8_t tmp;
  // row 1
  tmp = state[1][0];
  state[1][0] = state[1][1];
  state[1][1] = state[1][2];
  state[1][2] = state[1][3];
  state[1][3] = tmp;
  // row 2
  tmp = state[2][0];
  state[2][0] = state[2][2];
  state[2][2] = tmp;
  tmp = state[2][1];
  state[2][1] = state[2][3];
  state[2][3] = tmp;
  // row 3
  tmp = state[3][0];
  state[3][0] = state[3][3];
  state[3][3] = state[3][2];
  state[3][2] = state[3][1];
  state[3][1] = tmp;
}

static uint8_t xtime(uint8_t x) {
  return (x<<1) ^ (((x>>7)&1)*0x1b);
}

static void MixColumns(state_t state) {
  for(int c=0; c<4; c++) {
    uint8_t a0 = state[0][c], a1 = state[1][c];
    uint8_t a2 = state[2][c], a3 = state[3][c];
    uint8_t t = a0 ^ a1 ^ a2 ^ a3;
    uint8_t u = a0;
    uint8_t xt;
    xt = a0 ^ a1; xt = xtime(xt); state[0][c] ^= xt ^ t;
    xt = a1 ^ a2; xt = xtime(xt); state[1][c] ^= xt ^ t;
    xt = a2 ^ a3; xt = xtime(xt); state[2][c] ^= xt ^ t;
    xt = a3 ^ u;  xt = xtime(xt); state[3][c] ^= xt ^ t;
  }
}

static void Cipher(state_t state, const uint8_t *RoundKey) {
  AddRoundKey(0, state, RoundKey);
  for(uint8_t round = 1; round < Nr; round++) {
    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);
    AddRoundKey(round, state, RoundKey);
  }
  // final round
  SubBytes(state);
  ShiftRows(state);
  AddRoundKey(Nr, state, RoundKey);
}

#if ECB == 1
void AES_ECB_encrypt(const struct AES_ctx *ctx, uint8_t *buf) {
  state_t state;
  // load the 16 bytes into our 4×4 state matrix
  memcpy(state, buf, AES_BLOCKLEN);
  // run the core AES cipher on the matrix
  Cipher(state, ctx->RoundKey);
  // write the result back into the byte buffer
  memcpy(buf, state, AES_BLOCKLEN);
}
void AES_ECB_decrypt(const struct AES_ctx *ctx, uint8_t *buf) {
  // InvCipher not shown here; assume present if needed
}
#endif

#if CBC == 1
static void XorWithIv(uint8_t *buf, const uint8_t *Iv) {
  for(int i=0;i<AES_BLOCKLEN;i++) buf[i] ^= Iv[i];
}
void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, size_t length) {
  uint8_t *Iv = ctx->Iv;
  state_t state;
  
  for(size_t i=0;i<length;i+=AES_BLOCKLEN) {
    XorWithIv(buf, Iv);
    memcpy(state, buf, AES_BLOCKLEN);
    Cipher(state, ctx->RoundKey);
    Iv = buf;
    buf += AES_BLOCKLEN;
  }
  memcpy(buf, state, AES_BLOCKLEN);
  memcpy(ctx->Iv, Iv, AES_BLOCKLEN);
}
#endif

#if CTR == 1
void AES_CTR_xcrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, size_t length) {
  uint8_t buffer[AES_BLOCKLEN];
  int bi = AES_BLOCKLEN;
  state_t state;
  for(size_t i=0;i<length;i++) {
    if(bi == AES_BLOCKLEN) {
      memcpy(buffer, ctx->Iv, AES_BLOCKLEN);
      memcpy(state, buf, AES_BLOCKLEN);
      Cipher(state, ctx->RoundKey);
      memcpy(buf, state, AES_BLOCKLEN);
      // increment IV
      for(int j = AES_BLOCKLEN-1; j>=0; j--) {
        if(++ctx->Iv[j]!=0) break;
      }
      bi = 0;
    }
    buf[i] ^= buffer[bi++];
  }
}
#endif
