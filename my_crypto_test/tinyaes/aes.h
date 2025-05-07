/* tinyaes/aes.h */
#ifndef _AES_H_
#define _AES_H_

#include <stdint.h>
#include <stddef.h>

// Enable/disable modes of operation
#ifndef ECB
#define ECB 1
#endif
#ifndef CBC
#define CBC 1
#endif
#ifndef CTR
#define CTR 1
#endif

// Select key size: only AES128 supported here
#define AES128 1

// Block size is always 16 bytes = 128 bits
#define AES_BLOCKLEN      16

// Key length & expanded key size
#if defined(AES256) && AES256 == 1
  #define AES_KEYLEN      32
  #define AES_keyExpSize  240
#elif defined(AES192) && AES192 == 1
  #define AES_KEYLEN      24
  #define AES_keyExpSize  208
#else
  #define AES_KEYLEN      16
  #define AES_keyExpSize  176
#endif

/**
 * AES context holds the round keys and (optionally) IV.
 */
struct AES_ctx {
  uint8_t RoundKey[AES_keyExpSize];
#if (CBC == 1) || (CTR == 1)
  uint8_t Iv[AES_BLOCKLEN];
#endif
};

/* Initialize for ECB mode (just expand the key) */
void AES_init_ctx(struct AES_ctx *ctx, const uint8_t *key);

#if CBC == 1 || CTR == 1
/* Initialize for CBC or CTR: expand key + set IV */
void AES_init_ctx_iv(struct AES_ctx *ctx, const uint8_t *key, const uint8_t *iv);
/* Reset IV on the fly */
void AES_ctx_set_iv(struct AES_ctx *ctx, const uint8_t *iv);
#endif

#if ECB == 1
/* ECB encrypt/decrypt exactly one block in-place */
  void AES_ECB_encrypt(const struct AES_ctx *ctx, uint8_t *buf);
  void AES_ECB_decrypt(const struct AES_ctx *ctx, uint8_t *buf);
#endif

#if CBC == 1
/* CBC: buffer length must be multiple of AES_BLOCKLEN */
  void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, size_t length);
  void AES_CBC_decrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, size_t length);
#endif

#if CTR == 1
/* CTR: same for encrypt/decrypt, increments IV internally */
  void AES_CTR_xcrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, size_t length);
#endif

#endif /* _AES_H_ */
