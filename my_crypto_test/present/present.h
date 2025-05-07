/* present.h */
#ifndef PRESENT_H
#define PRESENT_H

#include <stdint.h>
#include <stdlib.h>

/* A packed byte of two 4-bit nibbles */
typedef struct __attribute__((__packed__)) {
    uint8_t nibble1:4;
    uint8_t nibble2:4;
} byte;

/* ---- Core API ---- */

/**
 * Convert a 16-char hex string (64 bits) to a 64-bit integer.
 * hex must be lowercase, no “0x”, exactly 16 chars.
 */
uint64_t present_fromHexStringToLong(const char *hex);

/**
 * Convert a 64-bit integer to a 16-char hex string (plus null).
 * out must point to at least 17 chars.
 */
char *present_fromLongToHexString(uint64_t block, char *out);

/**
 * Encrypt one 64-bit block (hex string) under an 80-bit key (hex string).
 * Both strings are lowercase, without “0x”. Returns a newly malloc’ed
 * 17-byte string (caller must free), containing the 16-char ciphertext + NUL.
 */
char *present_encrypt(const char *plaintext_hex, const char *key_hex);

/**
 * Decrypt one 64-bit block ciphertext (hex string) under an 80-bit key.
 * Returns a newly malloc’ed 17-byte plaintext string + NUL.
 */
char *present_decrypt(const char *ciphertext_hex, const char *key_hex);

#endif /* PRESENT_H */
