/* speck.h */
#ifndef SPECK_H
#define SPECK_H

#include <stdint.h>

/* Number of rounds for Speck-128/128 */
#define SPECK_ROUNDS 32

/**
 * Expand a 128-bit key (2×64-bit words) into the 2×SPECK_ROUNDS round keys.
 *
 * @param k        Input key as two 64-bit words.
 * @param subkeys  Output buffer of length 2*SPECK_ROUNDS.
 */
void speck_key_expand(const uint64_t k[2],
                      uint64_t subkeys[2 * SPECK_ROUNDS]);

/**
 * Encrypt one 128-bit block under the given 128-bit key.
 *
 * @param pt   Input plaintext as two little-endian 64-bit words.
 * @param ct   Output ciphertext (same format).
 * @param key  Input key (2 words).
 */
void speck_encrypt(const uint64_t pt[2],
                   uint64_t ct[2],
                   const uint64_t key[2]);

/**
 * Decrypt one 128-bit block under the given 128-bit key.
 *
 * @param ct   Input ciphertext as two words.
 * @param pt   Output plaintext.
 * @param key  Input key.
 */
void speck_decrypt(const uint64_t ct[2],
                   uint64_t pt[2],
                   const uint64_t key[2]);

#endif /* SPECK_H */
