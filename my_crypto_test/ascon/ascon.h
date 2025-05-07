/* ascon.h */
#ifndef ASCON_H
#define ASCON_H

#include <stdint.h>

/* 64-bit word type */
typedef uint64_t bit64;

/**
 * ascon_initialization(state, key):
 *   - state:  5-word array that holds the internal state
 *   - key:    2-word array (128-bit key)
 *
 * Performs the ASCON initialization (12-round P, key injection).
 */
void ascon_initialization(bit64 state[5], const bit64 key[2]);

/**
 * ascon_associated_data(state, ad, ad_len):
 *   - state:    internal state after initialization
 *   - ad:       pointer to ad_len blocks of associated data
 *   - ad_len:   number of 64-bit blocks of AD
 *
 * Absorbs associated data (6-round P per block, plus domain separator).
 */
void ascon_associated_data(bit64 state[5],
                           const bit64 *ad, int ad_len);

/**
 * ascon_encrypt(state, pt, ct, pt_len):
 *   - state:    internal state after processing AD
 *   - pt:       pointer to pt_len plaintext blocks
 *   - ct:       output buffer for ciphertext (same number of blocks)
 *   - pt_len:   number of 64-bit blocks
 *
 * Encrypts pt_len blocks in CTR-like mode (6-round P between blocks).
 */
void ascon_encrypt(bit64 state[5],
                   const bit64 *pt, bit64 *ct, int pt_len);

/**
 * ascon_decrypt(state, ct, pt, ct_len):
 *   - state:    internal state after processing AD
 *   - ct:       pointer to ct_len ciphertext blocks
 *   - pt:       output buffer for plaintext
 *   - ct_len:   number of blocks
 *
 * Decrypts, same mode as encrypt.
 */
void ascon_decrypt(bit64 state[5],
                   const bit64 *ct, bit64 *pt, int ct_len);

/**
 * ascon_finalization(state, key):
 *   - state: internal state after decrypt/encrypt
 *   - key:   same key array as init
 *
 * Finalizes and injects key for tag generation (12-round P).
 * After this call, state[3] || state[4] is the 128-bit tag.
 */
void ascon_finalization(bit64 state[5], const bit64 key[2]);

#endif /* ASCON_H */
