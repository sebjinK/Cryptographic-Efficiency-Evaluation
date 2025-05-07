/*
 * my_crypto_test.c
 * Crypto Energy Test with Contiki-NG logging & Energest
 */

 #include "contiki.h"
 #include "sys/energest.h"
 #include "sys/log.h"
 #include <string.h>
 #include <stdlib.h>
 #include <inttypes.h>
 
 /* Your cipher headers */
 #include "ascon/ascon.h"
 #include "speck/speck.h"
 #include "present/present.h"
 #include "tinyaes/aes.h"
 
 #define LOG_MODULE "CryptoTest"
 #define LOG_LEVEL   LOG_LEVEL_INFO
 
 #define TEST_INTERVAL (1 * CLOCK_SECOND)
 #define ITER           1000
 #define BLOCKS           1
 
 /* --- ASCON buffers --- */
 static bit64 ascon_state[5];
 static const bit64 ascon_pt[BLOCKS] = { 0x0123456789abcdefULL };
 static bit64 ascon_ct[BLOCKS];
 static const bit64 ascon_key[2] = {
   0x0123456789abcdefULL,
   0xfedcba9876543210ULL
 };
 
 /* --- SPECK buffers --- */
 static const uint64_t speck_key[2] = {
   0x0123456789abcdefULL,
   0xfedcba9876543210ULL
 };
 static const uint64_t speck_pt[2] = {
   0x1111111111111111ULL,
   0x2222222222222222ULL
 };
 static uint64_t speck_ct[2];
 
 /* --- PRESENT inputs (hex strings) --- */
 static char present_pt_hex[17]  = "0123456789abcdef";
 static char present_key_hex[21] = "abcdef0123456789abc0";
 
 /* --- AES-128 ECB buffers --- */
 static const uint8_t aes_key[16] = {
   0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
   0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F
 };
 static const uint8_t aes_pt[16] = {
   0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
   0x28,0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F
 };
 static uint8_t aes_buf[16];
 static struct AES_ctx aes_ctx;
 
 PROCESS(my_crypto_test_process, "Crypto + Energest");
 AUTOSTART_PROCESSES(&my_crypto_test_process);
 
 PROCESS_THREAD(my_crypto_test_process, ev, data)
 {
   static struct etimer timer;
   uint64_t cpu_b, lpm_b, tx_b, rx_b;
   uint64_t cpu_a, lpm_a, tx_a, rx_a;
 
   PROCESS_BEGIN();
 
   /* Initialize Energest */
   energest_init();
   etimer_set(&timer, TEST_INTERVAL);
 
   while(1) {
     PROCESS_WAIT_EVENT_UNTIL(ev == PROCESS_EVENT_TIMER && data == &timer);
     etimer_reset(&timer);
 
     /* snapshot before */
     energest_flush();
     cpu_b = energest_type_time(ENERGEST_TYPE_CPU);
     lpm_b = energest_type_time(ENERGEST_TYPE_LPM);
     tx_b  = energest_type_time(ENERGEST_TYPE_TRANSMIT);
     rx_b  = energest_type_time(ENERGEST_TYPE_LISTEN);
 
     /* crypto workload */
     for(int i = 0; i < ITER; i++) {
       /* ASCON */
       memset(ascon_state, 0, sizeof(ascon_state));
       ascon_initialization(ascon_state, ascon_key);
       ascon_encrypt(ascon_state, ascon_pt, ascon_ct, BLOCKS);
       ascon_finalization(ascon_state, ascon_key);
 
       /* SPECK */
       speck_encrypt(speck_pt, speck_ct, speck_key);
 
       /* PRESENT */
       {
         char *ct_hex = present_encrypt(present_pt_hex, present_key_hex);
         if(ct_hex) {
           free(ct_hex);
         }
       }
 
       /* AES-128 ECB */
       memcpy(aes_buf, aes_pt, sizeof(aes_buf));
       AES_init_ctx(&aes_ctx, aes_key);
       AES_ECB_encrypt(&aes_ctx, aes_buf);
     }
 
     /* snapshot after */
     energest_flush();
     cpu_a = energest_type_time(ENERGEST_TYPE_CPU);
     lpm_a = energest_type_time(ENERGEST_TYPE_LPM);
     tx_a  = energest_type_time(ENERGEST_TYPE_TRANSMIT);
     rx_a  = energest_type_time(ENERGEST_TYPE_LISTEN);
 
     /* log the deltas */
     LOG_INFO("----- Energest in last %lus -----\n",
              (unsigned long)(TEST_INTERVAL / CLOCK_SECOND));
     LOG_INFO(" CPU ticks : %" PRIu64 "\n", cpu_a - cpu_b);
     LOG_INFO(" LPM ticks : %" PRIu64 "\n", lpm_a - lpm_b);
     LOG_INFO(" TX ticks  : %" PRIu64 "\n", tx_a  - tx_b);
     LOG_INFO(" RX ticks  : %" PRIu64 "\n", rx_a  - rx_b);
   }
 
   PROCESS_END();
 }
 