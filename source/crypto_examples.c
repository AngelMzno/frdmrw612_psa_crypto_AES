/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "psa/crypto.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "mbedtls/mbedtls_config.h"
#include "mbedtls/aes.h"


#include "fsl_debug_console.h"
#include "board.h"
#include "app.h"
#include "aes.c"


int main() {
    // Initialize the debug console
    BOARD_InitBootPins();
    BOARD_InitBootClocks();
    BOARD_InitDebugConsole();

    // Key and IV
    unsigned char key[16] = "CBC128bitKey1234";
    unsigned char iv[16] = "CBC128bitKey1234";

    // Plaintext
    unsigned char plaintext[16] = "Hello, AES!";
    unsigned char ciphertext[16];
    unsigned char decryptedtext[16];

    // AES context
    mbedtls_aes_context aes;

    // Initialize AES context
    mbedtls_aes_init(&aes);

    // Set encryption key
    mbedtls_aes_setkey_enc(&aes, key, 128);

    // Encrypt plaintext
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, 16, iv, plaintext, ciphertext);

    // Reset IV for decryption
    memcpy(iv, "CBC128bitKey1234", 16);

    // Set decryption key
    mbedtls_aes_setkey_dec(&aes, key, 128);

    // Decrypt ciphertext
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, 16, iv, ciphertext, decryptedtext);

    // Print results
    PRINTF("Plaintext: %s\n\r", plaintext);
    PRINTF("Ciphertext: ");
    for (int i = 0; i < 16; i++) {
        PRINTF("%02x", ciphertext[i]);
    }
    PRINTF("\nDecrypted text: %s\n\r", decryptedtext);

    // Free AES context
    mbedtls_aes_free(&aes);

    return 0;
}