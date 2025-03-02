/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "psa/crypto.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "mbedtls/mbedtls_config.h"
#include "mbedtls/chacha20.h"

#include "chacha20.c"

#include "fsl_debug_console.h"
#include "board.h"
#include "app.h"

int main() {
    // Initialize the debug console
    BOARD_InitBootPins();
    BOARD_InitBootClocks();
    BOARD_InitDebugConsole();

    // Key and nonce
    unsigned char key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11,
        0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
        0x1E, 0x1F
    };
    unsigned char nonce[12] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    };
    unsigned char counter = 0;

    // Message to encrypt
    unsigned char input[] = "Cha Cha cha ronda 20!";
    size_t input_len = strlen((const char *)input);
    unsigned char output[sizeof(input)];
    unsigned char decrypted[sizeof(input)];

    // Initialize context
    mbedtls_chacha20_context ctx;
    mbedtls_chacha20_init(&ctx);

    // Set key and nonce
    mbedtls_chacha20_setkey(&ctx, key);
    mbedtls_chacha20_starts(&ctx, nonce, counter);

    // Encrypt the message
    mbedtls_chacha20_update(&ctx, input_len, input, output);
    
    // Reuse the same context to decrypt
    // Reinitialize the context
    mbedtls_chacha20_init(&ctx);
    mbedtls_chacha20_setkey(&ctx, key);
    mbedtls_chacha20_starts(&ctx, nonce, counter);

    // Decrypt the message
    mbedtls_chacha20_update(&ctx, input_len, output, decrypted);

    // Show results
    PRINTF("Encrypted text: ");
    for (size_t i = 0; i < input_len; i++) {
        PRINTF("%02x ", output[i]); // Show in hexadecimal format
    }
    PRINTF("\nDecrypted text: %s\n", decrypted);

    // Free context
    mbedtls_chacha20_free(&ctx);
    
    return 0;
}