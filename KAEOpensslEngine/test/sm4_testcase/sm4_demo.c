#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define DATA_SIZE 2048
#define NUM_OF_DATA 600000

void generate_random_data(uint8_t *data, size_t size) {
    RAND_bytes(data, size);
}

void print_hex(const uint8_t *data, size_t size) {
    for (size_t i = 0; i < size; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

double get_elapsed_time(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) + (double)(end.tv_nsec - start.tv_nsec) / 1e9;
}


int main() {
    // uint8_t *data[NUM_OF_DATA];
    uint8_t **data = (uint8_t **)malloc(NUM_OF_DATA * sizeof(uint8_t *));
    // uint8_t *encrypted_data[NUM_OF_DATA];
    uint8_t **encrypted_data = (uint8_t **)malloc(NUM_OF_DATA * sizeof(uint8_t *));

    uint8_t key[16];
    uint8_t iv[16];
    struct timespec start, end;

    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);
    // Generate random key and IV
    generate_random_data(key, sizeof(key));
    generate_random_data(iv, sizeof(iv));

    // Generate random data
    for (int i = 0; i < NUM_OF_DATA; i++) {
        data[i] = (uint8_t *)malloc(DATA_SIZE);
        generate_random_data(data[i], DATA_SIZE);
    }

    // Initialize cipher context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_sm4_ecb(), NULL, key, iv);

    // Encrypt data and measure elapsed time
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < NUM_OF_DATA; i++) {
        encrypted_data[i] = (uint8_t *)malloc(DATA_SIZE*2);
        int encrypted_len;
        EVP_EncryptUpdate(ctx, encrypted_data[i], &encrypted_len, data[i], DATA_SIZE);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);

    // Calculate elapsed time
    double elapsed_time = get_elapsed_time(start, end);

    //Print encrypted data and elapsed time
    // for (int i = 0; i < NUM_OF_DATA; i++) {
    //     printf("Encrypted Data %d: ", i);
    //     print_hex(encrypted_data[i], DATA_SIZE);
    // }
    printf("Elapsed Time: %.6fs, data length is %d, data num is %d, Each data spend %.6fs.\n", elapsed_time, DATA_SIZE, NUM_OF_DATA, (elapsed_time/NUM_OF_DATA));

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    for (int i = 0; i < NUM_OF_DATA; i++) {
        free(data[i]);
        free(encrypted_data[i]);
    }
    free(data);
    free(encrypted_data);

    return 0;
}