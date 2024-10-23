// Alon Hillel-Tuch
// 2024

#define DEBUG_PRINT(fmt, ...) fprintf(stderr, "Debug: " fmt "\n", ##__VA_ARGS__)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <unistd.h>

//priority import of our common defines and header funcs
#include "common_defs.h"  
#include "digital_signature.h"
#include "command_args.h"
#include "hsm_shared.h"
#include "utils.h"
#include "key_func.h"

KeyEntry keystore[MAX_KEYS];
int key_count = 0;
unsigned char master_key[KEY_SIZE];

char keystore_file[MAX_FILENAME] = "keystore.dat";
char master_key_file[MAX_FILENAME] = "master.key";

// Function prototypes //
void update_global_paths(const CommandLineArgs* args);
void handle_sign_command(const char* key_name);
void handle_verify_command(const char* key_name);
void handle_export_public_key_command(const char* key_name);
void handle_import_public_key_command(const char* key_name);




// Function to update global file paths from arguments
void update_global_paths(const CommandLineArgs* args) {
    if (strlen(args->keystore_file) > 0) {
        strncpy(keystore_file, args->keystore_file, MAX_FILENAME - 1);
        keystore_file[MAX_FILENAME - 1] = '\0';
    }
    
    if (strlen(args->master_key_file) > 0) {
        strncpy(master_key_file, args->master_key_file, MAX_FILENAME - 1);
        master_key_file[MAX_FILENAME - 1] = '\0';
    }
}


int main(int argc, char *argv[]) {
    fprintf(stderr, "Debug: Starting virtual_hsm\n");
    
    CommandLineArgs args;
    
    if (!handle_arguments(argc, argv, &args)) {
        return 1;
    }

    update_global_paths(&args);

    if (strcmp(args.command, "-generate_master_key") == 0) {
        generate_master_key();
        return 0;
    }

    load_master_key(args.provided_master_key);
    load_keystore();

    if (strcmp(args.command, "-store") == 0) {
        char hex_key[KEY_SIZE * 2 + 1];
        if (fread(hex_key, 1, KEY_SIZE * 2, stdin) != KEY_SIZE * 2) {
            fprintf(stderr, "Error: Invalid key input. Please provide %d hex characters.\n", KEY_SIZE * 2);
            return 1;
        }
        hex_key[KEY_SIZE * 2] = '\0';
        
        unsigned char binary_key[KEY_SIZE];
        hex_to_bytes(hex_key, binary_key, KEY_SIZE);
        store_key(args.key_name, binary_key, 0);
    } else if (strcmp(args.command, "-retrieve") == 0) {
        retrieve_key(args.key_name);
    } else if (strcmp(args.command, "-list") == 0) {
        list_keys();
    } else if (strcmp(args.command, "-generate_key_pair") == 0) {
        generate_key_pair(args.key_name);
    } else if (strcmp(args.command, "-sign") == 0) {
        handle_sign_command(args.key_name);
    } else if (strcmp(args.command, "-verify") == 0) {
        handle_verify_command(args.key_name);
    } else if (strcmp(args.command, "-export_public_key") == 0) {
        handle_export_public_key_command(args.key_name);
    } else if (strcmp(args.command, "-import_public_key") == 0) {
        handle_import_public_key_command(args.key_name);
    }

    return 0;
}


// Helper functions for handling specific commands
void handle_sign_command(const char* key_name) {
    unsigned char *data = NULL;
    size_t data_len = 0;
    size_t buffer_size = BUFFER_SIZE;
    
    data = malloc(buffer_size);
    if (!data) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }

    while ((data_len += fread(data + data_len, 1, buffer_size - data_len, stdin)) == buffer_size) {
        buffer_size *= ARRAY_EXPANSION_MULTIPLE;
        unsigned char *temp = realloc(data, buffer_size);
        if (!temp) {
            fprintf(stderr, "Memory reallocation failed\n");
            free(data);
            exit(1);
        }
        data = temp;
    }

    DEBUG_PRINT("Read data length: %zu", data_len);
    
    unsigned char signature[MAX_SIGNATURE_SIZE];
    size_t sig_len = sizeof(signature);

    if (sign_data(key_name, data, data_len, signature, &sig_len)) {
        DEBUG_PRINT("Signature created, length: %zu", sig_len);
        fwrite(signature, 1, sig_len, stdout);
    } else {
        fprintf(stderr, "Signing failed\n");
        free(data);
        exit(1);
    }

    free(data);
}

void handle_verify_command(const char* key_name) {
    unsigned char signature[MAX_SIGNATURE_SIZE];
    unsigned char *data = NULL;
    size_t data_len = 0;
    size_t sig_len = 0;
    size_t buffer_size = BUFFER_SIZE;

    data = malloc(buffer_size);
    if (!data) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }

    while ((data_len += fread(data + data_len, 1, buffer_size - data_len, stdin)) == buffer_size) {
        buffer_size *= ARRAY_EXPANSION_MULTIPLE;
        unsigned char *temp = realloc(data, buffer_size);
        if (!temp) {
            fprintf(stderr, "Memory reallocation failed\n");
            free(data);
            exit(1);
        }
        data = temp;
    }

    if (data_len < SIG_LENGTH) {
        fprintf(stderr, "Input data too short\n");
        free(data);
        exit(1);
    }

    sig_len = SIG_LENGTH;
    memcpy(signature, data + data_len - sig_len, sig_len);
    data_len -= sig_len;

    if (verify_signature(key_name, data, data_len, signature, sig_len)) {
        printf("Signature verified\n");
    } else {
        fprintf(stderr, "Signature verification failed\n");
        free(data);
        exit(1);
    }

    free(data);
}

void handle_export_public_key_command(const char* key_name) {
    char *pem_key;
    if (export_public_key(key_name, &pem_key)) {
        printf("%s", pem_key);
        free(pem_key);
    } else {
        fprintf(stderr, "Public key export failed\n");
        exit(1);
    }
}

void handle_import_public_key_command(const char* key_name) {
    char pem_key[PEM_KEY_CHAR_ARR_SIZE];
    size_t pem_len = fread(pem_key, 1, sizeof(pem_key), stdin);
    pem_key[pem_len] = '\0';
    
    if (import_public_key(key_name, pem_key)) {
        printf("Public key imported successfully\n");
    } else {
        fprintf(stderr, "Public key import failed\n");
        exit(1);
    }
}
