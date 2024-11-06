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
#include <sys/stat.h>

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

// Function prototypes
void update_global_paths(const CommandLineArgs* args);
void handle_sign_command(const CommandLineArgs* args);
void handle_verify_command(const CommandLineArgs* args);
void handle_export_public_key_command(const char* key_name);
void handle_import_public_key_command(const CommandLineArgs* args);

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

    load_master_key(args.provided_master_key);
    load_keystore();

    if (strcmp(args.command, "-generate_master_key") == 0) {
        generate_master_key();
        return 0;
    }



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
        handle_sign_command(&args);
    } else if (strcmp(args.command, "-verify") == 0) {
        handle_verify_command(&args);
    } else if (strcmp(args.command, "-export_public_key") == 0) {
        handle_export_public_key_command(args.key_name);
    } else if (strcmp(args.command, "-import_public_key") == 0) {
        handle_import_public_key_command(&args);
    }

    return 0;
}

void handle_sign_command(const CommandLineArgs* args) {
    if (!args) {
        fprintf(stderr, "Error: Invalid arguments\n");
        exit(1);
    }

    unsigned char *data = NULL;
    size_t data_len = 0;

    if (args->input_file) {
        data = read_file(args->input_file, &data_len);
        if (!data) {
            fprintf(stderr, "Error: Failed to read input file '%s'\n", args->input_file);
            exit(1);
        }
    } else if (args->input_string) {
        data_len = strlen(args->input_string);
        data = (unsigned char*)malloc(data_len + 1);
        if (!data) {
            fprintf(stderr, "Error: Memory allocation failed\n");
            exit(1);
        }
        memcpy(data, args->input_string, data_len);
        data[data_len] = '\0';
    } else {
        fprintf(stderr, "Error: No input data provided for signing\n");
        exit(1);
    }

    unsigned char signature[MAX_SIGNATURE_SIZE];
    size_t sig_len = sizeof(signature);

    if (sign_data(args->key_name, data, data_len, signature, &sig_len)) {
        if (args->output_file) {
            if (!write_file(args->output_file, signature, sig_len)) {
                fprintf(stderr, "Error: Failed to write signature to file\n");
                free(data);
                exit(1);
            }
        } else {
            char default_output[MAX_FILENAME];
            snprintf(default_output, sizeof(default_output), "%s_signed", args->input_file ? args->input_file : "output");
            if (!write_file(default_output, signature, sig_len)) {
                fprintf(stderr, "Error: Failed to write signature to default file\n");
                free(data);
                exit(1);
            }
            printf("Signature saved to: %s\n", default_output);
        }
    } else {
        fprintf(stderr, "Error: Signing failed\n");
        free(data);
        exit(1);
    }

    free(data);
}

void handle_verify_command(const CommandLineArgs* args) {
    if (!args) {
        fprintf(stderr, "Error: Invalid arguments\n");
        exit(1);
    }

    if (!args->input_file && !args->input_string) {
        fprintf(stderr, "Error: No input data provided for verification\n");
        exit(1);
    }

    if (!args->signature_file) {
        fprintf(stderr, "Error: No signature file provided\n");
        exit(1);
    }

    unsigned char *data = NULL;
    size_t data_len = 0;
    unsigned char signature[MAX_SIGNATURE_SIZE];
    size_t sig_len = 0;

    // Read input data
    if (args->input_file) {
        data = read_file(args->input_file, &data_len);
        if (!data) {
            fprintf(stderr, "Error: Failed to read input file '%s'\n", args->input_file);
            exit(1);
        }
    } else {
        data_len = strlen(args->input_string);
        data = (unsigned char*)malloc(data_len + 1);
        if (!data) {
            fprintf(stderr, "Error: Memory allocation failed\n");
            exit(1);
        }
        memcpy(data, args->input_string, data_len);
        data[data_len] = '\0';
    }

    // Read signature
    FILE *sig_file = fopen(args->signature_file, "rb");
    if (!sig_file) {
        fprintf(stderr, "Error: Failed to open signature file '%s'\n", args->signature_file);
        free(data);
        exit(1);
    }
    sig_len = fread(signature, 1, sizeof(signature), sig_file);
    fclose(sig_file);

    if (sig_len == 0) {
        fprintf(stderr, "Error: Failed to read signature\n");
        free(data);
        exit(1);
    }

    if (verify_signature(args->key_name, data, data_len, signature, sig_len)) {
        printf("Signature verified successfully\n");
    } else {
        fprintf(stderr, "Error: Signature verification failed\n");
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

void handle_import_public_key_command(const CommandLineArgs* args) {
    char pem_key[PEM_KEY_CHAR_ARR_SIZE];
    size_t pem_len = 0;

    if (args->input_file) {
        unsigned char* data = read_file(args->input_file, &pem_len);
        if (data) {
            strncpy(pem_key, (char*)data, sizeof(pem_key) - 1);
            pem_key[sizeof(pem_key) - 1] = '\0';
            free(data);
        } else {
            fprintf(stderr, "Error: Failed to read input file\n");
            exit(1);
        }
    } else if (args->input_string) {
        pem_len = strlen(args->input_string);
        strncpy(pem_key, args->input_string, sizeof(pem_key) - 1);
        pem_key[sizeof(pem_key) - 1] = '\0';
    } else {
        pem_len = fread(pem_key, 1, sizeof(pem_key), stdin);
    }

    if (import_public_key(args->key_name, pem_key)) {
        printf("Public key imported successfully\n");
    } else {
        fprintf(stderr, "Public key import failed\n");
        exit(1);
    }
}
