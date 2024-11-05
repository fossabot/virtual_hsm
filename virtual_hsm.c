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

void handle_sign_command(const CommandLineArgs* args);
void handle_verify_command(const CommandLineArgs* args);
void handle_import_public_key_command(const CommandLineArgs* args);

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
    unsigned char *data = NULL;
    size_t data_len = 0;

    if (args->input_file) {
        data = read_file(args->input_file, &data_len);
        if (!data) {
            fprintf(stderr, "Error: Failed to read input file\n");
            exit(1);
        }
    } else if (args->input_string) {
        data = (unsigned char*)args->input_string;
        data_len = strlen(args->input_string);
    } else {
        fprintf(stderr, "Error: No input data provided for signing\n");
        exit(1);
    }

    unsigned char signature[MAX_SIGNATURE_SIZE];
    size_t sig_len = sizeof(signature);

    if (sign_data(args->key_name, data, data_len, signature, &sig_len)) {
        if (args->output_file) {
            write_file(args->output_file, signature, sig_len);
        } else {
            char default_output[MAX_FILENAME];
            snprintf(default_output, sizeof(default_output), "%s_signed", args->input_file);
            write_file(default_output, signature, sig_len);
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
    unsigned char signature[MAX_SIGNATURE_SIZE];
    unsigned char *data = NULL;
    size_t data_len = 0, sig_len = 0;

    if (args->input_file) {
        data = read_file(args->input_file, &data_len);
        sig_len = read_hex_string(args->input_string, signature, sizeof(signature));
    } else if (args->input_string) {
        data = (unsigned char*)args->input_string;
        data_len = strlen(args->input_string);
        sig_len = read_hex_string(args->input_string, signature, sizeof(signature));
    } else {
        fprintf(stderr, "Error: No input data or signature provided for verification\n");
        exit(1);
    }

    if (verify_signature(args->key_name, data, data_len, signature, sig_len)) {
        printf("Signature verified\n");
    } else {
        fprintf(stderr, "Error: Signature verification failed\n");
        free(data);
        exit(1);
    }

    free(data);
}

void handle_import_public_key_command(const CommandLineArgs* args) {
    char pem_key[PEM_KEY_CHAR_ARR_SIZE];
    size_t pem_len = 0;

    if (args->input_file) {
        pem_len = read_file(args->input_file, pem_key, sizeof(pem_key));
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
