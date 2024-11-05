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
    size_t buffer_size = BUFFER_SIZE;
    
    if (args->input_file) {
        // Read data from file
        FILE *file = fopen(args->input_file, "rb");
        if (!file) {
            fprintf(stderr, "Error: Failed to open input file '%s'\n", args->input_file);
            exit(1);
        }
        
        fseek(file, 0, SEEK_END);
        data_len = ftell(file);
        fseek(file, 0, SEEK_SET);
        
        data = malloc(data_len);
        if (!data) {
            fprintf(stderr, "Error: Memory allocation failed\n");
            fclose(file);
            exit(1);
        }
        
        if (fread(data, 1, data_len, file) != data_len) {
            fprintf(stderr, "Error: Failed to read input file\n");
            free(data);
            fclose(file);
            exit(1);
        }
        
        fclose(file);
    } else {
        // Read data from stdin
        data = malloc(buffer_size);
        if (!data) {
            fprintf(stderr, "Error: Memory allocation failed\n");
            exit(1);
        }

        // Set stdin to non-blocking mode
        #ifdef _WIN32
            // Windows-specific non-blocking stdin
            int mode = _setmode(_fileno(stdin), _O_BINARY);
            if (mode == -1) {
                fprintf(stderr, "Error: Could not set binary mode\n");
                free(data);
                exit(1);
            }
        #else
            // Unix-specific non-blocking stdin
            int flags = fcntl(STDIN_FILENO, F_GETFL, 0);
            if (flags == -1) {
                fprintf(stderr, "Error: Could not get file status flags\n");
                free(data);
                exit(1);
            }
            if (fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK) == -1) {
                fprintf(stderr, "Error: Could not set non-blocking mode\n");
                free(data);
                exit(1);
            }
        #endif

        // Try to read with timeout
        struct timeval timeout;
        timeout.tv_sec = 1;  // 1 second timeout
        timeout.tv_usec = 0;
        
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);

        int ready = select(STDIN_FILENO + 1, &readfds, NULL, NULL, &timeout);
        if (ready <= 0) {
            fprintf(stderr, "Error: No input data provided for signing within timeout\n");
            free(data);
            exit(1);
        }

        // Reset stdin to blocking mode
        #ifdef _WIN32
            mode = _setmode(_fileno(stdin), _O_TEXT);
        #else
            if (fcntl(STDIN_FILENO, F_SETFL, flags) == -1) {
                fprintf(stderr, "Error: Could not reset blocking mode\n");
                free(data);
                exit(1);
            }
        #endif

        // Read the actual data
        while ((data_len += fread(data + data_len, 1, buffer_size - data_len, stdin)) == buffer_size) {
            buffer_size *= ARRAY_EXPANSION_MULTIPLE;
            unsigned char *temp = realloc(data, buffer_size);
            if (!temp) {
                fprintf(stderr, "Error: Memory reallocation failed\n");
                free(data);
                exit(1);
            }
            data = temp;
        }

        if (data_len == 0) {
            fprintf(stderr, "Error: No data read from input\n");
            free(data);
            exit(1);
        }
    }

    DEBUG_PRINT("Read data length: %zu", data_len);
    
    unsigned char signature[MAX_SIGNATURE_SIZE];
    size_t sig_len = sizeof(signature);

    if (sign_data(args->key_name, data, data_len, signature, &sig_len)) {
        DEBUG_PRINT("Signature created, length: %zu", sig_len);
        
        // Write the signature to the output file or stdout
        if (args->output_file) {
            FILE *file = fopen(args->output_file, "wb");
            if (!file) {
                fprintf(stderr, "Error: Failed to open output file '%s'\n", args->output_file);
                free(data);
                exit(1);
            }
            fwrite(signature, 1, sig_len, file);
            fclose(file);
        } else {
            fwrite(signature, 1, sig_len, stdout);
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
    size_t data_len = 0;
    size_t sig_len = 0;
    size_t buffer_size = BUFFER_SIZE;

    if (args->input_string) {
        // Use the provided input string
        data = (unsigned char*)args->input_string;
        data_len = strlen(args->input_string);
        sig_len = SIG_LENGTH;
        memcpy(signature, data + data_len - sig_len, sig_len);
        data_len -= sig_len;
    } else if (args->input_file) {
        // Read data from the provided input file
        FILE *file = fopen(args->input_file, "rb");
        if (!file) {
            fprintf(stderr, "Error: Failed to open input file '%s'\n", args->input_file);
            exit(1);
        }
        
        fseek(file, 0, SEEK_END);
        data_len = ftell(file);
        fseek(file, 0, SEEK_SET);
        
        data = malloc(data_len);
        if (!data) {
            fprintf(stderr, "Error: Memory allocation failed\n");
            fclose(file);
            exit(1);
        }
        
        if (fread(data, 1, data_len, file) != data_len) {
            fprintf(stderr, "Error: Failed to read input file\n");
            free(data);
            fclose(file);
            exit(1);
        }
        
        sig_len = SIG_LENGTH;
        memcpy(signature, data + data_len - sig_len, sig_len);
        data_len -= sig_len;
        
        fclose(file);
    } else {
        // Read data from stdin
        data = malloc(buffer_size);
        if (!data) {
            fprintf(stderr, "Error: Memory allocation failed\n");
            exit(1);
        }

        // Set stdin to non-blocking mode
        #ifdef _WIN32
            // Windows-specific non-blocking stdin
            int mode = _setmode(_fileno(stdin), _O_BINARY);
            if (mode == -1) {
                fprintf(stderr, "Error: Could not set binary mode\n");
                free(data);
                exit(1);
            }
        #else
            // Unix-specific non-blocking stdin
            int flags = fcntl(STDIN_FILENO, F_GETFL, 0);
            if (flags == -1) {
                fprintf(stderr, "Error: Could not get file status flags\n");
                free(data);
                exit(1);
            }
            if (fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK) == -1) {
                fprintf(stderr, "Error: Could not set non-blocking mode\n");
                free(data);
                exit(1);
            }
        #endif

        // Try to read with timeout
        struct timeval timeout;
        timeout.tv_sec = 1;  // 1 second timeout
        timeout.tv_usec = 0;
        
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);

        int ready = select(STDIN_FILENO + 1, &readfds, NULL, NULL, &timeout);
        if (ready <= 0) {
            fprintf(stderr, "Error: No input data provided for verification within timeout\n");
            free(data);
            exit(1);
        }

        // Reset stdin to blocking mode
        #ifdef _WIN32
            mode = _setmode(_fileno(stdin), _O_TEXT);
        #else
            if (fcntl(STDIN_FILENO, F_SETFL, flags) == -1) {
                fprintf(stderr, "Error: Could not reset blocking mode\n");
                free(data);
                exit(1);
            }
        #endif

        // Read the actual data
        while ((data_len += fread(data + data_len, 1, buffer_size - data_len, stdin)) == buffer_size) {
            buffer_size *= ARRAY_EXPANSION_MULTIPLE;
            unsigned char *temp = realloc(data, buffer_size);
            if (!temp) {
                fprintf(stderr, "Error: Memory reallocation failed\n");
                free(data);
                exit(1);
            }
            data = temp;
        }

        if (data_len < SIG_LENGTH) {
            fprintf(stderr, "Error: Input data too short or empty\n");
            free(data);
            exit(1);
        }

        sig_len = SIG_LENGTH;
        memcpy(signature, data + data_len - sig_len, sig_len);
        data_len -= sig_len;
    }

    if (verify_signature(args->key_name, data, data_len, signature, sig_len)) {
        printf("Signature verified\n");
    } else {
        fprintf(stderr, "Error: Signature verification failed\n");
        if (data != (unsigned char*)args->input_string) {
            free(data);
        }
        exit(1);
    }

    if (data != (unsigned char*)args->input_string) {
        free(data);
    }
}

void handle_import_public_key_command(const CommandLineArgs* args) {
    char pem_key[PEM_KEY_CHAR_ARR_SIZE];
    
    if (args->input_file) {
        // Read PEM key from file
        FILE *file = fopen(args->input_file, "r");
        if (!file) {
            fprintf(stderr, "Error: Failed to open input file '%s'\n", args->input_file);
            exit(1);
        }
        
        size_t pem_len = fread(pem_key, 1, sizeof(pem_key), file);
        pem_key[pem_len] = '\0';
        fclose(file);
    } else {
        // Read PEM key from stdin
        size_t pem_len = fread(pem_key, 1, sizeof(pem_key), stdin);
        pem_key[pem_len] = '\0';
    }

    if (import_public_key(args->key_name, pem_key)) {
        printf("Public key imported successfully\n");
    } else {
        fprintf(stderr, "Public key import failed\n");
        exit(1);
    }
}
