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

#define MAX_KEYS 100
#define KEY_SIZE 32 
#define IV_SIZE 12  
#define TAG_SIZE 16 // GCM tag size

typedef struct {
    char name[MAX_NAME_LENGTH + 1];
    unsigned char key_data[KEY_SIZE];
    unsigned char iv[IV_SIZE];
    unsigned char tag[TAG_SIZE];
    int encrypted_len;
    int is_public_key;
} KeyEntry;

KeyEntry keystore[MAX_KEYS];
int key_count = 0;
unsigned char master_key[KEY_SIZE];

char keystore_file[MAX_FILENAME] = "keystore.dat";
char master_key_file[MAX_FILENAME] = "master.key";

// Function prototypes
void handle_errors(void);
void generate_master_key(void);
void load_master_key(const char *provided_key);
void save_keystore(void);
void load_keystore(void);
int encrypt_key(const unsigned char *plaintext, unsigned char *ciphertext, 
                int *ciphertext_len, unsigned char *iv, unsigned char *tag);
int decrypt_key(const unsigned char *ciphertext, int ciphertext_len,
                unsigned char *plaintext, const unsigned char *iv,
                const unsigned char *tag);
void store_key(const char *name, const unsigned char *key, int is_public_key);
void retrieve_key(const char *name);
void list_keys(void);
void store_public_key(const char *name, const unsigned char *key, size_t key_len);
void handle_sign_command(const char* key_name);
void handle_verify_command(const char* key_name);
void handle_export_public_key_command(const char* key_name);
void handle_import_public_key_command(const char* key_name);

// our header funcs
#include "digital_signature.h"
#include "command_args.h"

// Utility Functions
int hex_to_int(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

void hex_to_bytes(const char *hex, unsigned char *bytes, size_t length) {
    DEBUG_PRINT("Converting hex string to bytes: %s", hex);
    for (size_t i = 0; i < length; i++) {
        bytes[i] = (hex_to_int(hex[i*2]) << 4) | hex_to_int(hex[i*2 + 1]);
    }
}

void handle_errors() {
    unsigned long err = ERR_get_error();
    char err_msg[256];
    ERR_error_string_n(err, err_msg, sizeof(err_msg));
    fprintf(stderr, "Debug: OpenSSL Error: %s\n", err_msg);
    ERR_print_errors_fp(stderr);
    exit(1);
}

void generate_master_key() {
    unsigned char new_master_key[KEY_SIZE];
    if (RAND_bytes(new_master_key, KEY_SIZE) != 1) {
        handle_errors();
    }

    printf("Generated Master Key (hex format for GitHub Secret):\n");
    for (int i = 0; i < KEY_SIZE; i++) {
        printf("%02x", new_master_key[i]);
    }
    printf("\n");

    FILE *file = fopen(master_key_file, "wb");
    if (file == NULL) {
        fprintf(stderr, "Error: Unable to open master key file for writing.\n");
        exit(1);
    }
    fwrite(new_master_key, 1, KEY_SIZE, file);
    fclose(file);

    printf("WARNING: The master key has been stored in %s. This is insecure and should only be used for educational purposes.\n", master_key_file);
}

void load_master_key(const char *provided_key) {
    DEBUG_PRINT("Entering load_master_key function");
    if (provided_key) {
        DEBUG_PRINT("Master key provided via command line");
        if (strlen(provided_key) != KEY_SIZE * 2) {
            fprintf(stderr, "Error: Invalid master key length. Expected %d hex characters, got %zu.\n", 
                    KEY_SIZE * 2, strlen(provided_key));
            exit(1);
        }
        hex_to_bytes(provided_key, master_key, KEY_SIZE);
        DEBUG_PRINT("Master key loaded successfully");
        return;
    }

    FILE *file = fopen(master_key_file, "rb");
    if (file == NULL) {
        fprintf(stderr, "Error: Master key file not found and no key provided.\n");
        exit(1);
    } else {
        if (fread(master_key, 1, KEY_SIZE, file) != KEY_SIZE) {
            fprintf(stderr, "Error: Invalid master key file.\n");
            fclose(file);
            exit(1);
        }
        fclose(file);
        printf("WARNING: Master key loaded from file. This is insecure and should only be used for educational purposes.\n");
    }
}

void save_keystore() {
    FILE *file = fopen(keystore_file, "wb");
    if (file == NULL) {
        fprintf(stderr, "Error opening keystore file for writing.\n");
        exit(1);
    }
    fwrite(&key_count, sizeof(int), 1, file);
    fwrite(keystore, sizeof(KeyEntry), key_count, file);
    fclose(file);
}

void load_keystore() {
    DEBUG_PRINT("Entering load_keystore function");
    FILE *file = fopen(keystore_file, "rb");
    if (file != NULL) {
        fread(&key_count, sizeof(int), 1, file);
        fread(keystore, sizeof(KeyEntry), key_count, file);
        fclose(file);
        DEBUG_PRINT("Keystore loaded with %d keys", key_count);
    } else {
        DEBUG_PRINT("No existing keystore found");
    }
}

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

[Rest of the encryption/decryption and key handling functions remain the same...]

// Main function updated to use command_args.h
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
