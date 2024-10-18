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
#define MAX_FILENAME 256
#define MAX_NAME_LENGTH 49

typedef struct {
    char name[MAX_NAME_LENGTH + 1];
    unsigned char encrypted_key[KEY_SIZE + EVP_MAX_BLOCK_LENGTH];
    unsigned char iv[IV_SIZE];
    unsigned char tag[TAG_SIZE];  // GCM authentication tag
    int encrypted_len;
} KeyEntry;

KeyEntry keystore[MAX_KEYS];
int key_count = 0;
unsigned char master_key[KEY_SIZE];

char keystore_file[MAX_FILENAME] = "keystore.dat";
char master_key_file[MAX_FILENAME] = "master.key";

// Our sub-programs
#include "digital_signature.h"

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

int encrypt_key(const unsigned char *plaintext, unsigned char *ciphertext, 
                int *ciphertext_len, unsigned char *iv, unsigned char *tag) {
    EVP_CIPHER_CTX *ctx;

    if (RAND_bytes(iv, IV_SIZE) != 1) {
        handle_errors();
    }

    if (!(ctx = EVP_CIPHER_CTX_new())) 
        handle_errors();

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, master_key, iv))
        handle_errors();

    int len;
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, KEY_SIZE))
        handle_errors();
    
    *ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handle_errors();
    
    *ciphertext_len += len;

    // Get the tag
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag))
        handle_errors();

    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

int decrypt_key(const unsigned char *ciphertext, int ciphertext_len,
                unsigned char *plaintext, const unsigned char *iv,
                const unsigned char *tag) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    DEBUG_PRINT("Entering decrypt_key function");
    DEBUG_PRINT("Ciphertext length: %d", ciphertext_len);
    DEBUG_PRINT("IV (first 4 bytes): %02x%02x%02x%02x", iv[0], iv[1], iv[2], iv[3]);

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        DEBUG_PRINT("Failed to create cipher context");
        handle_errors();
    }

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, master_key, iv)) {
        DEBUG_PRINT("Failed to initialize decryption");
        handle_errors();
    }

    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        DEBUG_PRINT("Failed during decryption update");
        handle_errors();
    }
    plaintext_len = len;

    // Set expected tag value
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, (void*)tag)) {
        DEBUG_PRINT("Failed to set authentication tag");
        handle_errors();
    }

    // Finalize decryption and verify tag
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    if (ret <= 0) {
        DEBUG_PRINT("Authentication failed or decrypt error");
        handle_errors();
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    DEBUG_PRINT("Decryption completed successfully");
    return plaintext_len;
}

void store_key(const char *name, const unsigned char *key) {
    DEBUG_PRINT("Entering store_key function for key '%s'", name);
    if (key_count >= MAX_KEYS) {
        fprintf(stderr, "Error: Keystore is full.\n");
        exit(1);
    }

    if (strlen(name) > MAX_NAME_LENGTH) {
        fprintf(stderr, "Error: Key name is too long.\n");
        exit(1);
    }

    KeyEntry *entry = &keystore[key_count++];
    strncpy(entry->name, name, MAX_NAME_LENGTH);
    entry->name[MAX_NAME_LENGTH] = '\0';

    DEBUG_PRINT("Starting encryption process");
    if (!encrypt_key(key, entry->encrypted_key, &entry->encrypted_len, 
                    entry->iv, entry->tag)) {
        fprintf(stderr, "Error: Failed to encrypt key.\n");
        exit(1);
    }
    
    save_keystore();
    DEBUG_PRINT("Key stored successfully");
}

void retrieve_key(const char *name) {
    DEBUG_PRINT("Entering retrieve_key function for key '%s'", name);
    for (int i = 0; i < key_count; i++) {
        if (strcmp(keystore[i].name, name) == 0) {
            DEBUG_PRINT("Key '%s' found in keystore", name);
            DEBUG_PRINT("Encrypted length: %d", keystore[i].encrypted_len);
            
            unsigned char decrypted_key[KEY_SIZE];
            memset(decrypted_key, 0, KEY_SIZE);
            
            DEBUG_PRINT("Starting decryption process");
            int decrypted_len = decrypt_key(keystore[i].encrypted_key, 
                                          keystore[i].encrypted_len,
                                          decrypted_key, 
                                          keystore[i].iv,
                                          keystore[i].tag);
            
            if (decrypted_len != KEY_SIZE) {
                fprintf(stderr, "Error: Decrypted key length mismatch\n");
                exit(1);
            }
            
            // Output in hex format
            for (int j = 0; j < KEY_SIZE; j++) {
                printf("%02x", decrypted_key[j]);
            }
            printf("\n");
            DEBUG_PRINT("Key retrieved successfully");
            return;
        }
    }
    fprintf(stderr, "Error: Key '%s' not found.\n", name);
    exit(1);
}

void list_keys() {
    for (int i = 0; i < key_count; i++) {
        printf("%s\n", keystore[i].name);
    }
}

void print_usage() {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  ./virtual_hsm [-keystore <keystore_file>] [-master <master_key_file>] [-master_key <hex_key>] <command> [options]\n");
    fprintf(stderr, "Commands:\n");
    fprintf(stderr, "  -store <key_name>\n");
    fprintf(stderr, "  -retrieve <key_name>\n");
    fprintf(stderr, "  -list\n");
    fprintf(stderr, "  -generate_master_key\n");
    fprintf(stderr, "  -generate_key_pair <key_name>\n");
    fprintf(stderr, "  -sign <key_name>\n");
    fprintf(stderr, "  -verify <key_name>\n");
    fprintf(stderr, "  -export_public_key <key_name>\n");
    fprintf(stderr, "  -import_public_key <key_name>\n");
}

int main(int argc, char *argv[]) {
    fprintf(stderr, "Debug: Starting virtual_hsm\n");
    int i;
    const char *provided_master_key = NULL;
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-keystore") == 0 && i + 1 < argc) {
            strncpy(keystore_file, argv[++i], MAX_FILENAME - 1);
            keystore_file[MAX_FILENAME - 1] = '\0';
        } else if (strcmp(argv[i], "-master") == 0 && i + 1 < argc) {
            strncpy(master_key_file, argv[++i], MAX_FILENAME - 1);
            master_key_file[MAX_FILENAME - 1] = '\0';
        } else if (strcmp(argv[i], "-master_key") == 0 && i + 1 < argc) {
            provided_master_key = argv[++i];
        } else {
            break;
        }
    }

    if (i >= argc) {
        print_usage();
        return 1;
    }

    if (strcmp(argv[i], "-generate_master_key") == 0) {
        generate_master_key();
        return 0;
    }

    load_master_key(provided_master_key);
    load_keystore();

    if (strcmp(argv[i], "-store") == 0) {
        if (i + 1 >= argc) {
            print_usage();
            return 1;
        }
        // Read hex string from stdin
        char hex_key[KEY_SIZE * 2 + 1];
        if (fread(hex_key, 1, KEY_SIZE * 2, stdin) != KEY_SIZE * 2) {
            fprintf(stderr, "Error: Invalid key input. Please provide %d hex characters.\n", KEY_SIZE * 2);
            return 1;
        }
        hex_key[KEY_SIZE * 2] = '\0';
        
        // Convert hex to binary
        unsigned char binary_key[KEY_SIZE];
        hex_to_bytes(hex_key, binary_key, KEY_SIZE);
        
        store_key(argv[i + 1], binary_key);
    } else if (strcmp(argv[i], "-retrieve") == 0) {
        if (i + 1 >= argc) {
            print_usage();
            return 1;
        }

        retrieve_key(argv[i + 1]);
    } else if (strcmp(argv[i], "-list") == 0) {
        list_keys();
    } else if (strcmp(argv[i], "-generate_key_pair") == 0) {
    if (i + 1 >= argc) {
        print_usage();
        return 1;
    }
    generate_key_pair(argv[i + 1]);
    } else if (strcmp(argv[i], "-sign") == 0) {
        if (i + 1 >= argc) {
            print_usage();
            return 1;
        }
        unsigned char signature[MAX_SIGNATURE_SIZE];
        size_t sig_len = sizeof(signature);
        unsigned char data[1024];
        size_t data_len = fread(data, 1, sizeof(data), stdin);
        
        DEBUG_PRINT("Signing data for key: %s", argv[i + 1]);
        DEBUG_PRINT("Data length: %zu", data_len);
        
        if (sign_data(argv[i + 1], data, data_len, signature, &sig_len)) {
            DEBUG_PRINT("Signature created, length: %zu", sig_len);
            fwrite(signature, 1, sig_len, stdout);
        } else {
            fprintf(stderr, "Signing failed\n");
            return 1;
        }
    } else if (strcmp(argv[i], "-verify") == 0) {
        if (i + 2 >= argc) {
            print_usage();
            return 1;
        }
        unsigned char signature[MAX_SIGNATURE_SIZE];
        size_t sig_len = fread(signature, 1, sizeof(signature), stdin);
        unsigned char data[1024];
        size_t data_len = fread(data, 1, sizeof(data), stdin);
        if (verify_signature(argv[i + 1], data, data_len, signature, sig_len)) {
            printf("Signature verified\n");
        } else {
            fprintf(stderr, "Signature verification failed\n");
            return 1;
        }
} else if (strcmp(argv[i], "-export_public_key") == 0) {
    if (i + 1 >= argc) {
        print_usage();
        return 1;
    }
    char *pem_key;
    if (export_public_key(argv[i + 1], &pem_key)) {
        printf("%s", pem_key);
        free(pem_key);
    } else {
        fprintf(stderr, "Public key export failed\n");
        return 1;
    }
} else if (strcmp(argv[i], "-import_public_key") == 0) {
    if (i + 1 >= argc) {
        print_usage();
        return 1;
    }
    char pem_key[4096];
    size_t pem_len = fread(pem_key, 1, sizeof(pem_key), stdin);
    pem_key[pem_len] = '\0';
    if (import_public_key(argv[i + 1], pem_key)) {
        printf("Public key imported successfully\n");
    } else {
        fprintf(stderr, "Public key import failed\n");
        return 1;
    }
    
} else {
        print_usage();
        return 1;
    }

    return 0;
}
