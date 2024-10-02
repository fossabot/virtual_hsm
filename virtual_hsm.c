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
#define IV_SIZE 16
#define MAX_FILENAME 256
#define MAX_NAME_LENGTH 49

typedef struct {
    char name[MAX_NAME_LENGTH + 1];
    unsigned char encrypted_key[KEY_SIZE + EVP_MAX_BLOCK_LENGTH];
    unsigned char iv[IV_SIZE];
    int encrypted_len;
} KeyEntry;

KeyEntry keystore[MAX_KEYS];
int key_count = 0;
unsigned char master_key[KEY_SIZE];

char keystore_file[MAX_FILENAME] = "keystore.dat";
char master_key_file[MAX_FILENAME] = "master.key";

void handle_errors() {
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
        if (strlen(provided_key) != KEY_SIZE) {
            fprintf(stderr, "Error: Invalid master key length. Expected %d characters, got %zu.\n", KEY_SIZE, strlen(provided_key));
            exit(1);
        }
        for (int i = 0; i < KEY_SIZE; i++) {
            sscanf(provided_key + 2*i, "%2hhx", &master_key[i]);
        }
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

int encrypt_key(const unsigned char *plaintext, unsigned char *ciphertext, int *ciphertext_len, unsigned char *iv) {
    EVP_CIPHER_CTX *ctx;

    if (RAND_bytes(iv, IV_SIZE) != 1) {
        handle_errors();
    }

    if (!(ctx = EVP_CIPHER_CTX_new())) handle_errors();

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, master_key, iv))
        handle_errors();

    int len;
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, KEY_SIZE))
        handle_errors();
    *ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handle_errors();
    *ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

int decrypt_key(const unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext, const unsigned char *iv) {
    EVP_CIPHER_CTX *ctx;

    if (!(ctx = EVP_CIPHER_CTX_new())) handle_errors();

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, master_key, iv))
        handle_errors();

    int len;
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handle_errors();
    int plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handle_errors();
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
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

    for (int i = 0; i < key_count; i++) {
        if (strcmp(keystore[i].name, name) == 0) {
            fprintf(stderr, "Error: Key with this name already exists.\n");
            exit(1);
        }
    }

    KeyEntry *entry = &keystore[key_count++];
    strncpy(entry->name, name, MAX_NAME_LENGTH);
    entry->name[MAX_NAME_LENGTH] = '\0';
    if (!encrypt_key(key, entry->encrypted_key, &entry->encrypted_len, entry->iv)) {
        fprintf(stderr, "Error: Failed to encrypt key.\n");
        exit(1);
    }
    DEBUG_PRINT("Key '%s' encrypted successfully", name);
    save_keystore();
    DEBUG_PRINT("Keystore saved successfully");
    printf("Key stored successfully.\n");
}

void retrieve_key(const char *name, int pipe_mode) {
    DEBUG_PRINT("Entering retrieve_key function for key '%s'", name);
    for (int i = 0; i < key_count; i++) {
        if (strcmp(keystore[i].name, name) == 0) {
            DEBUG_PRINT("Key '%s' found in keystore", name);
            unsigned char decrypted_key[KEY_SIZE];
            int decrypted_len = decrypt_key(keystore[i].encrypted_key, keystore[i].encrypted_len, 
                                          decrypted_key, keystore[i].iv);
            
            if (decrypted_len != KEY_SIZE) {
                fprintf(stderr, "Error: Decrypted key length mismatch\n");
                exit(1);
            }
            
            // Print the key in hex format instead of binary
            for (int j = 0; j < KEY_SIZE; j++) {
                printf("%02x", decrypted_key[j]);
            }
            printf("\n");
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
    fprintf(stderr, "  -retrieve <key_name> [-pipe]\n");
    fprintf(stderr, "  -list\n");
    fprintf(stderr, "  -generate_master_key\n");
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
        unsigned char key[KEY_SIZE];
        if (fread(key, 1, KEY_SIZE, stdin) != KEY_SIZE) {
            fprintf(stderr, "Error: Invalid key input. Please provide 32 bytes.\n");
            return 1;
        }
        store_key(argv[i + 1], key);
    } else if (strcmp(argv[i], "-retrieve") == 0) {
        if (i + 1 >= argc) {
            print_usage();
            return 1;
        }
        int pipe_mode = (i + 2 < argc && strcmp(argv[i + 2], "-pipe") == 0);
        retrieve_key(argv[i + 1], pipe_mode);
    } else if (strcmp(argv[i], "-list") == 0) {
        list_keys();
    } else {
        print_usage();
        return 1;
    }

    return 0;
}
