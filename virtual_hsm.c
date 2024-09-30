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

typedef struct {
    char name[50];
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
    abort();
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
}

void load_master_key() {
    FILE *file = fopen(master_key_file, "rb");
    if (file == NULL) {
        if (RAND_bytes(master_key, KEY_SIZE) != 1) {
            handle_errors();
        }
        file = fopen(master_key_file, "wb");
        fwrite(master_key, 1, KEY_SIZE, file);
    } else {
        fread(master_key, 1, KEY_SIZE, file);
    }
    fclose(file);
}

void save_keystore() {
    FILE *file = fopen(keystore_file, "wb");
    fwrite(&key_count, sizeof(int), 1, file);
    fwrite(keystore, sizeof(KeyEntry), key_count, file);
    fclose(file);
}

void load_keystore() {
    FILE *file = fopen(keystore_file, "rb");
    if (file != NULL) {
        fread(&key_count, sizeof(int), 1, file);
        fread(keystore, sizeof(KeyEntry), key_count, file);
        fclose(file);
    }
}

int encrypt_key(const unsigned char *plaintext, unsigned char *ciphertext, int *ciphertext_len, unsigned char *iv) {
    EVP_CIPHER_CTX *ctx;

    if (RAND_bytes(iv, IV_SIZE) != 1) {
        handle_errors();
    }

    if (!(ctx = EVP_CIPHER_CTX_new())) handle_errors();

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, master_key, iv))
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

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, master_key, iv))
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
    if (key_count >= MAX_KEYS) {
        fprintf(stderr, "Error: Keystore is full.\n");
        exit(1);
    }

    for (int i = 0; i < key_count; i++) {
        if (strcmp(keystore[i].name, name) == 0) {
            fprintf(stderr, "Error: Key with this name already exists.\n");
            exit(1);
        }
    }

    KeyEntry *entry = &keystore[key_count++];
    strncpy(entry->name, name, sizeof(entry->name) - 1);
    if (!encrypt_key(key, entry->encrypted_key, &entry->encrypted_len, entry->iv)) {
        fprintf(stderr, "Error: Failed to encrypt key.\n");
        exit(1);
    }
    save_keystore();
    printf("Key stored successfully.\n");
}

void retrieve_key(const char *name, int pipe_mode) {
    for (int i = 0; i < key_count; i++) {
        if (strcmp(keystore[i].name, name) == 0) {
            unsigned char decrypted_key[KEY_SIZE];
            int decrypted_len = decrypt_key(keystore[i].encrypted_key, keystore[i].encrypted_len, decrypted_key, keystore[i].iv);
            if (decrypted_len != KEY_SIZE) {
                fprintf(stderr, "Error: Decrypted key length mismatch.\n");
                exit(1);
            }
            fwrite(decrypted_key, 1, KEY_SIZE, stdout);
            if (pipe_mode) {
                printf("\n");
            }
            return;
        }
    }
    fprintf(stderr, "Error: Key not found.\n");
    exit(1);
}

void list_keys() {
    for (int i = 0; i < key_count; i++) {
        printf("%s\n", keystore[i].name);
    }
}

int set_master_key_from_hex(const char *hex_key) {
    if (strlen(hex_key) != KEY_SIZE * 2) {
        fprintf(stderr, "Error: Invalid master key length. Expected %d characters.\n", KEY_SIZE * 2);
        return 0;
    }

    for (int i = 0; i < KEY_SIZE; i++) {
        sscanf(hex_key + 2*i, "%2hhx", &master_key[i]);
    }
    return 1;
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
    int i;
    int master_key_set = 0;
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-keystore") == 0 && i + 1 < argc) {
            strncpy(keystore_file, argv[++i], MAX_FILENAME - 1);
        } else if (strcmp(argv[i], "-master") == 0 && i + 1 < argc) {
            strncpy(master_key_file, argv[++i], MAX_FILENAME - 1);
        } else if (strcmp(argv[i], "-master_key") == 0 && i + 1 < argc) {
            if (set_master_key_from_hex(argv[++i])) {
                master_key_set = 1;
            } else {
                return 1;
            }
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

    if (!master_key_set) {
        load_master_key();
    }
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
