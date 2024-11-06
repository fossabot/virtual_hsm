#ifndef COMMAND_ARGS_H
#define COMMAND_ARGS_H

#include <stdio.h>
#include <string.h>

// Our imports
#include "common_defs.h"

#define MAX_FILENAME 256
#define MAX_NAME_LENGTH 49

// Structure to hold parsed command line arguments
typedef struct {
    char keystore_file[MAX_FILENAME];
    char master_key_file[MAX_FILENAME];
    const char* provided_master_key;
    const char* command;
    const char* key_name;
    const char* input_file;
    const char* output_file;
    const char* signature_file; 
    const char* input_string;
    int use_stdin;              // Flag to indicate if using stdin
} CommandLineArgs;

// Function prototypes
void init_command_line_args(CommandLineArgs* args);
void update_global_paths(const CommandLineArgs* args);
int handle_arguments(int argc, char *argv[], CommandLineArgs* args);
void print_usage(void);

// Implementation of command line argument handling functions
void init_command_line_args(CommandLineArgs* args) {
    memset(args->keystore_file, 0, MAX_FILENAME);
    memset(args->master_key_file, 0, MAX_FILENAME);
    args->provided_master_key = NULL;
    args->command = NULL;
    args->key_name = NULL;
    args->input_file = NULL;
    args->output_file = NULL;
    args->signature_file = NULL;
    args->input_string = NULL;
    args->use_stdin = 0;
}

void print_usage(void) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  ./virtual_hsm [-keystore <keystore_file>] [-master <master_key_file>] [-master_key <hex_key>] <command> [options]\n\n");
    
    fprintf(stderr, "Global Options:\n");
    fprintf(stderr, "  -keystore <file>      Specify custom keystore file (default: keystore.dat)\n");
    fprintf(stderr, "  -master <file>        Specify custom master key file (default: master.key)\n");
    fprintf(stderr, "  -master_key <hex>     Provide master key directly as hex string\n\n");
    
    fprintf(stderr, "Commands:\n");
    fprintf(stderr, "  Key Management:\n");
    fprintf(stderr, "    -store <key_name>           Store a symmetric key (read hex from stdin)\n");
    fprintf(stderr, "                                Example: echo \"0123456789abcdef\" | ./virtual_hsm -store mykey\n\n");
    
    fprintf(stderr, "    -retrieve <key_name>        Retrieve a key's value in hex format\n");
    fprintf(stderr, "                                Example: ./virtual_hsm -retrieve mykey\n\n");
    
    fprintf(stderr, "    -list                       List all stored key names\n");
    fprintf(stderr, "                                Example: ./virtual_hsm -list\n\n");
    
    fprintf(stderr, "  Master Key Operations:\n");
    fprintf(stderr, "    -generate_master_key        Generate a new master key\n");
    fprintf(stderr, "                                Example: ./virtual_hsm -generate_master_key\n\n");
    
    fprintf(stderr, "  Asymmetric Key Operations:\n");
    fprintf(stderr, "    -generate_key_pair <name>   Generate ED25519 key pair\n");
    fprintf(stderr, "                                Creates both <name> (private) and <name>_public\n");
    fprintf(stderr, "                                Example: ./virtual_hsm -generate_key_pair signing_key\n\n");
    
    fprintf(stderr, "    -sign <key_name>           Sign data using private key (data from stdin)\n");
    fprintf(stderr, "                                IMPORTANT: The signature is output to stdout and must be\n");
    fprintf(stderr, "                                saved to a file for later verification.\n");
    fprintf(stderr, "                                Examples:\n");
    fprintf(stderr, "                                  # Sign data and save signature:\n");
    fprintf(stderr, "                                  echo -n \"hello\" | ./virtual_hsm -sign signing_key > signature.bin\n");
    fprintf(stderr, "                                  # Sign a file and save signature:\n");
    fprintf(stderr, "                                  cat file.txt | ./virtual_hsm -sign signing_key > signature.bin\n");
    fprintf(stderr, "                                  # Without saving signature (NOT RECOMMENDED):\n");
    fprintf(stderr, "                                  echo -n \"hello\" | ./virtual_hsm -sign signing_key\n\n");
    
    fprintf(stderr, "    -verify <key_name>         Verify signature using either:\n");
    fprintf(stderr, "                                1. Concatenated input via stdin:\n");
    fprintf(stderr, "                                   cat file.txt signature.bin | ./virtual_hsm -verify signing_key_public\n");
    fprintf(stderr, "                                   (echo -n \"hello\"; cat signature.bin) | ./virtual_hsm -verify signing_key_public\n\n");
    fprintf(stderr, "                                2. Separate files:\n");
    fprintf(stderr, "                                   ./virtual_hsm -verify signing_key_public -in data.txt -sig signature.bin\n\n");
    
    
    fprintf(stderr, "    -export_public_key <name>   Export public key in PEM format\n");
    fprintf(stderr, "                                Example: ./virtual_hsm -export_public_key signing_key_public\n\n");
    
    fprintf(stderr, "    -import_public_key <name>   Import public key from PEM format (read from stdin)\n");
    fprintf(stderr, "                                Example: cat public.pem | ./virtual_hsm -import_public_key new_key\n\n");
    
    fprintf(stderr, "Notes:\n");
    fprintf(stderr, "  - All keys are stored encrypted using the master key\n");
    fprintf(stderr, "  - Public keys from key pairs are stored with '_public' suffix\n");
    fprintf(stderr, "  - Max key name length is %d characters\n", MAX_NAME_LENGTH);
    fprintf(stderr, "  - When signing data:\n");
    fprintf(stderr, "    * The signature is output in binary format to stdout\n");
    fprintf(stderr, "    * You MUST save the signature to verify it later (use > signature.bin)\n");
    fprintf(stderr, "    * The signature file is required for verification\n");
    fprintf(stderr, "  - When verifying:\n");
    fprintf(stderr, "    * You must provide both the original data AND its signature\n");
    fprintf(stderr, "    * The data must come first, followed by the signature\n");
    fprintf(stderr, "    * Use cat to concatenate them together as shown in examples\n\n");
    
    fprintf(stderr, "Complete Example Workflow for Digital Signatures:\n");
    fprintf(stderr, "  1. Generate a key pair:\n");
    fprintf(stderr, "     ./virtual_hsm -generate_key_pair mykey\n\n");
    
    fprintf(stderr, "  2. Sign a file (MUST save the signature):\n");
    fprintf(stderr, "     cat myfile.txt | ./virtual_hsm -sign mykey > signature.bin\n\n");
    
    fprintf(stderr, "  3. Verify the file with its signature:\n");
    fprintf(stderr, "     cat myfile.txt signature.bin | ./virtual_hsm -verify mykey_public\n\n");
    
    fprintf(stderr, "  NOTE: Running just './virtual_hsm -sign mykey' without saving the signature\n");
    fprintf(stderr, "        will output the binary signature to the terminal, making it unusable\n");
    fprintf(stderr, "        for later verification. Always save signatures to a file!\n");
}

int handle_arguments(int argc, char *argv[], CommandLineArgs* args) {
    if (argc < 2) {
        print_usage();
        return 0;
    }

    init_command_line_args(args);

    int i;
    // Parse optional arguments first
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-keystore") == 0 && i + 1 < argc) {
            strncpy(args->keystore_file, argv[++i], MAX_FILENAME - 1);
            args->keystore_file[MAX_FILENAME - 1] = '\0';
        } else if (strcmp(argv[i], "-master") == 0 && i + 1 < argc) {
            strncpy(args->master_key_file, argv[++i], MAX_FILENAME - 1);
            args->master_key_file[MAX_FILENAME - 1] = '\0';
        } else if (strcmp(argv[i], "-master_key") == 0 && i + 1 < argc) {
            args->provided_master_key = argv[++i];
        } else {
            break;  // Found the command
        }
    }

    if (i >= argc) {
        print_usage();
        return 0;
    }

    // Store the command
    args->command = argv[i];
    
    // Store the key name if the command requires it
    if (i + 1 < argc && strcmp(args->command, "-list") != 0 && 
        strcmp(args->command, "-generate_master_key") != 0) {
        args->key_name = argv[i + 1];
        i++;  // Move past the key name
    }

    // Parse additional arguments for verify command
    if (strcmp(args->command, "-verify") == 0) {
        args->use_stdin = 1;  // Default to stdin unless files are specified
        
        // Parse remaining arguments for file inputs
        for (i++; i < argc; i++) {
            if (strcmp(argv[i], "-in") == 0 && i + 1 < argc) {
                args->input_file = argv[++i];
                args->use_stdin = 0;
            } else if (strcmp(argv[i], "-sig") == 0 && i + 1 < argc) {
                args->signature_file = argv[++i];
                args->use_stdin = 0;
            }
        }

        // Validate that if one file is specified, both must be
        if ((args->input_file && !args->signature_file) || 
            (!args->input_file && args->signature_file)) {
            fprintf(stderr, "Error: Both -in and -sig must be specified when using file inputs\n");
            return 0;
        }
    }

    // Validate command and arguments
    if (strcmp(args->command, "-store") == 0 ||
        strcmp(args->command, "-retrieve") == 0 ||
        strcmp(args->command, "-generate_key_pair") == 0 ||
        strcmp(args->command, "-sign") == 0 ||
        strcmp(args->command, "-verify") == 0 ||
        strcmp(args->command, "-export_public_key") == 0 ||
        strcmp(args->command, "-import_public_key") == 0) {
        if (!args->key_name) {
            fprintf(stderr, "Error: Key name required for %s command\n", args->command);
            print_usage();
            return 0;
        }
    } else if (strcmp(args->command, "-list") != 0 && 
               strcmp(args->command, "-generate_master_key") != 0) {
        fprintf(stderr, "Error: Unknown command: %s\n", args->command);
        print_usage();
        return 0;
    }

    return 1;
}

#endif // COMMAND_ARGS_H
