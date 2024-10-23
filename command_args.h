#ifndef COMMAND_ARGS_H
#define COMMAND_ARGS_H

#include <stdio.h>
#include <string.h>

#define MAX_FILENAME 256
#define MAX_NAME_LENGTH 49

// Structure to hold parsed command line arguments
typedef struct {
    char keystore_file[MAX_FILENAME];
    char master_key_file[MAX_FILENAME];
    const char* provided_master_key;
    const char* command;
    const char* key_name;
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
}

void print_usage(void) {
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
