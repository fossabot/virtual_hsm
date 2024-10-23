#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Utility Functions
int hex_to_int(char c);
void hex_to_bytes(const char *hex, unsigned char *bytes, size_t length);
void handle_errors(void);

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
    char err_msg[CHAR_ERR_MSG_ARRAY];
    ERR_error_string_n(err, err_msg, sizeof(err_msg));
    fprintf(stderr, "Debug: OpenSSL Error: %s\n", err_msg);
    ERR_print_errors_fp(stderr);
    exit(1);
}

#endif // UTILS_H
