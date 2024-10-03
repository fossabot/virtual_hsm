# Virtual Hardware Security Management (HSM) Program

A virtualized hardware security management tool for students to leverage in various assignments for the NYU Application Security course.

## Table of Contents
- [Overview](#overview)
- [Design Notes](#design-notes)
- [Operation Notes](#operation-notes)
- [Usage](#usage)
  - [Compilation](#compilation)
  - [Key Management](#key-management)
  - [File Operations](#file-operations)
  - [Custom Keystore and Master Key Files](#custom-keystore-and-master-key-files)
- [GitHub Secrets and Actions Workflow](#github-secrets-and-actions-workflow)
- [Generating a Master Key for GitHub Secrets](#generating-a-master-key-for-github-secrets)
- [Known Limitations](#known-limitations)
- [Debug Output](#debug-output)

## Overview

This HSM is exceptionally simple and is not meant to be a true HSM, but simply a virtualized expression of one that can be addressed via terminal commands. 

**Warning: Do not use in production environments**

## Design Notes

- Uses the EVP (Envelope) interface for encryption and decryption, as recommended in OpenSSL 3.0
- Implements error handling using OpenSSL's error reporting functions
- Employs AES-256-GCM encryption with a unique IV for each key
- Provides persistent storage through `keystore.dat` and `master.key` split-paired files
- Fully supports GitHub Secrets and Actions Workflow passing as Hexadecimal via command line

## Operation Notes

Upon execution, the program generates two files:

1. `keystore.dat`: An encrypted database file storing the key information
2. `master.key`: The master key file required to access the HSM (paired with `keystore.dat`)

Input/Output:
- Key storage: Reads 64 hexadecimal characters (representing 32 bytes) from stdin
- Key retrieval: Prints the key in hexadecimal format (64 characters) to stdout with a newline


Why is this true:

Each hexadecimal character represents 4 bits. Since there are 64 hexadecimal characters, they represent a total of 64 * 4 = 256 bits (or 32 bytes).

## Usage

### Compilation

```bash
gcc -o virtual_hsm virtual_hsm.c -lcrypto
```

### Key Management

Store a key (must be exactly 64 hexadecimal characters):
```bash
echo -n "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF" | ./virtual_hsm -store mykey
```

Retrieve a key (outputs in hex format):
```bash
./virtual_hsm -retrieve mykey
```

List keys:
```bash
./virtual_hsm -list
```

### File Operations

Save key output to file:
```bash
./virtual_hsm -retrieve mykey > key.hex
```

Set environmental variable (will contain hex representation):
```bash
export MY_SECRET_KEY=$(./virtual_hsm -retrieve mykey)
```

### Custom Keystore and Master Key Files

Store a key with custom file names:
```bash
echo -n "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF" | \
./virtual_hsm -keystore "appseckeystore.dat" -master "masterAppsec.key" -store mykey
```

Retrieve a key with custom file names:
```bash
./virtual_hsm -keystore "appseckeystore.dat" -master "masterAppsec.key" -retrieve mykey
```

List keys with custom file names:
```bash
./virtual_hsm -keystore "appseckeystore.dat" -master "masterAppsec.key" -list
```

## GitHub Secrets and Actions Workflow

You can pass the master key directly as a command-line argument using the `-master_key` option followed by a 64-character hexadecimal string (representing the 32-byte key).

Example:
```bash
./virtual_hsm -master_key 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF -store my_key
```

In a GitHub Actions workflow:
```yaml
- name: Run virtual HSM
  run: ./virtual_hsm -master_key 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF -store my_key
```
  
Secrets on a GitHub Actions workflow:
```yaml
- name: Run virtual HSM
  run: ./virtual_hsm -master_key ${{ secrets.MASTER_KEY }} -store my_key
```


## Generating a Master Key for GitHub Secrets

Generate a master key suitable for use as a GitHub Secret:
```bash
./virtual_hsm -generate_master_key
```

This will output a hexadecimal string that you can use to create a new GitHub Secret:

1. In your GitHub repository, go to Settings > Secrets and variables > Actions
2. Click on "New repository secret"
3. Name the secret (e.g., "MASTER_KEY")
4. Paste the generated hexadecimal string as the secret value
5. Click "Add secret"

## Debug Output

The program includes debug output that is printed to stderr. These messages are prefixed with "Debug:" and provide information about the program's operation, including:
- Key operations (storage and retrieval)
- Encryption and decryption processes
- File operations
- Error conditions

These debug messages can be helpful for troubleshooting but are not part of the program's main output.

## Known Limitations

This implementation is for educational purposes and lacks several security features found in production HSMs:

- Secure memory management
- Access controls and authentication
- Audit logging
- Proper key lifecycle management
- Protection against side-channel attacks
- Undefined behavior protection (e.g., filename bounds checking)
- No secure key erasure from memory
- And many more!
