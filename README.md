# Virtual Hardware Security Management (HSM) Program
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fahillelt%2Fvirtual_hsm.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fahillelt%2Fvirtual_hsm?ref=badge_shield)


A virtualized hardware security management tool.

## Table of Contents
- [Overview](#overview)
- [Design Notes](#design-notes)
- [Operation Notes](#operation-notes)
- [Usage](#usage)
  - [Compilation](#compilation)
  - [Command-line Options](#command-line-options)
  - [Key Management](#key-management)
  - [Digital Signatures](#digital-signatures)
  - [Public Key Operations](#public-key-operations)
  - [File Operations](#file-operations)
  - [Custom Keystore and Master Key Files](#custom-keystore-and-master-key-files)
- [GitHub Secrets and Actions Workflow](#github-secrets-and-actions-workflow)
- [Generating a Master Key for GitHub Secrets](#generating-a-master-key-for-github-secrets)
- [Debug Output](#debug-output)
- [Known Limitations](#known-limitations)

## Overview

This virtual HSM is relatively simple and is not meant to be a true HSM, there is no actual hardware management platform in use. This is a virtualized expression of an HSM that can be addressed via terminal commands. The purpose of the program is to assist those in learning how to interact with HSMs and their functionality. It does provide encryption services, key storage, and ED25519 digital signatures. However, it's all done without storage in a secure hardware environment. 

**Warning: Do not use in production environments**

## Design Notes

- Uses the EVP (Envelope) interface for encryption and decryption, with Ed25519 signing
- Implements error handling using OpenSSL's error reporting functions
- Employs AES-256-GCM encryption with a unique IV for each key
- Uses 32-byte (256-bit) keys for Ed25519 digital signatures
- Provides persistent storage through `keystore.dat` and `master.key` split-paired files
- Fully supports GitHub Secrets and Actions Workflow passing as Hexadecimal via command line
- Supports digital signatures using Ed25519 algorithm
- Allows generation, storage, and management of public/private key pairs

## Operation Notes

Upon execution, the program generates two files:

1. `keystore.dat`: An encrypted database file storing the key information
2. `master.key`: The master key file required to access the HSM (paired with `keystore.dat`)

Input/Output:
- Key storage: Reads 64 hexadecimal characters (representing 32 bytes) from stdin (terminal)
- Key retrieval: Prints the key in hexadecimal format (64 characters) to stdout (terminal) with a newline for easy capture
- Digital signatures: Reads data from stdin, outputs signature to stdout
- Public key export: Outputs public key in PEM format to stdout
- Public key import: Reads PEM formatted public key from stdin
- The program exits with a non-zero status code on errors
- instead of terminal we can pipe to file

The keystore.dat file stores keys in a binary format, with each key entry containing:
- Key name (up to 49 characters)
- Key data (32 bytes)
- Initialization Vector (12 bytes)
- GCM Tag (16 bytes)
- Encrypted data length
- A flag indicating if it's a public key

Why is a 64 character Hexadecimal output representative of 256 bits?:

Each hexadecimal character represents 4 bits. Since there are 64 hexadecimal characters, they represent a total of 64 * 4 = 256 bits (or 32 bytes).

## Usage

### Compilation

```bash
gcc -o virtual_hsm virtual_hsm.c -lcrypto
```

### Command-line Options

- `-keystore <keystore_file>`: Specify a custom keystore file
- `-master <master_key_file>`: Specify a custom master key file
- `-master_key <hex_key>`: Provide the master key directly as a hex string
- `-generate_master_key`: Generate a new master key
- `-store <key_name>`: Store a new key
- `-retrieve <key_name>`: Retrieve a stored key
- `-list`: List all stored keys
- `-generate_key_pair <key_name>`: Generate a new Ed25519 key pair
- `-sign <key_name>`: Sign data using the specified key
- `-verify <key_name>`: Verify a signature using the specified key
- `-export_public_key <key_name>`: Export a public key in PEM format
- `-import_public_key <key_name>`: Import a public key in PEM format

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

Generate a key pair:
```bash
./virtual_hsm -generate_key_pair mykeypair
```
This generates both a private key "mykeypair" and a public key "mykeypair_public".

### Digital Signatures

Sign data:
```bash
echo -n "Hello, World!" | ./virtual_hsm -sign mykeypair
```

Verify signature:
```bash
(echo -n "Hello, World!"; cat signature.bin) | ./virtual_hsm -verify mykeypair_public
```
Note: The data (17 bytes) should be followed by the signature (64 bytes).

### Public Key Operations

Export public key:
```bash
./virtual_hsm -export_public_key mykeypair_public
```

Import public key:
```bash
cat public_key.pem | ./virtual_hsm -import_public_key imported_public_key
```

Note: Public keys are stored unencrypted in the keystore.

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
- Digital signature operations
- Public key operations

These debug messages can be helpful for troubleshooting but are not part of the program's main output.

To view debug output, redirect stderr to a file or the console:
```bash
./virtual_hsm -list 2>debug.log
```
or
```bash
./virtual_hsm -list 2>&1
```

## Known Limitations

This implementation is for educational purposes and lacks several security features found in production HSMs:

- Secure memory management
- Access controls and authentication
- Audit logging
- Proper key lifecycle management
- Protection against side-channel attacks
- Undefined behavior protection (e.g., filename bounds checking)
- No secure key erasure from memory
- Limited error handling for some operations
- No protection against key overwriting
- No built-in key rotation mechanism
- And many more!


## License
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fahillelt%2Fvirtual_hsm.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fahillelt%2Fvirtual_hsm?ref=badge_large)