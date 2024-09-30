# Virtual Hardware Security Management (HSM) Program

A virtualized hardware security management tool for students to leverage in various assignments for the NYU Application Security course. 

This HSM is exceptionally simple, and is not meant to be a true HSM, but simply a virtualized expression of one that can be addressed via terminal commands. 
**Do not use in production environments**

## Design Notes:

* The EVP (Envelope) interface is for encryption and decryption, which is the recommended approach in OpenSSL 3.0.
* Error handling uses OpenSSL's error reporting functions.
* AES-256 encryption, unique IV for each key
* Persistent storage due to keystore.dat and master.key split-paired files. 

## Operation Notes:

Two files will be generated upon execution of the program :

1) keystore.dat - an encrypted database file storing the key information
2) master.key - the master.key file required to acccess the HSM. This is paired to keystore.dat. The HSM is agnostic, and works with any generated master.key paired to it's respective keystore.dat.

Input/Output:

* When storing a key, the program reads 32 bytes from stdin. This allows you to pipe in the key data or use input redirection.
* When retrieving a key, it prints the key in ASCII format to stdout since the goal is provide simple functionality for students to use. 

## Example commands:

### Compile:

```gcc -o virtual_hsm virtual_hsm.c -lcrypto```

### Key Storage:

```echo -n "0123456789appsec0123456789abcdef" | ./virtual_hsm -store myappseckey```

### Key Retrieval:

```./virtual_hsm -retrieve myappseckey```

### Key List:

```./virtual_hsm -list```

#### Piping
If you're piping the output to another command or file, you might want to add a newline character after the key is printed. If that's the case, you add a flag called -pipe so it adds a printf("\n"); after the fwrite call.

##### Retrieve a key with newline (for piping or file output)
```./virtual_hsm -retrieve myappseckey -pipe```

##### Example of piping the output
```./virtual_hsm -retrieve myappseckey -pipe | xxd -p```

#### key and file commands

Yoy can manage multiple keystores with different master keys. The program will use the default file names if the -keystore and -master flags are not provided. Example commands using the flags:

##### Using default file names
```echo -n "0123456789appsec0123456789abcdef" | ./virtual_hsm -store myappseckey```

##### Using custom file names
```echo -n "0123456789appsec0123456789abcdef" | ./virtual_hsm -keystore "appseckeystore.dat" -master "masterAppsec.key" -store myappseckey```

##### Retrieving a key with custom file names and piping
```./virtual_hsm -keystore "appseckeystore.dat" -master "masterAppsec.key" -retrieve myappseckey -pipe```

##### Listing keys with custom file names
```./virtual_hsm -keystore "appseckeystore.dat" -master "masterAppsec.key" -list```

## Flaws

To my students, this is certainly missing:

* Actual secure memory management
* Access controls and authentication
* Audit logging
* Proper key lifecycle management
* Protection against side-channel attacks

