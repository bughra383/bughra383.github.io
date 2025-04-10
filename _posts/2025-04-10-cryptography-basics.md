---
layout: post
title: Cryptography Basics
date: 2025-04-10 16:27 +0300
categories: [Cryptography]
tags: [cryptography, encryption, decryption, plaintext, ciphertext, key, cipher]
---

## Core Concepts

- **Plaintext**: The original, readable data before encryption.
- **Ciphertext**: The scrambled, unreadable result after encryption.
- **Cipher**: An algorithm or method used to perform encryption or decryption.
- **Key**: A piece of information that determines the output of a cryptographic algorithm.
- **Encryption**: The process of converting plaintext into ciphertext.
- **Decryption**: The process of converting ciphertext back into plaintext.
- **Encoding**: Converting data from one format to another (not for security, just representation).

## Types of Encryption

### Symmetric Encryption

- Uses the same key for encryption and decryption
- Fast and efficient for large data
- Examples: AES, DES, 3DES
- Use cases: Secure local storage, efficient data transmission

### Asymmetric Encryption

- Uses different keys for encryption (public) and decryption (private)
- Slower than symmetric but solves key distribution problem
- Examples: RSA, ECC
- Use cases: Secure communication, digital signatures

### Hybrid Encryption

- Uses asymmetric encryption to exchange a symmetric key
- Then uses symmetric encryption for the actual data
- Use cases: HTTPS, secure messaging apps

## Hash Functions

- One-way mathematical functions that convert data of any size to a fixed-size output. Any small changes in the input data (even a single bit) should cause a large change in the output.
- The output of a hash function is normally raw bytes, which are then encoded. Common encodings for this are base 64 or hexadecimal. Decoding these won’t give you anything useful.
- Properties: deterministic, fast computation, pre-image resistance, small changes cause large output differences
- Examples: SHA-256, SHA-3, BLAKE2

### Hash-Related Concepts

- **Hash Collision**: When two different inputs produce the same hash output. (Search for pigeonhole effect)
- **Rainbow Tables**: Precomputed tables for reversing hash functions
- **Password Salting**: Adding random data (salt) to passwords before hashing to prevent rainbow table attacks
- **Pepper**: A secret value added to passwords before hashing, stored separately from the database

## Public Key Cryptography

Public key cryptography (asymmetric cryptography) uses a pair of mathematically related keys:
- **Public Key**: Shared openly with anyone
- **Private Key**: Kept secret by the owner

### Core Mechanics

- **Encryption**: Data encrypted with the public key can only be decrypted with the corresponding private key
- **Digital Signatures**: Data signed with a private key can be verified with the corresponding public key
- **Key Distribution**: Solves the problem of securely exchanging keys over insecure channels
- **Non-repudiation**: Provides proof of origin through digital signatures

### RSA (Rivest–Shamir–Adleman)

- Based on the mathematical difficulty of factoring the product of two large prime numbers
- **Key Generation Process**:
  1. Select two large prime numbers (p, q)
  2. Compute n = p × q
  3. Compute φ(n) = (p-1) × (q-1)
  4. Choose public exponent e (usually 65537)
  5. Compute private exponent d where (d × e) mod φ(n) = 1
  6. Public key = (n, e), Private key = (n, d)
- **Security**: Relies on the computational difficulty of the integer factorization problem
- **Use Cases**: Digital signatures, secure key exchange, encryption of small data blocks
- **Limitations**: Relatively slow, especially for large data; vulnerable to quantum computing attacks

### Diffie-Hellman Key Exchange

- Allows two parties to establish a shared secret key over an insecure channel
- **How It Works**:
  1. Parties agree on public parameters (a prime number p and base g)
  2. Each party generates a private key (a, b)
  3. Each computes public values: A = g^a mod p, B = g^b mod p
  4. Each shares their public value with the other party
  5. Shared secret calculated: K = B^a mod p = A^b mod p = g^(ab) mod p
- **Security**: Based on the discrete logarithm problem
- **Limitation**: Vulnerable to man-in-the-middle attacks without authentication

### Elliptic Curve Cryptography (ECC)

- Based on algebraic structure of elliptic curves over finite fields
- Same security level as RSA but with significantly smaller key sizes
- ECC 256-bit keys provide similar security to RSA 3072-bit keys
- Much faster and more efficient than RSA, especially on constrained devices
- Used in modern TLS, secure messaging apps, and cryptocurrencies

### Digital Signatures

- **Creation**: Hash the message and encrypt the hash with the sender's private key
- **Verification**: Recipient decrypts the hash using sender's public key and compares it with newly calculated hash
- **Properties**: Authenticates the sender, ensures data integrity, provides non-repudiation
- **Algorithms**: RSA-PSS, ECDSA, EdDSA

### Public Key Infrastructure (PKI)

- System that manages digital certificates and public key encryption
- **Certificate Authorities (CAs)**: Trusted third parties that issue digital certificates
- **Digital Certificates**: Documents binding a public key to an entity's identity
- **Trust Chain**: Hierarchy of certificates from root CAs to end-entity certificates
- **Use Case**: Web browsers use PKI to verify website authenticity (HTTPS)

### Comparison of Key Public Key Algorithms

| Feature | RSA | Diffie-Hellman | ECC |
|---------|-----|----------------|-----|
| Purpose | Encryption, signatures | Key exchange only | Encryption, signatures, key exchange |
| Authentication | Can provide | Doesn't provide by itself | Can provide |
| Performance | Slowest | Moderate | Fastest |
| Key size | 2048-4096 bits | 2048+ bits | 256-384 bits |
| Quantum resistance | Vulnerable | Vulnerable | Vulnerable, but requires larger quantum resources |
| Mathematical basis | Integer factorization | Discrete logarithm problem | Elliptic curve discrete logarithm problem |
## Authentication with Salted Passwords

### Key Question

How does password verification work with random salts if the salt changes each time?

### Solution

1. The salt is **not** secret and is stored in plaintext alongside the password hash
2. During authentication:
    - System retrieves the stored salt for that specific user
    - Combines the entered password with the stored salt
    - Hashes this combination
    - Compares resulting hash with stored hash

### Example Flow

```
Registration:
1. User creates password: "password123"
2. System generates random salt: "8f4e2a9c"
3. System combines: "password1238f4e2a9c"
4. System hashes: hash("password1238f4e2a9c") → "a7f9b23..."
5. Stores in database:
   - Salt: "8f4e2a9c"
   - Hash: "a7f9b23..."

Authentication:
1. User enters: "password123"
2. System retrieves stored salt: "8f4e2a9c"
3. System combines: "password1238f4e2a9c"
4. System hashes: hash("password1238f4e2a9c") → "a7f9b23..."
5. Compares with stored hash
6. Match = authenticated
```

## Security Principles

- Salt does not need to be secret; its security comes from uniqueness
- Each user having a different salt means identical passwords produce different hashes
- Even if an attacker knows the salt, they need to create a separate rainbow table for each salt
- Pre-computing rainbow tables for every possible salt is computationally infeasible

## Best Practices

- Use cryptographically secure random salt generation
- Salt should be at least 16 bytes (128 bits)
- Always use modern hashing algorithms (Argon2, bcrypt, PBKDF2)
- Implement proper key stretching with high iteration counts


## Recognising Password Hashes

| Prefix                         | Algorithm                                                                                                                                                                                        |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `$y$`                          | yescrypt is a scalable hashing scheme and is the default and recommended choice in new systems                                                                                                   |
| `$gy$`                         | gost-yescrypt uses the GOST R 34.11-2012 hash function and the yescrypt hashing method                                                                                                           |
| `$7$`                          | scrypt is a password-based key derivation function                                                                                                                                               |
| `$2b$`, `$2y$`, `$2a$`, `$2x$` | bcrypt is a hash based on the Blowfish block cipher originally developed for OpenBSD but supported on a recent version of FreeBSD, NetBSD, Solaris 10 and newer, and several Linux distributions |
| `$6$`                          | sha512crypt is a hash based on SHA-2 with 512-bit output originally developed for GNU libc and commonly used on (older) Linux systems                                                            |
| `$md5`                         | SunMD5 is a hash based on the MD5 algorithm originally developed for Solaris                                                                                                                     |
| `$1$`                          | md5crypt is a hash based on the MD5 algorithm originally developed for FreeBSD                                                                                                                   |

