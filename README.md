# TGAEncryptor

TGAEncryptor is a lightweight C++ tool that encrypts and decrypts **TGA image files** using symmetric ciphers from the **OpenSSL** library.  
It was developed as part of a cryptography programming assignment at **CTU FIT**.

---

##  Features

- Encrypts and decrypts `.TGA` files using OpenSSL EVP interface  
- Preserves the 18-byte TGA header for compatibility with image viewers  
- Automatically generates missing keys or IVs using secure random bytes  
- Supports multiple cipher modes (AES-128-ECB, AES-128-CBC, etc.)  
- Processes large files efficiently (chunked I/O, minimal memory usage)

---

## Structure

| Function | Description |
|-----------|--------------|
| `encrypt_data()` | Encrypts image data while preserving the header |
| `decrypt_data()` | Decrypts encrypted files to restore original image |
| `crypto_config` | Holds cipher name, key, IV, and their lengths |

---

## Example

```cpp
crypto_config config;
config.m_crypto_function = "AES-128-CBC";
config.m_key = std::make_unique<uint8_t[]>(16);
config.m_IV  = std::make_unique<uint8_t[]>(16);
config.m_key_len = config.m_IV_len = 16;
memset(config.m_key.get(), 0, 16);
memset(config.m_IV.get(), 0, 16);

encrypt_data("input.TGA", "encrypted.TGA", config);
decrypt_data("encrypted.TGA", "decrypted.TGA", config);
````

---

## Local Testing

The provided `main()` runs a suite of tests using sample `.TGA` images.

Compile with:

```bash
g++ -std=c++23 -Wall -Wextra -pedantic -O2 tga_encryptor.cpp -lcrypto -o tga_encryptor
```

Run:

```bash
./tga_encryptor
```

Make sure to have OpenSSL installed and test images (e.g. `homer-simpson.TGA`, `UCM8.TGA`) available in the same directory.

---

## Requirements

* C++23 compatible compiler (e.g. `g++ 13+`)
* OpenSSL 3.x (`libcrypto`)
* Linux or macOS recommended (tested under Ubuntu)
