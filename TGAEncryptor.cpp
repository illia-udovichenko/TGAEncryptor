#include <cstdlib>
#include <cstdio>
#include <iomanip>
#include <unistd.h>
#include <sys/stat.h>
#include <string>
#include <memory>
#include <vector>
#include <fstream>
#include <cassert>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/rand.h>

using namespace std;

// Structure to hold cryptographic configuration
struct crypto_config {
    const char *m_crypto_function; // Name of the cryptographic function (e.g., AES-128-ECB)
    unique_ptr<uint8_t[]> m_key; // Encryption key
    unique_ptr<uint8_t[]> m_IV; // Initialization vector (IV)
    size_t m_key_len; // Length of the key
    size_t m_IV_len; // Length of the IV
};

// Function to encrypt data from input file to output file
int encrypt_data(const string &in_filename, const string &out_filename, crypto_config &config) {
    // Check for nullptrs
    if (!config.m_crypto_function)
        return EXIT_FAILURE;

    // Get cipher
    const EVP_CIPHER *cipher = EVP_get_cipherbyname(config.m_crypto_function);
    if (!cipher)
        return EXIT_FAILURE;

    // Get required key and IV lengths
    size_t key_len = EVP_CIPHER_key_length(cipher);
    size_t iv_len = EVP_CIPHER_iv_length(cipher);

    // Generate key if it's not long enough
    if (config.m_key_len < key_len || !config.m_key) {
        config.m_key = make_unique<uint8_t[]>(key_len);
        if (RAND_bytes(config.m_key.get(), key_len) != 1)
            return EXIT_FAILURE;
        config.m_key_len = key_len;
    }

    // Generate IV if it's not long enough and the mode requires it
    if (config.m_IV_len < iv_len || (iv_len > 0 && !config.m_IV)) {
        config.m_IV = make_unique<uint8_t[]>(iv_len);
        if (RAND_bytes(config.m_IV.get(), iv_len) != 1)
            return EXIT_FAILURE;
        config.m_IV_len = iv_len;
    }

    // Open input and output files
    ifstream in_file(in_filename, ios::binary);
    ofstream out_file(out_filename, ios::binary);
    if (!in_file || !out_file)
        return EXIT_FAILURE;

    // Copy the first 18 bytes (header) without modification
    vector<uint8_t> header(18);
    if (!in_file.read(reinterpret_cast<char *>(header.data()), 18))
        return EXIT_FAILURE;
    out_file.write(reinterpret_cast<char *>(header.data()), 18);
    if (!out_file)
        return EXIT_FAILURE;

    // Initialize encryption context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return EXIT_FAILURE;

    // Initialize encryption operation
    if (EVP_EncryptInit_ex(ctx, cipher, nullptr, config.m_key.get(), config.m_IV.get()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return EXIT_FAILURE;
    }

    // Buffers for reading and writing data
    vector<uint8_t> buffer(4096);
    vector<uint8_t> out_buffer(4096 + EVP_CIPHER_block_size(cipher));
    int out_len;

    // Encrypt the data in chunks
    while (true) {
        if (!in_file.read(reinterpret_cast<char *>(buffer.data()), buffer.size())) {
            if (in_file.eof())
                break;
            EVP_CIPHER_CTX_free(ctx);
            return EXIT_FAILURE;
        }

        if (EVP_EncryptUpdate(ctx, out_buffer.data(), &out_len, buffer.data(), 4096) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return EXIT_FAILURE;
        }
        out_file.write(reinterpret_cast<char *>(out_buffer.data()), out_len);
        if (!out_file) {
            EVP_CIPHER_CTX_free(ctx);
            return EXIT_FAILURE;
        }
    }

    // Encrypting last block
    int len = in_file.gcount();
    if (len) {
        if (EVP_EncryptUpdate(ctx, out_buffer.data(), &out_len, buffer.data(), len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return EXIT_FAILURE;
        }
        out_file.write(reinterpret_cast<char *>(out_buffer.data()), out_len);
        if (!out_file) {
            EVP_CIPHER_CTX_free(ctx);
            return EXIT_FAILURE;
        }
    }

    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx, out_buffer.data(), &out_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return EXIT_FAILURE;
    }
    out_file.write(reinterpret_cast<char *>(out_buffer.data()), out_len);
    if (!out_file) {
        EVP_CIPHER_CTX_free(ctx);
        return EXIT_FAILURE;
    }

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    return EXIT_SUCCESS;
}

// Function to decrypt data from input file to output file
int decrypt_data(const string &in_filename, const string &out_filename, crypto_config &config) {
    // Check for valid key and IV lengths
    if (!config.m_crypto_function || !config.m_key)
        return EXIT_FAILURE;

    // Get cipher
    const EVP_CIPHER *cipher = EVP_get_cipherbyname(config.m_crypto_function);
    if (!cipher)
        return EXIT_FAILURE;

    // Get required key and IV lengths
    size_t key_len = EVP_CIPHER_key_length(cipher);
    size_t iv_len = EVP_CIPHER_iv_length(cipher);

    // Check key and IV lengths
    if (config.m_key_len < key_len || config.m_IV_len < iv_len || (iv_len > 0 && !config.m_IV))
        return EXIT_FAILURE;

    // Open input and output files
    ifstream in_file(in_filename, ios::binary);
    ofstream out_file(out_filename, ios::binary);
    if (!in_file || !out_file)
        return EXIT_FAILURE;

    // Copy the first 18 bytes (header) without modification
    vector<uint8_t> header(18);
    if (!in_file.read(reinterpret_cast<char *>(header.data()), 18))
        return EXIT_FAILURE;
    out_file.write(reinterpret_cast<char *>(header.data()), 18);
    if (!out_file)
        return EXIT_FAILURE;

    // Initialize decryption context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return EXIT_FAILURE;

    // Initialize decryption operation
    if (EVP_DecryptInit_ex(ctx, cipher, nullptr, config.m_key.get(), config.m_IV.get()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return EXIT_FAILURE;
    }

    // Buffers for reading and writing data
    vector<uint8_t> buffer(4096);
    vector<uint8_t> out_buffer(4096 + EVP_CIPHER_block_size(cipher));
    int out_len;

    // Decrypt the data in chunks
    while (true) {
        if (!in_file.read(reinterpret_cast<char *>(buffer.data()), buffer.size())) {
            if (in_file.eof())
                break;
            EVP_CIPHER_CTX_free(ctx);
            return EXIT_FAILURE;
        }

        if (EVP_DecryptUpdate(ctx, out_buffer.data(), &out_len, buffer.data(), 4096) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return EXIT_FAILURE;
        }
        out_file.write(reinterpret_cast<char *>(out_buffer.data()), out_len);
        if (!out_file) {
            EVP_CIPHER_CTX_free(ctx);
            return EXIT_FAILURE;
        }
    }

    // Decrypting last block
    int len = in_file.gcount();
    if (len) {
        if (EVP_DecryptUpdate(ctx, out_buffer.data(), &out_len, buffer.data(), len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return EXIT_FAILURE;
        }
        out_file.write(reinterpret_cast<char *>(out_buffer.data()), out_len);
        if (!out_file) {
            EVP_CIPHER_CTX_free(ctx);
            return EXIT_FAILURE;
        }
    }

    // Finalize decryption
    if (EVP_DecryptFinal_ex(ctx, out_buffer.data(), &out_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return EXIT_FAILURE;
    }
    out_file.write(reinterpret_cast<char *>(out_buffer.data()), out_len);
    if (!out_file) {
        EVP_CIPHER_CTX_free(ctx);
        return EXIT_FAILURE;
    }

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    return EXIT_SUCCESS;
}

bool compare_files(const char *name1, const char *name2) {
    std::ifstream file1(name1, std::ios::binary | std::ios::ate);
    std::ifstream file2(name2, std::ios::binary | std::ios::ate);

    if (!file1.is_open() || !file2.is_open()) {
        return false;
    }

    std::streamsize size1 = file1.tellg();
    std::streamsize size2 = file2.tellg();

    if (size1 != size2) {
        return false;
    }

    file1.seekg(0, std::ios::beg);
    file2.seekg(0, std::ios::beg);

    std::vector<char> buffer1(size1);
    std::vector<char> buffer2(size2);

    if (!file1.read(buffer1.data(), size1) || !file2.read(buffer2.data(), size2)) {
        return false;
    }

    return buffer1 == buffer2;
}

int main() {
    crypto_config config{nullptr, nullptr, nullptr, 0, 0};

    // ECB mode
    config.m_crypto_function = "AES-128-ECB";
    config.m_key = std::make_unique<uint8_t[]>(16);
    memset(config.m_key.get(), 0, 16);
    config.m_key_len = 16;

    encrypt_data("homer-simpson.TGA", "out_file.TGA", config);

    assert(EXIT_SUCCESS == encrypt_data ("homer-simpson.TGA", "out_file.TGA", config) &&
        compare_files ("out_file.TGA", "homer-simpson_enc_ecb.TGA"));

    assert(EXIT_SUCCESS == decrypt_data ("homer-simpson_enc_ecb.TGA", "out_file.TGA", config) &&
        compare_files ("out_file.TGA", "homer-simpson.TGA"));

    assert(EXIT_SUCCESS == encrypt_data ("UCM8.TGA", "out_file.TGA", config) &&
        compare_files ("out_file.TGA", "UCM8_enc_ecb.TGA"));

    assert(EXIT_SUCCESS == decrypt_data ("UCM8_enc_ecb.TGA", "out_file.TGA", config) &&
        compare_files ("out_file.TGA", "UCM8.TGA"));

    assert(EXIT_SUCCESS == encrypt_data ("image_1.TGA", "out_file.TGA", config) &&
        compare_files ("out_file.TGA", "ref_1_enc_ecb.TGA"));

    assert(EXIT_SUCCESS == encrypt_data ("image_2.TGA", "out_file.TGA", config) &&
        compare_files ("out_file.TGA", "ref_2_enc_ecb.TGA"));

    assert(EXIT_SUCCESS == decrypt_data ("image_3_enc_ecb.TGA", "out_file.TGA", config) &&
        compare_files("out_file.TGA", "ref_3_dec_ecb.TGA"));

    assert(EXIT_SUCCESS == decrypt_data ("image_4_enc_ecb.TGA", "out_file.TGA", config) &&
        compare_files("out_file.TGA", "ref_4_dec_ecb.TGA"));

    // CBC mode
    config.m_crypto_function = "AES-128-CBC";
    config.m_IV = std::make_unique<uint8_t[]>(16);
    config.m_IV_len = 16;
    memset(config.m_IV.get(), 0, 16);

    assert(EXIT_SUCCESS == encrypt_data ("UCM8.TGA", "out_file.TGA", config) &&
        compare_files ("out_file.TGA", "UCM8_enc_cbc.TGA"));

    assert(EXIT_SUCCESS == decrypt_data ("UCM8_enc_cbc.TGA", "out_file.TGA", config) &&
        compare_files ("out_file.TGA", "UCM8.TGA"));

    assert(EXIT_SUCCESS == encrypt_data ("homer-simpson.TGA", "out_file.TGA", config) &&
        compare_files ("out_file.TGA", "homer-simpson_enc_cbc.TGA"));

    assert(EXIT_SUCCESS == decrypt_data ("homer-simpson_enc_cbc.TGA", "out_file.TGA", config) &&
        compare_files ("out_file.TGA", "homer-simpson.TGA"));

    assert(EXIT_SUCCESS == encrypt_data ("image_1.TGA", "out_file.TGA", config) &&
        compare_files ("out_file.TGA", "ref_5_enc_cbc.TGA"));

    assert(EXIT_SUCCESS == encrypt_data ("image_2.TGA", "out_file.TGA", config) &&
        compare_files ("out_file.TGA", "ref_6_enc_cbc.TGA"));

    assert(EXIT_SUCCESS == decrypt_data ("image_7_enc_cbc.TGA", "out_file.TGA", config) &&
        compare_files("out_file.TGA", "ref_7_dec_cbc.TGA"));

    assert(EXIT_SUCCESS == decrypt_data ("image_8_enc_cbc.TGA", "out_file.TGA", config) &&
        compare_files("out_file.TGA", "ref_8_dec_cbc.TGA"));
    return 0;
}
