//----------------------------------------------------------------------------
// rsabench - Copyright (c) 2025, Thierry Lelegard
// BSD 2-Clause License, see LICENSE file.
//----------------------------------------------------------------------------

#include <iostream>
#include <vector>
#include <filesystem>
#include <cstdlib>
#include <cinttypes>
#include <unistd.h>
#include <sys/resource.h>

#include <openssl/opensslv.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#if defined(__APPLE__)
    #include <libproc.h>
#endif

constexpr int64_t USECPERSEC = 1000000;  // microseconds per second
constexpr int64_t MIN_CPU_TIME = 2 * USECPERSEC;
constexpr size_t  INNER_LOOP_COUNT = 10;


//----------------------------------------------------------------------------
// Get current CPU time resource usage in microseconds.
//----------------------------------------------------------------------------

int64_t cpu_time()
{
    rusage ru;
    if (getrusage(RUSAGE_SELF, &ru) < 0) {
        perror("getrusage");
        exit(EXIT_FAILURE);
    }
    return ((int64_t)(ru.ru_utime.tv_sec) * USECPERSEC) + ru.ru_utime.tv_usec +
           ((int64_t)(ru.ru_stime.tv_sec) * USECPERSEC) + ru.ru_stime.tv_usec;
}


//----------------------------------------------------------------------------
// OpenSSL error, abort application.
//----------------------------------------------------------------------------

[[noreturn]] void fatal(const std::string& message)
{
    if (!message.empty()) {
        std::cerr << "openssl: " << message << std::endl;
    }
    ERR_print_errors_fp(stderr);
    std::exit(EXIT_FAILURE);
}


//----------------------------------------------------------------------------
// Print entry for OpenSSL version.
//----------------------------------------------------------------------------

void print_openssl_version()
{
    std::cout << "openssl: "
#if defined(OPENSSL_FULL_VERSION_STRING) // v3
              << OpenSSL_version(OPENSSL_FULL_VERSION_STRING) << ", " << OpenSSL_version(OPENSSL_CPU_INFO)
#elif defined(OPENSSL_VERSION)
              << OpenSSL_version(OPENSSL_VERSION)
#else
              << OPENSSL_VERSION_TEXT
#endif
              << std::endl;
}


//----------------------------------------------------------------------------
// Get current executable path.
//----------------------------------------------------------------------------

std::string current_exec()
{
#if defined(__APPLE__)
    char name[PROC_PIDPATHINFO_MAXSIZE];
    int length = proc_pidpath(getpid(), name, sizeof(name));
    return length < 0 ? "" : std::string(name, length);
#else
    return std::filesystem::weakly_canonical("/proc/self/exe");
#endif
}


//----------------------------------------------------------------------------
// Get directory of keys. Abort on error.
//----------------------------------------------------------------------------

std::string keys_directory()
{
    const std::string exe(current_exec());
    std::string dir(exe);
    size_t sep = 0;

    while ((sep = dir.rfind('/')) != std::string::npos) {
        dir.resize(sep);
        const std::string keys(dir + "/keys");
        if (std::filesystem::is_directory(keys)) {
            return keys;
        }
    }

    fatal("cannot find 'keys' directory from " + exe);
}


//----------------------------------------------------------------------------
// Print one test result.
//----------------------------------------------------------------------------

void print_result(const char* name, uint64_t count, uint64_t size, uint64_t duration)
{
    std::cout << name << "-microsec: " << duration << std::endl;
    std::cout << name << "-size: " << size << std::endl;
    std::cout << name << "-bitrate: " << ((USECPERSEC * 8 * size) / duration) << std::endl;
    std::cout << name << "-count: " << count << std::endl;
    std::cout << name << "-persec: " << ((USECPERSEC * count) / duration) << std::endl;
}


//----------------------------------------------------------------------------
// Perform one test
//----------------------------------------------------------------------------

void one_test(const char* private_key_file, const char* public_key_file, const EVP_MD* evp_pss_hash)
{
    const std::string dir(keys_directory() + "/");
    const std::string kpriv_file(dir + private_key_file);
    const std::string kpub_file(dir + public_key_file);

    // Load keys.
    std::FILE* fp = nullptr;
    if ((fp = std::fopen(kpriv_file.c_str(), "r")) == nullptr) {
        perror(kpriv_file.c_str());
        std::exit(EXIT_FAILURE);
    }
    EVP_PKEY* kpriv = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
    if (kpriv == nullptr) {
        fatal("error loading private key from " + kpriv_file);
    }
    fclose(fp);

    if ((fp = std::fopen(kpub_file.c_str(), "r")) == nullptr) {
        perror(kpub_file.c_str());
        std::exit(EXIT_FAILURE);
    }
    EVP_PKEY* kpub = PEM_read_PUBKEY(fp, nullptr, nullptr, nullptr);
    if (kpub == nullptr) {
        fatal("error loading public key from " + kpub_file);
    }
    fclose(fp);

    // Check key size consistency.
    if (EVP_PKEY_get_bits(kpriv) != EVP_PKEY_get_bits(kpub) || EVP_PKEY_get_size(kpriv) != EVP_PKEY_get_size(kpub)) {
        fatal("internal error: inconsistent key sizes");
    }

    // Use input data of half the max output size for the algorithm.
    // This is the usual scheme: RSA-2048 -> 256 bytes -> sign/encrypt 128-bit data.
    const size_t key_bits = EVP_PKEY_get_bits(kpriv);
    const size_t data_size = EVP_PKEY_get_size(kpriv);
    std::vector<uint8_t> input(data_size / 2, 0xA5);

    std::cout << "algo: " << EVP_PKEY_get0_type_name(kpriv) << "-" << key_bits << std::endl;
    std::cout << "key-size: " << key_bits << std::endl;
    std::cout << "data-size: " << input.size() << std::endl;
    std::cout << "output-size: " << data_size << std::endl;

    // Initialize encryption with OAEP padding.
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(kpub, nullptr);
    if (ctx == nullptr) {
        fatal("error in EVP_PKEY_CTX_new(public-key)");
    }
    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        fatal("error in EVP_PKEY_encrypt_init");
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        fatal("error in EVP_PKEY_CTX_set_rsa_padding(RSA_PKCS1_OAEP_PADDING)");
    }

    // Encryption test.
    std::vector<uint8_t> encrypted(data_size);
    size_t encrypted_len = 0;
    uint64_t count = 0;
    uint64_t size = 0;
    uint64_t duration = 0;
    uint64_t start = cpu_time();

    do {
        for (size_t i = 0; i < INNER_LOOP_COUNT; i++) {
            encrypted_len = encrypted.size();
            if (EVP_PKEY_encrypt(ctx, encrypted.data(), &encrypted_len, input.data(), input.size()) <= 0) {
                fatal("RSA encrypt error");
            }
            size += input.size();
            count++;
        }
        duration = cpu_time() - start;
    } while (duration < MIN_CPU_TIME);

    // End of encryption test.
    std::cout << "encrypted-size: " << encrypted_len << std::endl;
    print_result("oaep-encrypt", count, size, duration);
    EVP_PKEY_CTX_free(ctx);

    // Initialize decryption with OAEP padding.
    if ((ctx = EVP_PKEY_CTX_new(kpriv, nullptr)) == nullptr) {
        fatal("error in EVP_PKEY_CTX_new(private-key)");
    }
    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        fatal("error in EVP_PKEY_decrypt_init");
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        fatal("error in EVP_PKEY_CTX_set_rsa_padding(RSA_PKCS1_OAEP_PADDING)");
    }

    // Decryption test.
    std::vector<uint8_t> decrypted(data_size);
    size_t decrypted_len = 0;
    count = 0;
    size = 0;
    duration = 0;
    start = cpu_time();

    do {
        for (size_t i = 0; i < INNER_LOOP_COUNT; i++) {
            decrypted_len = decrypted.size();
            if (EVP_PKEY_decrypt(ctx, decrypted.data(), &decrypted_len, encrypted.data(), encrypted_len) <= 0) {
                fatal("RSA decrypt error");
            }
            size += encrypted_len;
            count++;
        }
        duration = cpu_time() - start;
    } while (duration < MIN_CPU_TIME);

    // End of decryption test.
    std::cout << "decrypted-size: " << decrypted_len << std::endl;
    print_result("oaep-decrypt", count, size, duration);
    EVP_PKEY_CTX_free(ctx);

    // Check decrypted data.
    if (decrypted_len != input.size() || memcmp(input.data(), decrypted.data(), decrypted_len) != 0) {
        fatal("decrypted data don't match input");
    }

    // Initialize signature with PSS padding.
    if ((ctx = EVP_PKEY_CTX_new(kpriv, nullptr)) == nullptr) {
        fatal("error in EVP_PKEY_CTX_new(private-key)");
    }
    if (EVP_PKEY_sign_init(ctx) <= 0) {
        fatal("error in EVP_PKEY_sign_init");
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) <= 0) {
        fatal("error in EVP_PKEY_CTX_set_rsa_padding");
    }
    if (EVP_PKEY_CTX_set_signature_md(ctx, evp_pss_hash) <= 0) {
        fatal("error in EVP_PKEY_CTX_set_signature_md");
    }

    std::cout << "pss-digest-size: " << (8 * EVP_MD_get_size(evp_pss_hash)) << std::endl;

    // Signature test.
    std::vector<uint8_t> signature(1024);
    size_t signature_len = 0;
    count = 0;
    size = 0;
    duration = 0;
    start = cpu_time();

    do {
        for (size_t i = 0; i < INNER_LOOP_COUNT; i++) {
            signature_len = signature.size();
            std::cout << "@@@ signing" << std::endl;
            if (EVP_PKEY_sign(ctx, signature.data(), &signature_len, input.data(), input.size()) <= 0) {
                fatal("RSA sign error");
            }
            size += input.size();
            count++;
        }
        duration = cpu_time() - start;
    } while (duration < MIN_CPU_TIME);

    // End of signature test.
    std::cout << "signature-size: " << signature_len << std::endl;
    print_result("pss-sign", count, size, duration);
    EVP_PKEY_CTX_free(ctx);

    // Initialize signature verification with PSS padding.
    if ((ctx = EVP_PKEY_CTX_new(kpub, nullptr)) == nullptr) {
        fatal("error in EVP_PKEY_CTX_new(public-key)");
    }
    if (EVP_PKEY_verify_init(ctx) <= 0) {
        fatal("error in EVP_PKEY_verify_init");
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) <= 0) {
        fatal("error in EVP_PKEY_CTX_set_rsa_padding");
    }
    if (EVP_PKEY_CTX_set_signature_md(ctx, evp_pss_hash) <= 0) {
        fatal("error in EVP_PKEY_CTX_set_signature_md");
    }

    // Signature verification test.
    count = 0;
    size = 0;
    duration = 0;
    start = cpu_time();

    do {
        for (size_t i = 0; i < INNER_LOOP_COUNT; i++) {
            // Status: 1=verified, 0=not verified, <0 = error
            const int res = EVP_PKEY_verify(ctx, signature.data(), signature_len, input.data(), input.size());
            if (res <= 0) {
                fatal("RSA verify error");
            }
            size += signature_len;
            count++;
        }
        duration = cpu_time() - start;
    } while (duration < MIN_CPU_TIME);

    // End of signature verification test.
    print_result("pss-verify", count, size, duration);
    EVP_PKEY_CTX_free(ctx);

    // Free keys.
    EVP_PKEY_free(kpub);
    EVP_PKEY_free(kpriv);
}


//----------------------------------------------------------------------------
// Application entry point
//----------------------------------------------------------------------------

int main(int argc, char* argv[])
{
    // OpenSSL initialization.
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    print_openssl_version();

    // Run tests.
    one_test("rsa-2048-prv.pem", "rsa-2048-pub.pem", EVP_sha256());
    one_test("rsa-3072-prv.pem", "rsa-3072-pub.pem", EVP_sha256());  // or 384
    one_test("rsa-4096-prv.pem", "rsa-4096-pub.pem", EVP_sha256());  // or 512

    // OpenSSL cleanup.
    EVP_cleanup();
    ERR_free_strings();
    return EXIT_SUCCESS;
}
