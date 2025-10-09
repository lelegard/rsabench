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
// constexpr int64_t MIN_CPU_TIME = 2 * USECPERSEC;
// constexpr size_t  DATA_SIZE = 64 * 1024 * 1024;
// constexpr size_t  INNER_LOOP_COUNT = 10;


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
// Perform one test
//----------------------------------------------------------------------------

void one_test(const char* private_key_file, const char* public_key_file)
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
    std::vector<uint8_t> input(EVP_PKEY_get_size(kpriv) / 2, 0xA5);
    std::vector<uint8_t> output(EVP_PKEY_get_size(kpriv));

    std::cout << "algo: " << EVP_PKEY_get0_type_name(kpriv) << std::endl;
    std::cout << "key-size: " << EVP_PKEY_get_bits(kpriv) << std::endl;
    std::cout << "data-size: " << input.size() << std::endl;
    std::cout << "output-size: " << output.size() << std::endl;

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
    one_test("rsa-2048-prv.pem", "rsa-2048-pub.pem");
    one_test("rsa-3072-prv.pem", "rsa-3072-pub.pem");
    one_test("rsa-4096-prv.pem", "rsa-4096-pub.pem");

    // OpenSSL cleanup.
    EVP_cleanup();
    ERR_free_strings();
    return EXIT_SUCCESS;
}
