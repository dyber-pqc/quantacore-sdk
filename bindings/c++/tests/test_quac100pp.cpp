/**
 * @file test_quac100pp.cpp
 * @brief QUAC 100 C++ SDK - Test Suite
 * @copyright Copyright © 2025 Dyber, Inc. All Rights Reserved.
 */

#include <quac100/quac100.hpp>
#include <iostream>
#include <cassert>
#include <iomanip>

using namespace quac100;

/*============================================================================
 * Test Framework
 *============================================================================*/

static int g_tests_run = 0;
static int g_tests_passed = 0;
static int g_tests_failed = 0;

#define TEST(name)                                           \
    std::cout << "Running " << name << "... " << std::flush; \
    g_tests_run++;

#define PASS()                        \
    std::cout << "PASS" << std::endl; \
    g_tests_passed++;

#define FAIL(msg)                              \
    std::cout << "FAIL: " << msg << std::endl; \
    g_tests_failed++;                          \
    return;

#define ASSERT(cond, msg) \
    if (!(cond))          \
    {                     \
        FAIL(msg);        \
    }

#define ASSERT_EQ(a, b)                                           \
    if ((a) != (b))                                               \
    {                                                             \
        std::cout << "FAIL: " << #a << " != " << #b << std::endl; \
        g_tests_failed++;                                         \
        return;                                                   \
    }

#define ASSERT_THROWS(expr, exc_type)          \
    try                                        \
    {                                          \
        expr;                                  \
        FAIL("Expected exception not thrown"); \
    }                                          \
    catch (const exc_type &)                   \
    {                                          \
        /* Expected */                         \
    }                                          \
    catch (...)                                \
    {                                          \
        FAIL("Wrong exception type");          \
    }

/*============================================================================
 * Helper Functions
 *============================================================================*/

void printHex(const Bytes &data, size_t maxLen = 16)
{
    for (size_t i = 0; i < std::min(data.size(), maxLen); ++i)
    {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(data[i]);
    }
    if (data.size() > maxLen)
    {
        std::cout << "...";
    }
    std::cout << std::dec;
}

/*============================================================================
 * Library Tests
 *============================================================================*/

void test_version()
{
    TEST("Library::version()");

    auto ver = Library::version();
    ASSERT(!ver.empty(), "Version string is empty");

    auto vinfo = Library::versionInfo();
    ASSERT(vinfo.major >= 0, "Invalid major version");

    std::cout << "v" << ver << " ";
    PASS();
}

void test_build_info()
{
    TEST("Library::buildInfo()");

    auto info = Library::buildInfo();
    ASSERT(!info.empty(), "Build info is empty");

    PASS();
}

/*============================================================================
 * Device Tests
 *============================================================================*/

void test_enumerate_devices(Library &lib)
{
    TEST("Library::enumerateDevices()");

    auto devices = lib.enumerateDevices();
    std::cout << "found " << devices.size() << " device(s) ";

    PASS();
}

void test_device_info(Device &device)
{
    TEST("Device::info()");

    auto info = device.info();
    ASSERT(!info.modelName.empty(), "Model name is empty");
    ASSERT(!info.serialNumber.empty(), "Serial number is empty");

    std::cout << info.modelName << " ";
    PASS();
}

void test_device_status(Device &device)
{
    TEST("Device::status()");

    auto status = device.status();
    ASSERT(status.temperature >= 0, "Invalid temperature");
    ASSERT(status.entropyLevel >= 0, "Invalid entropy level");

    std::cout << "temp=" << status.temperature << "C ";
    PASS();
}

void test_self_test(Device &device)
{
    TEST("Device::selfTest()");

    device.selfTest(); // Throws on failure

    PASS();
}

/*============================================================================
 * KEM Tests
 *============================================================================*/

void test_kem_params()
{
    TEST("Kem::getParams()");

    auto params512 = Kem::getParams(KemAlgorithm::ML_KEM_512);
    ASSERT_EQ(params512.publicKeySize, ML_KEM_512_PUBLIC_KEY_SIZE);

    auto params768 = Kem::getParams(KemAlgorithm::ML_KEM_768);
    ASSERT_EQ(params768.publicKeySize, ML_KEM_768_PUBLIC_KEY_SIZE);

    auto params1024 = Kem::getParams(KemAlgorithm::ML_KEM_1024);
    ASSERT_EQ(params1024.publicKeySize, ML_KEM_1024_PUBLIC_KEY_SIZE);

    PASS();
}

void test_kem_keygen(Device &device)
{
    TEST("Kem::generateKeyPair()");

    auto kp = device.kem().generateKeyPair(KemAlgorithm::ML_KEM_768);

    ASSERT_EQ(kp.publicKey.size(), ML_KEM_768_PUBLIC_KEY_SIZE);
    ASSERT_EQ(kp.secretKey.size(), ML_KEM_768_SECRET_KEY_SIZE);

    // Keys should not be all zeros
    bool pk_ok = false, sk_ok = false;
    for (auto b : kp.publicKey)
        if (b != 0)
            pk_ok = true;
    for (auto b : kp.secretKey)
        if (b != 0)
            sk_ok = true;
    ASSERT(pk_ok, "Public key is all zeros");
    ASSERT(sk_ok, "Secret key is all zeros");

    PASS();
}

void test_kem_encaps_decaps(Device &device)
{
    TEST("KEM encaps/decaps cycle");

    // Generate key pair
    auto kp = device.kem().generateKeyPair768();

    // Encapsulate
    auto encaps = device.kem().encapsulate768(kp.publicKey);
    ASSERT_EQ(encaps.ciphertext.size(), ML_KEM_768_CIPHERTEXT_SIZE);
    ASSERT_EQ(encaps.sharedSecret.size(), ML_KEM_SHARED_SECRET_SIZE);

    // Decapsulate
    auto ss2 = device.kem().decapsulate768(kp.secretKey, encaps.ciphertext);
    ASSERT_EQ(ss2.size(), ML_KEM_SHARED_SECRET_SIZE);

    // Shared secrets must match
    ASSERT(encaps.sharedSecret == ss2, "Shared secrets don't match");

    std::cout << "shared secrets match! ";
    PASS();
}

/*============================================================================
 * Signature Tests
 *============================================================================*/

void test_sign_params()
{
    TEST("Sign::getParams()");

    auto params44 = Sign::getParams(SignAlgorithm::ML_DSA_44);
    ASSERT_EQ(params44.publicKeySize, ML_DSA_44_PUBLIC_KEY_SIZE);

    auto params65 = Sign::getParams(SignAlgorithm::ML_DSA_65);
    ASSERT_EQ(params65.publicKeySize, ML_DSA_65_PUBLIC_KEY_SIZE);

    auto params87 = Sign::getParams(SignAlgorithm::ML_DSA_87);
    ASSERT_EQ(params87.publicKeySize, ML_DSA_87_PUBLIC_KEY_SIZE);

    PASS();
}

void test_sign_keygen(Device &device)
{
    TEST("Sign::generateKeyPair()");

    auto kp = device.sign().generateKeyPair65();

    ASSERT_EQ(kp.publicKey.size(), ML_DSA_65_PUBLIC_KEY_SIZE);
    ASSERT_EQ(kp.secretKey.size(), ML_DSA_65_SECRET_KEY_SIZE);

    PASS();
}

void test_sign_verify(Device &device)
{
    TEST("Sign/verify cycle");

    auto kp = device.sign().generateKeyPair65();

    std::string message = "Hello, QUAC 100!";
    auto sig = device.sign().sign65(kp.secretKey, message);

    ASSERT(sig.size() > 0, "Signature is empty");

    // Verify
    bool valid = device.sign().verify65(kp.publicKey, message, sig);
    ASSERT(valid, "Valid signature rejected");

    // Tamper detection
    std::string tampered = "Hello, QUAC 100?";
    bool invalid = device.sign().verify65(kp.publicKey, tampered, sig);
    ASSERT(!invalid, "Tampered message accepted");

    std::cout << "tamper detected! ";
    PASS();
}

/*============================================================================
 * Random Tests
 *============================================================================*/

void test_random_bytes(Device &device)
{
    TEST("Random::bytes()");

    auto r1 = device.random().bytes(32);
    auto r2 = device.random().bytes(32);

    ASSERT_EQ(r1.size(), 32);
    ASSERT_EQ(r2.size(), 32);
    ASSERT(r1 != r2, "Random bytes are identical");

    PASS();
}

void test_random_range(Device &device)
{
    TEST("Random::range()");

    for (int i = 0; i < 100; ++i)
    {
        auto val = device.random().range(100);
        ASSERT(val < 100, "Value out of range");
    }

    PASS();
}

void test_random_uniform(Device &device)
{
    TEST("Random::uniform()");

    for (int i = 0; i < 100; ++i)
    {
        auto val = device.random().uniform();
        ASSERT(val >= 0.0 && val < 1.0, "Value out of range");
    }

    PASS();
}

void test_random_uuid(Device &device)
{
    TEST("Random::uuid()");

    auto uuid = device.random().uuid();
    ASSERT_EQ(uuid.size(), 36); // UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

    std::cout << uuid << " ";
    PASS();
}

/*============================================================================
 * Hash Tests
 *============================================================================*/

void test_hash_sha256(Device &device)
{
    TEST("Hash::sha256()");

    auto hash = device.hash().sha256("Hello, World!");
    ASSERT_EQ(hash.size(), SHA256_SIZE);

    std::cout << "hash=";
    printHex(hash, 8);
    std::cout << " ";
    PASS();
}

void test_hash_incremental(Device &device)
{
    TEST("Hash::Context");

    auto ctx = device.hash().createContext(HashAlgorithm::SHA256);
    ctx.update("Hello, ");
    ctx.update("World!");
    auto hash1 = ctx.finalize();

    auto hash2 = device.hash().sha256("Hello, World!");

    ASSERT(hash1 == hash2, "Incremental hash mismatch");

    PASS();
}

/*============================================================================
 * Utility Tests
 *============================================================================*/

void test_secure_zero()
{
    TEST("utils::secureZero()");

    Bytes data = {1, 2, 3, 4, 5};
    utils::secureZero(data);

    for (auto b : data)
    {
        ASSERT(b == 0, "Buffer not zeroed");
    }

    PASS();
}

void test_secure_compare()
{
    TEST("utils::secureCompare()");

    Bytes a = {1, 2, 3, 4, 5};
    Bytes b = {1, 2, 3, 4, 5};
    Bytes c = {1, 2, 3, 4, 6};

    ASSERT(utils::secureCompare(a, b), "Equal buffers not equal");
    ASSERT(!utils::secureCompare(a, c), "Different buffers are equal");

    PASS();
}

void test_hex_encoding()
{
    TEST("utils::toHex/fromHex()");

    Bytes data = {0xDE, 0xAD, 0xBE, 0xEF};
    auto hex = utils::toHex(data);
    ASSERT(hex == "deadbeef", "Hex encoding failed");

    auto decoded = utils::fromHex(hex);
    ASSERT(decoded == data, "Hex decoding failed");

    PASS();
}

void test_base64_encoding()
{
    TEST("utils::toBase64/fromBase64()");

    Bytes data = {'H', 'e', 'l', 'l', 'o'};
    auto b64 = utils::toBase64(data);
    ASSERT(b64 == "SGVsbG8=", "Base64 encoding failed");

    auto decoded = utils::fromBase64(b64);
    ASSERT(decoded == data, "Base64 decoding failed");

    PASS();
}

/*============================================================================
 * Benchmark Tests
 *============================================================================*/

void test_benchmark_kem(Device &device)
{
    TEST("KEM benchmark");

    const int iterations = 100;

    // Benchmark keygen
    utils::Benchmark bench;
    for (int i = 0; i < iterations; ++i)
    {
        device.kem().generateKeyPair768();
    }
    double keygenTime = bench.elapsedMs() / iterations;

    // Benchmark encaps
    auto kp = device.kem().generateKeyPair768();
    bench.reset();
    for (int i = 0; i < iterations; ++i)
    {
        device.kem().encapsulate768(kp.publicKey);
    }
    double encapsTime = bench.elapsedMs() / iterations;

    std::cout << "keygen=" << std::fixed << std::setprecision(3)
              << keygenTime << "ms, encaps=" << encapsTime << "ms ";
    PASS();
}

/*============================================================================
 * Main
 *============================================================================*/

int main()
{
    std::cout << "========================================" << std::endl;
    std::cout << "QUAC 100 C++ SDK Test Suite" << std::endl;
    std::cout << "========================================" << std::endl
              << std::endl;

    try
    {
        // Initialize library
        Library lib;

        std::cout << "--- Library Tests ---" << std::endl;
        test_version();
        test_build_info();

        std::cout << std::endl
                  << "--- Device Tests ---" << std::endl;
        test_enumerate_devices(lib);

        // Open device
        Device device = lib.openFirstDevice();

        test_device_info(device);
        test_device_status(device);
        test_self_test(device);

        std::cout << std::endl
                  << "--- KEM Tests ---" << std::endl;
        test_kem_params();
        test_kem_keygen(device);
        test_kem_encaps_decaps(device);

        std::cout << std::endl
                  << "--- Signature Tests ---" << std::endl;
        test_sign_params();
        test_sign_keygen(device);
        test_sign_verify(device);

        std::cout << std::endl
                  << "--- Random Tests ---" << std::endl;
        test_random_bytes(device);
        test_random_range(device);
        test_random_uniform(device);
        test_random_uuid(device);

        std::cout << std::endl
                  << "--- Hash Tests ---" << std::endl;
        test_hash_sha256(device);
        test_hash_incremental(device);

        std::cout << std::endl
                  << "--- Utility Tests ---" << std::endl;
        test_secure_zero();
        test_secure_compare();
        test_hex_encoding();
        test_base64_encoding();

        std::cout << std::endl
                  << "--- Benchmark Tests ---" << std::endl;
        test_benchmark_kem(device);
    }
    catch (const Exception &e)
    {
        std::cerr << "FATAL: " << e.what() << std::endl;
        return 1;
    }

    std::cout << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Test Summary" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Total:  " << g_tests_run << std::endl;
    std::cout << "Passed: " << g_tests_passed << std::endl;
    std::cout << "Failed: " << g_tests_failed << std::endl;
    std::cout << "========================================" << std::endl;

    if (g_tests_failed == 0)
    {
        std::cout << std::endl
                  << "*** ALL TESTS PASSED! ***" << std::endl
                  << std::endl;
        return 0;
    }
    else
    {
        std::cout << std::endl
                  << "*** SOME TESTS FAILED ***" << std::endl
                  << std::endl;
        return 1;
    }
}