/*
 * test_standalone.c - Standalone C Test Suite for JWTTokenLib
 *
 * Tests all algorithms, error handling, and edge cases.
 * Run this after building to verify the library works correctly.
 *
 * Build and run:
 *   (Built automatically by CMake as 'test_jwt' executable)
 *   build/bin/Release/test_jwt.exe        (Windows)
 *   build/bin/test_jwt                     (Linux)
 *
 * You need:
 *   tests/keys/test_rsa_private.pem   (RSA key for RS256/PS256)
 *   tests/keys/test_ec_private.pem    (EC key for ES256)
 *   Generate with commands at bottom of this file.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Include the public API */
#include "jwtlib.h"

/* ============================================================
 * Test helpers
 * ============================================================ */
static int tests_run    = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_PASS(name) do { \
    tests_run++; tests_passed++; \
    printf("[PASS] %s\n", (name)); \
} while(0)

#define TEST_FAIL(name, msg) do { \
    tests_run++; tests_failed++; \
    printf("[FAIL] %s: %s\n", (name), (msg)); \
} while(0)

#define ASSERT_EQ(name, expected, actual) do { \
    if ((expected) == (actual)) { TEST_PASS(name); } \
    else { \
        char _buf[256]; \
        snprintf(_buf, sizeof(_buf), "expected %d, got %d", (int)(expected), (int)(actual)); \
        TEST_FAIL(name, _buf); \
    } \
} while(0)

#define ASSERT_STR_PREFIX(name, prefix, str) do { \
    if (strncmp((prefix), (str), strlen(prefix)) == 0) { TEST_PASS(name); } \
    else { \
        char _buf[256]; \
        snprintf(_buf, sizeof(_buf), "expected prefix '%s', got '%s'", (prefix), (str)); \
        TEST_FAIL(name, _buf); \
    } \
} while(0)

/* Verify token has 3 dot-separated parts */
static int has_three_parts(const char* token) {
    int dots = 0;
    const char* p = token;
    while (*p) { if (*p++ == '.') dots++; }
    return dots == 2;
}

/* ============================================================
 * Build a sample payload JSON string
 * ============================================================ */
static void build_payload(char* buf, size_t buf_size, const char* sub) {
    long ts = (long)time(NULL);
    snprintf(buf, buf_size,
        "{"
        "\"iss\":\"loadtest-system\","
        "\"sub\":\"%s\","
        "\"aud\":\"api.production.com\","
        "\"exp\":%ld,"
        "\"iat\":%ld,"
        "\"jti\":\"test-token-001\","
        "\"role\":\"customer\""
        "}",
        sub, ts + 3600, ts);
}

/* ============================================================
 * Test: Library version and algorithm support
 * ============================================================ */
static void test_version_and_algorithms(void) {
    printf("\n--- Version & Algorithm Support ---\n");

    const char* version = JWT_Get_Version();
    if (version && strlen(version) > 0) TEST_PASS("JWT_Get_Version returns non-empty");
    else TEST_FAIL("JWT_Get_Version", "returned empty or NULL");
    printf("  Version: %s\n", version ? version : "(null)");

    ASSERT_EQ("PS256 supported", 1, JWT_Is_Algorithm_Supported("PS256"));
    ASSERT_EQ("RS256 supported", 1, JWT_Is_Algorithm_Supported("RS256"));
    ASSERT_EQ("HS256 supported", 1, JWT_Is_Algorithm_Supported("HS256"));
    ASSERT_EQ("ES256 supported", 1, JWT_Is_Algorithm_Supported("ES256"));
    ASSERT_EQ("PS384 supported", 1, JWT_Is_Algorithm_Supported("PS384"));
    ASSERT_EQ("RS512 supported", 1, JWT_Is_Algorithm_Supported("RS512"));
    ASSERT_EQ("INVALID not supported", 0, JWT_Is_Algorithm_Supported("INVALID"));
    ASSERT_EQ("NULL not supported",    0, JWT_Is_Algorithm_Supported(NULL));
    ASSERT_EQ("RS255 not supported",   0, JWT_Is_Algorithm_Supported("RS255"));
}

/* ============================================================
 * Test: HS256 token generation
 * ============================================================ */
static void test_hs256(void) {
    char token[4096];
    char payload[1024];
    int  rc;

    printf("\n--- HS256 (HMAC-SHA256) ---\n");
    build_payload(payload, sizeof(payload), "hs256-test-user");

    rc = JWT_Generate("HS256", payload, "my-super-secret-key-for-testing-purposes", token, sizeof(token));
    ASSERT_EQ("HS256 generate success", JWT_SUCCESS, rc);

    if (rc == JWT_SUCCESS) {
        if (has_three_parts(token)) TEST_PASS("HS256 token has 3 parts");
        else TEST_FAIL("HS256 token structure", "expected 3 dot-separated parts");

        /* JWT HS256 header is always: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 */
        ASSERT_STR_PREFIX("HS256 header prefix", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", token);
        printf("  Token: %.60s...\n", token);
    }

    /* Test with empty secret */
    rc = JWT_Generate("HS256", payload, "", token, sizeof(token));
    ASSERT_EQ("HS256 empty secret fails", JWT_ERROR_INVALID_KEY, rc);

    /* Test HS384 */
    rc = JWT_Generate("HS384", payload, "my-super-secret-key-for-testing-purposes", token, sizeof(token));
    ASSERT_EQ("HS384 generate success", JWT_SUCCESS, rc);

    /* Test HS512 */
    rc = JWT_Generate("HS512", payload, "my-super-secret-key-for-testing-purposes", token, sizeof(token));
    ASSERT_EQ("HS512 generate success", JWT_SUCCESS, rc);
}

/* ============================================================
 * Test: RSA algorithms (RS256, PS256) with PEM file
 * ============================================================ */
static void test_rsa_algorithms(void) {
    char token[4096];
    char payload[1024];
    int  rc;

    printf("\n--- RSA Algorithms (RS256 / PS256) ---\n");
    build_payload(payload, sizeof(payload), "rsa-test-user");

    /* Check if test key exists */
    FILE* f = fopen("tests/keys/test_rsa_private.pem", "r");
    if (!f) {
        printf("  [SKIP] tests/keys/test_rsa_private.pem not found\n");
        printf("  Generate with: openssl genrsa -out tests/keys/test_rsa_private.pem 2048\n");
        return;
    }
    fclose(f);

    /* PS256 - primary algorithm for most users */
    rc = JWT_Generate("PS256", payload, "tests/keys/test_rsa_private.pem", token, sizeof(token));
    ASSERT_EQ("PS256 generate success", JWT_SUCCESS, rc);
    if (rc == JWT_SUCCESS) {
        if (has_three_parts(token)) TEST_PASS("PS256 token has 3 parts");
        else TEST_FAIL("PS256 token structure", "expected 3 dot-separated parts");
        ASSERT_STR_PREFIX("PS256 header prefix", "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9", token);
        printf("  PS256 token: %.60s...\n", token);
    }

    /* RS256 */
    rc = JWT_Generate("RS256", payload, "tests/keys/test_rsa_private.pem", token, sizeof(token));
    ASSERT_EQ("RS256 generate success", JWT_SUCCESS, rc);
    if (rc == JWT_SUCCESS) {
        ASSERT_STR_PREFIX("RS256 header prefix", "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9", token);
        printf("  RS256 token: %.60s...\n", token);
    }

    /* PS384, PS512 */
    rc = JWT_Generate("PS384", payload, "tests/keys/test_rsa_private.pem", token, sizeof(token));
    ASSERT_EQ("PS384 generate success", JWT_SUCCESS, rc);

    rc = JWT_Generate("PS512", payload, "tests/keys/test_rsa_private.pem", token, sizeof(token));
    ASSERT_EQ("PS512 generate success", JWT_SUCCESS, rc);

    /* RS384, RS512 */
    rc = JWT_Generate("RS384", payload, "tests/keys/test_rsa_private.pem", token, sizeof(token));
    ASSERT_EQ("RS384 generate success", JWT_SUCCESS, rc);

    rc = JWT_Generate("RS512", payload, "tests/keys/test_rsa_private.pem", token, sizeof(token));
    ASSERT_EQ("RS512 generate success", JWT_SUCCESS, rc);
}

/* ============================================================
 * Test: PEM content string (as if from rts.yaml parameter)
 * ============================================================ */
static void test_pem_content_string(void) {
    char  token[4096];
    char  payload[1024];
    char  pem_content[8192];
    int   rc;
    FILE* f;

    printf("\n--- PEM Content String (rts.yaml scenario) ---\n");
    build_payload(payload, sizeof(payload), "pem-string-user");

    f = fopen("tests/keys/test_rsa_private.pem", "r");
    if (!f) {
        printf("  [SKIP] tests/keys/test_rsa_private.pem not found\n");
        return;
    }

    /* Read entire PEM file into a string (simulates rts.yaml parameter) */
    size_t n = fread(pem_content, 1, sizeof(pem_content) - 1, f);
    pem_content[n] = '\0';
    fclose(f);

    /* Pass PEM content directly as key_or_secret */
    rc = JWT_Generate("PS256", payload, pem_content, token, sizeof(token));
    ASSERT_EQ("PS256 with PEM content string", JWT_SUCCESS, rc);
    if (rc == JWT_SUCCESS) {
        printf("  Token: %.60s...\n", token);
    }
}

/* ============================================================
 * Test: ECDSA (ES256) with PEM file
 * ============================================================ */
static void test_es256(void) {
    char token[4096];
    char payload[1024];
    int  rc;

    printf("\n--- ES256 (ECDSA P-256) ---\n");
    build_payload(payload, sizeof(payload), "ec-test-user");

    FILE* f = fopen("tests/keys/test_ec_private.pem", "r");
    if (!f) {
        printf("  [SKIP] tests/keys/test_ec_private.pem not found\n");
        printf("  Generate with: openssl ecparam -genkey -name prime256v1 -noout -out tests/keys/test_ec_private.pem\n");
        return;
    }
    fclose(f);

    rc = JWT_Generate("ES256", payload, "tests/keys/test_ec_private.pem", token, sizeof(token));
    ASSERT_EQ("ES256 generate success", JWT_SUCCESS, rc);
    if (rc == JWT_SUCCESS) {
        if (has_three_parts(token)) TEST_PASS("ES256 token has 3 parts");
        else TEST_FAIL("ES256 token structure", "expected 3 dot-separated parts");
        printf("  Token: %.60s...\n", token);
    }
}

/* ============================================================
 * Test: Error handling
 * ============================================================ */
static void test_error_handling(void) {
    char token[4096];
    char small[10];
    int  rc;

    printf("\n--- Error Handling ---\n");

    /* NULL arguments */
    rc = JWT_Generate(NULL, "{}", "secret", token, sizeof(token));
    ASSERT_EQ("NULL algorithm", JWT_ERROR_NULL_POINTER, rc);

    rc = JWT_Generate("HS256", NULL, "secret", token, sizeof(token));
    ASSERT_EQ("NULL payload", JWT_ERROR_NULL_POINTER, rc);

    rc = JWT_Generate("HS256", "{}", NULL, token, sizeof(token));
    ASSERT_EQ("NULL key", JWT_ERROR_NULL_POINTER, rc);

    rc = JWT_Generate("HS256", "{}", "secret", NULL, sizeof(token));
    ASSERT_EQ("NULL output", JWT_ERROR_NULL_POINTER, rc);

    /* Invalid algorithm */
    rc = JWT_Generate("SHA256", "{}", "secret", token, sizeof(token));
    ASSERT_EQ("Invalid algorithm 'SHA256'", JWT_ERROR_INVALID_ALG, rc);

    rc = JWT_Generate("HS256-BAD", "{}", "secret", token, sizeof(token));
    ASSERT_EQ("Invalid algorithm 'HS256-BAD'", JWT_ERROR_INVALID_ALG, rc);

    /* Buffer too small */
    rc = JWT_Generate("HS256", "{\"sub\":\"user1\"}", "secret", small, sizeof(small));
    ASSERT_EQ("Buffer too small", JWT_ERROR_BUFFER_SMALL, rc);

    /* Key file not found */
    rc = JWT_Generate("PS256", "{\"sub\":\"user1\"}", "non_existent_key.pem", token, sizeof(token));
    ASSERT_EQ("Key file not found", JWT_ERROR_FILE_NOT_FOUND, rc);

    /* Error messages */
    const char* msg;
    msg = JWT_Get_Error_Message(JWT_SUCCESS);
    if (msg && strlen(msg) > 0) TEST_PASS("Error msg for SUCCESS");
    else TEST_FAIL("Error msg for SUCCESS", "NULL or empty");

    msg = JWT_Get_Error_Message(JWT_ERROR_INVALID_ALG);
    if (msg && strlen(msg) > 0) TEST_PASS("Error msg for INVALID_ALG");
    else TEST_FAIL("Error msg for INVALID_ALG", "NULL or empty");

    msg = JWT_Get_Error_Message(JWT_ERROR_FILE_NOT_FOUND);
    if (msg && strlen(msg) > 0) TEST_PASS("Error msg for FILE_NOT_FOUND");
    else TEST_FAIL("Error msg for FILE_NOT_FOUND", "NULL or empty");

    msg = JWT_Get_Error_Message(-999);
    if (msg && strlen(msg) > 0) TEST_PASS("Error msg for unknown code");
    else TEST_FAIL("Error msg for unknown code", "NULL or empty");
}

/* ============================================================
 * Test: JWT_Is_Token_Expiring
 * ============================================================ */
static void test_token_expiry(void) {
    char token[4096];
    char payload[512];
    long ts = (long)time(NULL);
    int  rc;

    printf("\n--- Token Expiry Detection ---\n");

    /* Token that expires in 15 minutes */
    snprintf(payload, sizeof(payload),
        "{\"sub\":\"user1\",\"exp\":%ld,\"iat\":%ld}",
        ts + 900, ts);

    rc = JWT_Generate("HS256", payload, "test-secret-key", token, sizeof(token));
    if (rc == JWT_SUCCESS) {
        /* Should NOT be expiring (900s remaining, threshold=300) */
        ASSERT_EQ("Token not expiring (900s left, 300s threshold)", 0,
                  JWT_Is_Token_Expiring(token, 300));

        /* Should be expiring (900s remaining, threshold=1200) */
        ASSERT_EQ("Token is expiring (900s left, 1200s threshold)", 1,
                  JWT_Is_Token_Expiring(token, 1200));
    }

    /* Token with no "exp" claim */
    rc = JWT_Generate("HS256", "{\"sub\":\"user1\"}", "test-secret-key", token, sizeof(token));
    if (rc == JWT_SUCCESS) {
        ASSERT_EQ("No exp claim returns -1", -1, JWT_Is_Token_Expiring(token, 300));
    }

    /* Invalid token */
    ASSERT_EQ("Invalid token returns -1", -1, JWT_Is_Token_Expiring("not.a.valid.jwt", 300));
    ASSERT_EQ("NULL token returns -1",    -1, JWT_Is_Token_Expiring(NULL, 300));
    ASSERT_EQ("Empty token returns -1",   -1, JWT_Is_Token_Expiring("", 300));

    /* Token already expired */
    snprintf(payload, sizeof(payload),
        "{\"sub\":\"user1\",\"exp\":%ld,\"iat\":%ld}",
        ts - 100, ts - 1000);  /* expired 100 seconds ago */

    rc = JWT_Generate("HS256", payload, "test-secret-key", token, sizeof(token));
    if (rc == JWT_SUCCESS) {
        ASSERT_EQ("Already expired token returns 1", 1,
                  JWT_Is_Token_Expiring(token, 0));
    }
}

/* ============================================================
 * Test: Performance measurement
 * ============================================================ */
static void test_performance(void) {
    char token[4096];
    char payload[512];
    long ts = (long)time(NULL);
    int  rc;
    int  i;
    int  count    = 1000;
    clock_t start, end;
    double  elapsed;

    printf("\n--- Performance (HS256 x %d) ---\n", count);

    snprintf(payload, sizeof(payload),
        "{\"sub\":\"perf-user\",\"exp\":%ld,\"iat\":%ld}",
        ts + 3600, ts);

    start = clock();
    for (i = 0; i < count; i++) {
        rc = JWT_Generate("HS256", payload, "perf-test-secret-key", token, sizeof(token));
        if (rc != JWT_SUCCESS) {
            printf("  Performance test failed at iteration %d: %s\n",
                   i, JWT_Get_Error_Message(rc));
            return;
        }
    }
    end = clock();

    elapsed = (double)(end - start) / CLOCKS_PER_SEC;
    double tps = count / elapsed;
    printf("  %d tokens in %.3f seconds = %.0f TPS\n", count, elapsed, tps);
    if (tps > 1000) TEST_PASS("HS256 performance > 1000 TPS");
    else printf("  [INFO] HS256 TPS: %.0f (lower than expected, check build type)\n", tps);

    /* PS256 performance (if key exists) */
    FILE* f = fopen("tests/keys/test_rsa_private.pem", "r");
    if (f) {
        fclose(f);
        count = 200;
        printf("\n--- Performance (PS256 x %d) ---\n", count);
        start = clock();
        for (i = 0; i < count; i++) {
            rc = JWT_Generate("PS256", payload, "tests/keys/test_rsa_private.pem",
                              token, sizeof(token));
            if (rc != JWT_SUCCESS) break;
        }
        end = clock();
        elapsed = (double)(end - start) / CLOCKS_PER_SEC;
        tps = count / elapsed;
        printf("  %d tokens in %.3f seconds = %.0f TPS\n", count, elapsed, tps);
        if (tps > 100) TEST_PASS("PS256 performance > 100 TPS");
        else printf("  [INFO] PS256 TPS: %.0f\n", tps);
    }
}

/* ============================================================
 * Main
 * ============================================================ */
int main(void) {
    printf("============================================================\n");
    printf("JWTTokenLib Test Suite v%s\n", JWT_Get_Version());
    printf("============================================================\n");
    printf("\nSetup: Generate test keys if missing:\n");
    printf("  mkdir tests\\keys (Windows) or mkdir -p tests/keys (Linux)\n");
    printf("  openssl genrsa -out tests/keys/test_rsa_private.pem 2048\n");
    printf("  openssl ecparam -genkey -name prime256v1 -noout -out tests/keys/test_ec_private.pem\n\n");

    test_version_and_algorithms();
    test_hs256();
    test_rsa_algorithms();
    test_pem_content_string();
    test_es256();
    test_error_handling();
    test_token_expiry();
    test_performance();

    printf("\n============================================================\n");
    printf("Results: %d/%d passed", tests_passed, tests_run);
    if (tests_failed > 0) printf(", %d FAILED", tests_failed);
    printf("\n============================================================\n");

    return tests_failed > 0 ? 1 : 0;
}
