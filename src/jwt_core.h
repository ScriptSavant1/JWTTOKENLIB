/*
 * jwt_core.h - Internal header for JWTTokenLib
 * NOT part of the public API. Do not include in user code.
 *
 * All source files under src/ include this single header.
 * It provides: algorithm enum, key type enum, all OpenSSL includes,
 * and internal function prototypes.
 */

#ifndef JWT_CORE_H
#define JWT_CORE_H

/* Standard library */
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

/* OpenSSL */
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/err.h>

/* Public API - brings in JWTLIB_API and error codes */
#include "../include/jwtlib.h"

/* ============================================================
 * Internal Limits
 * ============================================================ */
#define JWT_MAX_HEADER_B64    256     /* Max base64url-encoded header   */
#define JWT_MAX_PAYLOAD_B64   16384   /* Max base64url-encoded payload  */
#define JWT_MAX_SIG_B64       1024    /* Max base64url-encoded signature */
#define JWT_MAX_SIG_BYTES     512     /* Max raw signature bytes (RSA)  */

/* ============================================================
 * Algorithm Enum
 * ============================================================ */
typedef enum {
    JWT_ALG_UNKNOWN = 0,
    /* HMAC symmetric */
    JWT_ALG_HS256, JWT_ALG_HS384, JWT_ALG_HS512,
    /* RSA PKCS#1 v1.5 */
    JWT_ALG_RS256, JWT_ALG_RS384, JWT_ALG_RS512,
    /* RSA-PSS  <-- primary for most users */
    JWT_ALG_PS256, JWT_ALG_PS384, JWT_ALG_PS512,
    /* ECDSA */
    JWT_ALG_ES256, JWT_ALG_ES384, JWT_ALG_ES512
} jwt_alg_t;

/* ============================================================
 * Key Type Enum (auto-detected from key_or_secret string)
 * ============================================================ */
typedef enum {
    KEY_PEM_FILE = 0,   /* File path ending with .pem              */
    KEY_PEM_CONTENT,    /* PEM content starting with "-----BEGIN"  */
    KEY_P12_FILE,       /* File path ending with .p12 or .pfx      */
    KEY_HMAC_SECRET     /* Raw string secret for HMAC algorithms   */
} jwt_key_type_t;

/* ============================================================
 * Platform Compatibility
 * ============================================================ */
#ifdef _WIN32
  #define jwt_strcasecmp  _stricmp
  #define jwt_strncasecmp _strnicmp
#else
  #include <strings.h>
  #define jwt_strcasecmp  strcasecmp
  #define jwt_strncasecmp strncasecmp
#endif

/* ============================================================
 * Internal Function Prototypes
 * ============================================================ */

/* --- Algorithm parsing (jwt_core.c) --- */
jwt_alg_t       jwt_parse_algorithm(const char* algorithm);
const EVP_MD*   jwt_get_hash_for_alg(jwt_alg_t alg);

/* --- Main generation logic (jwt_core.c) --- */
int jwt_generate_token(
    const char* algorithm,
    const char* payload_json,
    const char* key_or_secret,
    char*       output_token,
    int         buffer_size
);

/* --- Base64URL (utils/base64url.c) --- */
size_t base64url_encoded_len(size_t input_len);

int base64url_encode(
    const unsigned char* input,
    size_t               input_len,
    char*                output,
    size_t               output_size
);

int base64url_decode(
    const char*    input,
    size_t         input_len,
    unsigned char* output,
    size_t*        output_len
);

/* --- Key management (utils/key_manager.c) --- */
jwt_key_type_t jwt_detect_key_type(const char* key_or_secret);

EVP_PKEY* jwt_load_private_key(
    const char*    key_or_secret,
    jwt_key_type_t key_type
);

/* --- Signing algorithms --- */

/* HMAC (algorithms/hs256.c) */
int jwt_sign_hmac(
    const char*    signing_input,
    size_t         input_len,
    const char*    secret,
    const EVP_MD*  md,
    unsigned char* sig_out,
    size_t*        sig_len
);

/* RSA PKCS#1 v1.5 (algorithms/rs256.c) */
int jwt_sign_rsa(
    const char*    signing_input,
    size_t         input_len,
    EVP_PKEY*      pkey,
    const EVP_MD*  md,
    unsigned char* sig_out,
    size_t*        sig_len
);

/* RSA-PSS (algorithms/ps256.c) */
int jwt_sign_rsa_pss(
    const char*    signing_input,
    size_t         input_len,
    EVP_PKEY*      pkey,
    const EVP_MD*  md,
    unsigned char* sig_out,
    size_t*        sig_len
);

/* ECDSA (algorithms/es256.c) */
int jwt_sign_ecdsa(
    const char*    signing_input,
    size_t         input_len,
    EVP_PKEY*      pkey,
    const EVP_MD*  md,
    jwt_alg_t      alg,
    unsigned char* sig_out,
    size_t*        sig_len
);

#endif /* JWT_CORE_H */
