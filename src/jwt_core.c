/*
 * jwt_core.c - Main JWT Token Generation Logic
 *
 * Implements the JWT signing pipeline:
 *   1. Parse and validate algorithm name
 *   2. Build header JSON: {"alg":"PS256","typ":"JWT"}
 *   3. Base64URL encode header
 *   4. Base64URL encode payload (user-supplied JSON)
 *   5. Assemble signing input: header_b64 + "." + payload_b64
 *   6. Load key (auto-detected type)
 *   7. Sign using appropriate algorithm
 *   8. Base64URL encode signature
 *   9. Return: header_b64 + "." + payload_b64 + "." + sig_b64
 *
 * Thread safety: All functions use local variables only.
 * No global mutable state. Safe for concurrent VUsers.
 */

#include "jwt_core.h"

/* ============================================================
 * jwt_parse_algorithm
 * Maps algorithm name string to internal enum.
 * Case-insensitive comparison.
 * ============================================================ */
jwt_alg_t jwt_parse_algorithm(const char* algorithm) {
    if (!algorithm) return JWT_ALG_UNKNOWN;

    /* HMAC - symmetric */
    if (jwt_strcasecmp(algorithm, "HS256") == 0) return JWT_ALG_HS256;
    if (jwt_strcasecmp(algorithm, "HS384") == 0) return JWT_ALG_HS384;
    if (jwt_strcasecmp(algorithm, "HS512") == 0) return JWT_ALG_HS512;

    /* RSA PKCS#1 v1.5 - asymmetric */
    if (jwt_strcasecmp(algorithm, "RS256") == 0) return JWT_ALG_RS256;
    if (jwt_strcasecmp(algorithm, "RS384") == 0) return JWT_ALG_RS384;
    if (jwt_strcasecmp(algorithm, "RS512") == 0) return JWT_ALG_RS512;

    /* RSA-PSS - asymmetric (primary for most users) */
    if (jwt_strcasecmp(algorithm, "PS256") == 0) return JWT_ALG_PS256;
    if (jwt_strcasecmp(algorithm, "PS384") == 0) return JWT_ALG_PS384;
    if (jwt_strcasecmp(algorithm, "PS512") == 0) return JWT_ALG_PS512;

    /* ECDSA - asymmetric */
    if (jwt_strcasecmp(algorithm, "ES256") == 0) return JWT_ALG_ES256;
    if (jwt_strcasecmp(algorithm, "ES384") == 0) return JWT_ALG_ES384;
    if (jwt_strcasecmp(algorithm, "ES512") == 0) return JWT_ALG_ES512;

    return JWT_ALG_UNKNOWN;
}

/* ============================================================
 * jwt_get_hash_for_alg
 * Returns the OpenSSL EVP_MD for a given algorithm.
 * ============================================================ */
const EVP_MD* jwt_get_hash_for_alg(jwt_alg_t alg) {
    switch (alg) {
        case JWT_ALG_HS256:
        case JWT_ALG_RS256:
        case JWT_ALG_PS256:
        case JWT_ALG_ES256:
            return EVP_sha256();

        case JWT_ALG_HS384:
        case JWT_ALG_RS384:
        case JWT_ALG_PS384:
        case JWT_ALG_ES384:
            return EVP_sha384();

        case JWT_ALG_HS512:
        case JWT_ALG_RS512:
        case JWT_ALG_PS512:
        case JWT_ALG_ES512:
            return EVP_sha512();

        default:
            return NULL;
    }
}

/* ============================================================
 * jwt_generate_token
 * Main internal function called by JWT_Generate() export.
 * ============================================================ */
int jwt_generate_token(const char* algorithm,
                       const char* payload_json,
                       const char* key_or_secret,
                       char*       output_token,
                       int         buffer_size)
{
    jwt_alg_t      alg;
    const EVP_MD*  md;
    char           header_json[256];
    int            header_json_len;
    char           header_b64[JWT_MAX_HEADER_B64];
    int            header_b64_len;
    char*          payload_b64    = NULL;
    int            payload_b64_len;
    char*          signing_input  = NULL;
    size_t         signing_len;
    unsigned char  sig_bytes[JWT_MAX_SIG_BYTES];
    size_t         sig_len        = sizeof(sig_bytes);
    char           sig_b64[JWT_MAX_SIG_B64];
    int            sig_b64_len;
    jwt_key_type_t key_type;
    EVP_PKEY*      pkey           = NULL;
    size_t         payload_json_len;
    size_t         payload_b64_size;
    int            rc             = JWT_SUCCESS;
    int            total_len;

    /* ---- Input validation ---- */
    if (!algorithm || !payload_json || !key_or_secret ||
        !output_token || buffer_size <= 0) {
        return JWT_ERROR_NULL_POINTER;
    }

    /* ---- Parse algorithm ---- */
    alg = jwt_parse_algorithm(algorithm);
    if (alg == JWT_ALG_UNKNOWN) {
        return JWT_ERROR_INVALID_ALG;
    }

    md = jwt_get_hash_for_alg(alg);
    if (!md) return JWT_ERROR_INVALID_ALG;

    /* ---- Build header JSON ----
     * Always: {"alg":"<ALG>","typ":"JWT"}
     * Algorithm name from user input (preserves original case).
     */
    header_json_len = snprintf(header_json, sizeof(header_json),
                               "{\"alg\":\"%s\",\"typ\":\"JWT\"}", algorithm);
    if (header_json_len < 0 || header_json_len >= (int)sizeof(header_json)) {
        return JWT_ERROR_BUFFER_SMALL;
    }

    /* ---- Base64URL encode header ---- */
    header_b64_len = base64url_encode(
        (const unsigned char*)header_json,
        (size_t)header_json_len,
        header_b64,
        sizeof(header_b64)
    );
    if (header_b64_len < 0) return JWT_ERROR_ENCODE;

    /* ---- Base64URL encode payload ---- */
    payload_json_len = strlen(payload_json);
    payload_b64_size = base64url_encoded_len(payload_json_len) + 1;
    payload_b64      = (char*)malloc(payload_b64_size);
    if (!payload_b64) return JWT_ERROR_MEMORY;

    payload_b64_len = base64url_encode(
        (const unsigned char*)payload_json,
        payload_json_len,
        payload_b64,
        payload_b64_size
    );
    if (payload_b64_len < 0) {
        rc = JWT_ERROR_ENCODE;
        goto cleanup;
    }

    /* ---- Build signing input: header_b64 + "." + payload_b64 ---- */
    signing_len  = (size_t)header_b64_len + 1 + (size_t)payload_b64_len;
    signing_input = (char*)malloc(signing_len + 1);
    if (!signing_input) {
        rc = JWT_ERROR_MEMORY;
        goto cleanup;
    }

    memcpy(signing_input,                   header_b64,  (size_t)header_b64_len);
    signing_input[header_b64_len] = '.';
    memcpy(signing_input + header_b64_len + 1, payload_b64, (size_t)payload_b64_len);
    signing_input[signing_len] = '\0';

    /* ---- Detect key type ---- */
    key_type = jwt_detect_key_type(key_or_secret);

    /* ---- Sign ---- */
    memset(sig_bytes, 0, sizeof(sig_bytes));
    sig_len = sizeof(sig_bytes);

    if (alg >= JWT_ALG_HS256 && alg <= JWT_ALG_HS512) {
        /* --- HMAC (symmetric) --- */
        rc = jwt_sign_hmac(signing_input, signing_len,
                           key_or_secret, md,
                           sig_bytes, &sig_len);

    } else {
        /* --- Asymmetric: load key first --- */
        pkey = jwt_load_private_key(key_or_secret, key_type);
        if (!pkey) {
            rc = (key_type == KEY_PEM_FILE || key_type == KEY_P12_FILE)
                 ? JWT_ERROR_FILE_NOT_FOUND
                 : JWT_ERROR_INVALID_KEY;
            goto cleanup;
        }

        if (alg >= JWT_ALG_RS256 && alg <= JWT_ALG_RS512) {
            /* --- RSA PKCS#1 v1.5 --- */
            rc = jwt_sign_rsa(signing_input, signing_len,
                              pkey, md, sig_bytes, &sig_len);

        } else if (alg >= JWT_ALG_PS256 && alg <= JWT_ALG_PS512) {
            /* --- RSA-PSS (primary) --- */
            rc = jwt_sign_rsa_pss(signing_input, signing_len,
                                  pkey, md, sig_bytes, &sig_len);

        } else if (alg >= JWT_ALG_ES256 && alg <= JWT_ALG_ES512) {
            /* --- ECDSA --- */
            rc = jwt_sign_ecdsa(signing_input, signing_len,
                                pkey, md, alg, sig_bytes, &sig_len);
        }

        EVP_PKEY_free(pkey);
        pkey = NULL;
    }

    if (rc != JWT_SUCCESS) goto cleanup;

    /* ---- Base64URL encode signature ---- */
    sig_b64_len = base64url_encode(sig_bytes, sig_len,
                                   sig_b64, sizeof(sig_b64));
    if (sig_b64_len < 0) {
        rc = JWT_ERROR_ENCODE;
        goto cleanup;
    }

    /* ---- Assemble final token: header.payload.signature ---- */
    /* +3 for two dots and null terminator */
    total_len = header_b64_len + 1 + payload_b64_len + 1 + sig_b64_len + 1;
    if (total_len > buffer_size) {
        rc = JWT_ERROR_BUFFER_SMALL;
        goto cleanup;
    }

    {
        int offset = 0;
        memcpy(output_token + offset, header_b64,  (size_t)header_b64_len);
        offset += header_b64_len;
        output_token[offset++] = '.';
        memcpy(output_token + offset, payload_b64, (size_t)payload_b64_len);
        offset += payload_b64_len;
        output_token[offset++] = '.';
        memcpy(output_token + offset, sig_b64,     (size_t)sig_b64_len);
        offset += sig_b64_len;
        output_token[offset] = '\0';
    }

cleanup:
    if (payload_b64)   free(payload_b64);
    if (signing_input) free(signing_input);
    if (pkey)          EVP_PKEY_free(pkey);
    return rc;
}
