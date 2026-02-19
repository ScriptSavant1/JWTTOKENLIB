/*
 * hs256.c - HMAC Signing for HS256, HS384, HS512
 *
 * Uses OpenSSL HMAC() for FIPS-compliant HMAC-SHA computation.
 * The EVP_MD pointer determines which SHA variant is used:
 *   EVP_sha256() -> HS256
 *   EVP_sha384() -> HS384
 *   EVP_sha512() -> HS512
 *
 * The "secret" is a raw string (e.g. from rts.yaml parameter).
 * The signing input is:  base64url(header) + "." + base64url(payload)
 */

#include "jwt_core.h"

/* ============================================================
 * jwt_sign_hmac
 * ============================================================ */
int jwt_sign_hmac(const char*    signing_input,
                  size_t         input_len,
                  const char*    secret,
                  const EVP_MD*  md,
                  unsigned char* sig_out,
                  size_t*        sig_len)
{
    unsigned int hmac_len = 0;

    if (!signing_input || !secret || !sig_out || !sig_len || !md) {
        return JWT_ERROR_NULL_POINTER;
    }

    if (secret[0] == '\0') {
        return JWT_ERROR_INVALID_KEY;
    }

    /*
     * HMAC(md, key, key_len, data, data_len, out, out_len)
     * Returns pointer to HMAC result on success, NULL on failure.
     */
    unsigned char* result = HMAC(
        md,
        (const unsigned char*)secret,
        (int)strlen(secret),
        (const unsigned char*)signing_input,
        (int)input_len,
        sig_out,
        &hmac_len
    );

    if (!result) {
        return JWT_ERROR_SIGN_FAILED;
    }

    *sig_len = (size_t)hmac_len;
    return JWT_SUCCESS;
}
