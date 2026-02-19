/*
 * rs256.c - RSA PKCS#1 v1.5 Signing for RS256, RS384, RS512
 *
 * Uses OpenSSL EVP_DigestSign* API with default RSA padding.
 * Default RSA padding in OpenSSL EVP is PKCS#1 v1.5 (RSASSA-PKCS1-v1_5).
 *
 * The EVP_MD pointer determines which SHA variant is used:
 *   EVP_sha256() -> RS256
 *   EVP_sha384() -> RS384
 *   EVP_sha512() -> RS512
 *
 * Key must be loaded as an EVP_PKEY (RSA private key).
 * Minimum recommended key size: 2048 bits.
 */

#include "jwt_core.h"

/* ============================================================
 * jwt_sign_rsa
 * ============================================================ */
int jwt_sign_rsa(const char*    signing_input,
                 size_t         input_len,
                 EVP_PKEY*      pkey,
                 const EVP_MD*  md,
                 unsigned char* sig_out,
                 size_t*        sig_len)
{
    EVP_MD_CTX* ctx = NULL;
    int         rc  = JWT_SUCCESS;
    size_t      len = 0;

    if (!signing_input || !pkey || !sig_out || !sig_len || !md) {
        return JWT_ERROR_NULL_POINTER;
    }

    ctx = EVP_MD_CTX_new();
    if (!ctx) return JWT_ERROR_MEMORY;

    /* Initialize: RSA PKCS#1 v1.5 padding is the default for RSA keys */
    if (EVP_DigestSignInit(ctx, NULL, md, NULL, pkey) != 1) {
        rc = JWT_ERROR_SIGN_FAILED;
        goto cleanup;
    }

    /* Feed the signing input */
    if (EVP_DigestSignUpdate(ctx, signing_input, input_len) != 1) {
        rc = JWT_ERROR_SIGN_FAILED;
        goto cleanup;
    }

    /* First call: get required signature buffer size */
    if (EVP_DigestSignFinal(ctx, NULL, &len) != 1) {
        rc = JWT_ERROR_SIGN_FAILED;
        goto cleanup;
    }

    if (len > JWT_MAX_SIG_BYTES) {
        rc = JWT_ERROR_BUFFER_SMALL;
        goto cleanup;
    }

    /* Second call: get actual signature */
    *sig_len = len;
    if (EVP_DigestSignFinal(ctx, sig_out, sig_len) != 1) {
        rc = JWT_ERROR_SIGN_FAILED;
        goto cleanup;
    }

cleanup:
    EVP_MD_CTX_free(ctx);
    return rc;
}
