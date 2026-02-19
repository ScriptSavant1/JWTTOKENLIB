/*
 * ps256.c - RSA-PSS Signing for PS256, PS384, PS512
 *
 * PRIMARY algorithm for most LRE users.
 *
 * RSA-PSS (Probabilistic Signature Scheme) per RFC 8017:
 *   - Padding:     RSA_PKCS1_PSS_PADDING
 *   - Salt length: RSA_PSS_SALTLEN_DIGEST (salt = hash output length)
 *   - MGF1:        same hash as signature (MGF1 with SHA-256 for PS256)
 *
 * The EVP_MD pointer determines which SHA variant is used:
 *   EVP_sha256() -> PS256 (most common)
 *   EVP_sha384() -> PS384
 *   EVP_sha512() -> PS512
 *
 * Key must be RSA private key, minimum 2048 bits recommended.
 * PS256 with 2048-bit key achieves 8,000-12,000 signatures/sec on
 * modern hardware (easily handles 100-1000 TPS load tests).
 */

#include "jwt_core.h"
#include <openssl/rsa.h>

/* ============================================================
 * jwt_sign_rsa_pss
 * ============================================================ */
int jwt_sign_rsa_pss(const char*    signing_input,
                     size_t         input_len,
                     EVP_PKEY*      pkey,
                     const EVP_MD*  md,
                     unsigned char* sig_out,
                     size_t*        sig_len)
{
    EVP_MD_CTX*   ctx      = NULL;
    EVP_PKEY_CTX* pkey_ctx = NULL;  /* Owned by ctx, do NOT free separately */
    int           rc       = JWT_SUCCESS;
    size_t        len      = 0;

    if (!signing_input || !pkey || !sig_out || !sig_len || !md) {
        return JWT_ERROR_NULL_POINTER;
    }

    ctx = EVP_MD_CTX_new();
    if (!ctx) return JWT_ERROR_MEMORY;

    /*
     * EVP_DigestSignInit with pkey_ctx output so we can set PSS parameters.
     * pkey_ctx is managed by ctx and freed with EVP_MD_CTX_free(ctx).
     */
    if (EVP_DigestSignInit(ctx, &pkey_ctx, md, NULL, pkey) != 1) {
        rc = JWT_ERROR_SIGN_FAILED;
        goto cleanup;
    }

    /* Set RSA-PSS padding mode */
    if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) <= 0) {
        rc = JWT_ERROR_SIGN_FAILED;
        goto cleanup;
    }

    /*
     * Salt length = digest size.
     * RFC 7518 §3.5 recommends saltlen = hLen (hash output length).
     * RSA_PSS_SALTLEN_DIGEST = use the hash length as salt length.
     */
    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, RSA_PSS_SALTLEN_DIGEST) <= 0) {
        rc = JWT_ERROR_SIGN_FAILED;
        goto cleanup;
    }

    /* Feed the signing input: base64url(header).base64url(payload) */
    if (EVP_DigestSignUpdate(ctx, signing_input, input_len) != 1) {
        rc = JWT_ERROR_SIGN_FAILED;
        goto cleanup;
    }

    /* First call: determine required output buffer size */
    if (EVP_DigestSignFinal(ctx, NULL, &len) != 1) {
        rc = JWT_ERROR_SIGN_FAILED;
        goto cleanup;
    }

    if (len > JWT_MAX_SIG_BYTES) {
        rc = JWT_ERROR_BUFFER_SMALL;
        goto cleanup;
    }

    /* Second call: produce the actual RSA-PSS signature */
    *sig_len = len;
    if (EVP_DigestSignFinal(ctx, sig_out, sig_len) != 1) {
        rc = JWT_ERROR_SIGN_FAILED;
        goto cleanup;
    }

cleanup:
    EVP_MD_CTX_free(ctx);  /* also frees pkey_ctx */
    return rc;
}
