/*
 * es256.c - ECDSA Signing for ES256, ES384, ES512
 *
 * IMPORTANT - DER to R||S conversion:
 * OpenSSL EVP_DigestSign produces an ECDSA signature in DER (ASN.1) format:
 *   SEQUENCE {
 *     INTEGER r
 *     INTEGER s
 *   }
 *
 * JWT requires the raw R||S format (RFC 7518 §3.4):
 *   - R and S each zero-padded to the curve's coordinate byte length
 *   - Concatenated: [R bytes][S bytes]
 *
 * Curve sizes:
 *   ES256: P-256 (prime256v1) → 32 bytes each → 64 bytes total
 *   ES384: P-384 (secp384r1)  → 48 bytes each → 96 bytes total
 *   ES512: P-521 (secp521r1)  → 66 bytes each → 132 bytes total
 *         (P-521 is 521 bits = ceil(521/8) = 66 bytes, NOT 65)
 */

#include "jwt_core.h"

/* ============================================================
 * ecdsa_der_to_raw
 * Convert OpenSSL DER-encoded ECDSA signature to JWT R||S format.
 * curve_bytes: byte length of each coordinate (32, 48, or 66).
 * ============================================================ */
static int ecdsa_der_to_raw(const unsigned char* der_sig,
                             size_t               der_len,
                             unsigned char*       raw_sig,
                             size_t*              raw_len,
                             int                  curve_bytes)
{
    ECDSA_SIG*    sig = NULL;
    const BIGNUM* r   = NULL;
    const BIGNUM* s   = NULL;
    int           r_bytes, s_bytes;

    /*
     * d2i_ECDSA_SIG modifies the pointer, so use a copy.
     * d2i_ functions expect a pointer-to-pointer.
     */
    const unsigned char* p = der_sig;
    sig = d2i_ECDSA_SIG(NULL, &p, (long)der_len);
    if (!sig) return JWT_ERROR_SIGN_FAILED;

    ECDSA_SIG_get0(sig, &r, &s);

    r_bytes = BN_num_bytes(r);
    s_bytes = BN_num_bytes(s);

    /*
     * BIGNUMs can be shorter than curve_bytes if leading bytes are zero.
     * They must NOT be longer (would indicate wrong key curve).
     */
    if (r_bytes > curve_bytes || s_bytes > curve_bytes) {
        ECDSA_SIG_free(sig);
        return JWT_ERROR_SIGN_FAILED;
    }

    /* Zero the output buffer */
    memset(raw_sig, 0, (size_t)(curve_bytes * 2));

    /*
     * Right-align r and s within their respective curve_bytes slots.
     * Leading zeros are already zeroed by memset above.
     */
    BN_bn2bin(r, raw_sig + (curve_bytes - r_bytes));
    BN_bn2bin(s, raw_sig + (curve_bytes * 2 - s_bytes));

    *raw_len = (size_t)(curve_bytes * 2);

    ECDSA_SIG_free(sig);
    return JWT_SUCCESS;
}

/* ============================================================
 * jwt_sign_ecdsa
 * ============================================================ */
int jwt_sign_ecdsa(const char*    signing_input,
                   size_t         input_len,
                   EVP_PKEY*      pkey,
                   const EVP_MD*  md,
                   jwt_alg_t      alg,
                   unsigned char* sig_out,
                   size_t*        sig_len)
{
    EVP_MD_CTX*    ctx     = NULL;
    unsigned char* der_sig = NULL;
    size_t         der_len = 0;
    int            rc      = JWT_SUCCESS;
    int            curve_bytes;

    if (!signing_input || !pkey || !sig_out || !sig_len || !md) {
        return JWT_ERROR_NULL_POINTER;
    }

    /* Determine coordinate byte length per curve */
    switch (alg) {
        case JWT_ALG_ES256: curve_bytes = 32; break;
        case JWT_ALG_ES384: curve_bytes = 48; break;
        case JWT_ALG_ES512: curve_bytes = 66; break;
        default:            return JWT_ERROR_INVALID_ALG;
    }

    ctx = EVP_MD_CTX_new();
    if (!ctx) return JWT_ERROR_MEMORY;

    if (EVP_DigestSignInit(ctx, NULL, md, NULL, pkey) != 1) {
        rc = JWT_ERROR_SIGN_FAILED;
        goto cleanup;
    }

    if (EVP_DigestSignUpdate(ctx, signing_input, input_len) != 1) {
        rc = JWT_ERROR_SIGN_FAILED;
        goto cleanup;
    }

    /* First call: get DER signature length */
    if (EVP_DigestSignFinal(ctx, NULL, &der_len) != 1) {
        rc = JWT_ERROR_SIGN_FAILED;
        goto cleanup;
    }

    der_sig = (unsigned char*)malloc(der_len);
    if (!der_sig) {
        rc = JWT_ERROR_MEMORY;
        goto cleanup;
    }

    /* Second call: get DER signature bytes */
    if (EVP_DigestSignFinal(ctx, der_sig, &der_len) != 1) {
        rc = JWT_ERROR_SIGN_FAILED;
        goto cleanup;
    }

    /* Convert DER → JWT R||S format */
    rc = ecdsa_der_to_raw(der_sig, der_len, sig_out, sig_len, curve_bytes);

cleanup:
    if (der_sig) free(der_sig);
    EVP_MD_CTX_free(ctx);
    return rc;
}
