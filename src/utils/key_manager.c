/*
 * key_manager.c - Key Loading and Auto-Detection
 *
 * Auto-detects key type from the key_or_secret string:
 *
 *   "-----BEGIN ..."   -> PEM content in memory (from rts.yaml parameter)
 *   "*.pem"            -> PEM file path (from script extras/ folder)
 *   "*.p12" / "*.pfx"  -> PKCS#12 file path
 *   anything else      -> HMAC secret string (for HS256/384/512)
 *
 * Supported key formats loaded via OpenSSL:
 *   - RSA private key (PKCS#8 or traditional PEM)
 *   - EC private key  (for ECDSA algorithms)
 *   - PKCS#12 container (.p12 / .pfx) without password
 */

#include "jwt_core.h"

/* ============================================================
 * jwt_detect_key_type
 * ============================================================ */
jwt_key_type_t jwt_detect_key_type(const char* key_or_secret) {
    size_t len;

    if (!key_or_secret || key_or_secret[0] == '\0') {
        return KEY_HMAC_SECRET;
    }

    /* PEM content: starts with "-----BEGIN" */
    if (strncmp(key_or_secret, "-----BEGIN", 10) == 0) {
        return KEY_PEM_CONTENT;
    }

    /* File path detection by extension (last 4 chars) */
    len = strlen(key_or_secret);
    if (len >= 4) {
        const char* ext = key_or_secret + len - 4;
        if (jwt_strcasecmp(ext, ".pem") == 0) return KEY_PEM_FILE;
        if (jwt_strcasecmp(ext, ".p12") == 0) return KEY_P12_FILE;
        if (jwt_strcasecmp(ext, ".pfx") == 0) return KEY_P12_FILE;
    }

    /* Default: HMAC secret */
    return KEY_HMAC_SECRET;
}

/* ============================================================
 * load_key_from_bio
 * Internal: load EVP_PKEY from an OpenSSL BIO object.
 * Tries PKCS#8 first (most common modern format), then
 * falls back to traditional RSA/EC PEM format.
 * ============================================================ */
static EVP_PKEY* load_key_from_bio(BIO* bio) {
    EVP_PKEY* pkey = NULL;

    /* Try PKCS#8 PrivateKeyInfo (-----BEGIN PRIVATE KEY-----) */
    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (pkey) return pkey;

    /* Clear OpenSSL error queue and retry position */
    ERR_clear_error();
    BIO_reset(bio);

    /* Try traditional RSA (-----BEGIN RSA PRIVATE KEY-----) */
    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    return pkey;
}

/* ============================================================
 * jwt_load_private_key
 * Load an EVP_PKEY from file path or PEM content string.
 * Caller must EVP_PKEY_free() the returned key.
 * Returns NULL on failure.
 * ============================================================ */
EVP_PKEY* jwt_load_private_key(const char* key_or_secret,
                                jwt_key_type_t key_type) {
    EVP_PKEY* pkey = NULL;
    BIO*      bio  = NULL;

    switch (key_type) {

        case KEY_PEM_FILE: {
            /* Open the PEM file from disk */
            bio = BIO_new_file(key_or_secret, "r");
            if (!bio) return NULL;
            pkey = load_key_from_bio(bio);
            BIO_free(bio);
            break;
        }

        case KEY_PEM_CONTENT: {
            /* PEM content passed as a string (e.g. from rts.yaml parameter) */
            bio = BIO_new_mem_buf(key_or_secret, -1);
            if (!bio) return NULL;
            pkey = load_key_from_bio(bio);
            BIO_free(bio);
            break;
        }

        case KEY_P12_FILE: {
            /* PKCS#12 file (no password - enterprise certs without passphrase) */
            bio = BIO_new_file(key_or_secret, "rb");
            if (!bio) return NULL;

            PKCS12* p12 = d2i_PKCS12_bio(bio, NULL);
            BIO_free(bio);

            if (!p12) return NULL;

            X509*  cert   = NULL;
            EVP_PKEY* tmp = NULL;
            /* Parse without password (NULL = no passphrase) */
            if (PKCS12_parse(p12, NULL, &tmp, &cert, NULL) == 1) {
                pkey = tmp;
            }
            PKCS12_free(p12);
            if (cert) X509_free(cert);
            break;
        }

        default:
            /* KEY_HMAC_SECRET: not loaded as EVP_PKEY, handled separately */
            return NULL;
    }

    return pkey;
}
