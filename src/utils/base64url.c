/*
 * base64url.c - Base64URL Encoding / Decoding
 *
 * JWT uses Base64URL (RFC 4648 §5):
 *   - Standard Base64 alphabet BUT:
 *     '+' replaced with '-'
 *     '/' replaced with '_'
 *   - NO padding characters ('=')
 *
 * Used for: header encoding, payload encoding, signature encoding.
 */

#include "jwt_core.h"

/* Standard Base64 alphabet (we replace + and / after encoding) */
static const char B64_TABLE[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* ============================================================
 * base64url_encoded_len
 * Returns the number of characters needed (excluding null terminator)
 * ============================================================ */
size_t base64url_encoded_len(size_t input_len) {
    /* Each 3 bytes of input → 4 chars of output (no padding) */
    return ((input_len + 2) / 3) * 4;
}

/* ============================================================
 * base64url_encode
 * Encodes binary data to a Base64URL string.
 *
 * Returns: number of characters written (not counting null), or
 *          JWT_ERROR_BUFFER_SMALL if output_size is too small.
 * ============================================================ */
int base64url_encode(const unsigned char* input, size_t input_len,
                     char* output, size_t output_size) {
    size_t needed;
    size_t i, j;
    unsigned char b0, b1, b2;

    if (!input || !output) return JWT_ERROR_NULL_POINTER;

    needed = base64url_encoded_len(input_len) + 1; /* +1 for null */
    if (output_size < needed) return JWT_ERROR_BUFFER_SMALL;

    j = 0;
    for (i = 0; i + 2 < input_len; i += 3) {
        b0 = input[i];
        b1 = input[i + 1];
        b2 = input[i + 2];
        output[j++] = B64_TABLE[(b0 >> 2) & 0x3F];
        output[j++] = B64_TABLE[((b0 & 0x03) << 4) | ((b1 >> 4) & 0x0F)];
        output[j++] = B64_TABLE[((b1 & 0x0F) << 2) | ((b2 >> 6) & 0x03)];
        output[j++] = B64_TABLE[b2 & 0x3F];
    }

    /* Handle remaining 1 or 2 bytes */
    if (i < input_len) {
        b0 = input[i];
        output[j++] = B64_TABLE[(b0 >> 2) & 0x3F];
        if (i + 1 < input_len) {
            b1 = input[i + 1];
            output[j++] = B64_TABLE[((b0 & 0x03) << 4) | ((b1 >> 4) & 0x0F)];
            output[j++] = B64_TABLE[(b1 & 0x0F) << 2];
        } else {
            output[j++] = B64_TABLE[(b0 & 0x03) << 4];
        }
        /* No padding '=' in Base64URL */
    }

    /* Convert standard Base64 to Base64URL in-place */
    for (size_t k = 0; k < j; k++) {
        if (output[k] == '+') output[k] = '-';
        else if (output[k] == '/') output[k] = '_';
    }

    output[j] = '\0';
    return (int)j;
}

/* ============================================================
 * b64url_char_value
 * Returns the 6-bit value for a Base64URL character, or -1 if invalid.
 * Accepts both standard Base64 (+, /) and Base64URL (-, _).
 * ============================================================ */
static int b64url_char_value(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return (int)(c - 'A');
    if (c >= 'a' && c <= 'z') return (int)(c - 'a') + 26;
    if (c >= '0' && c <= '9') return (int)(c - '0') + 52;
    if (c == '+' || c == '-') return 62; /* both standard and URL-safe */
    if (c == '/' || c == '_') return 63; /* both standard and URL-safe */
    return -1; /* invalid / padding */
}

/* ============================================================
 * base64url_decode
 * Decodes a Base64URL string to binary data.
 * Input may or may not have '=' padding - both are handled.
 *
 * Returns: JWT_SUCCESS, or negative error code.
 * ============================================================ */
int base64url_decode(const char* input, size_t input_len,
                     unsigned char* output, size_t* output_len) {
    size_t i = 0, j = 0;
    int v[4];
    int k, count;

    if (!input || !output || !output_len) return JWT_ERROR_NULL_POINTER;

    while (i < input_len) {
        /* Collect up to 4 valid base64url characters */
        count = 0;
        for (k = 0; k < 4 && i < input_len; ) {
            unsigned char c = (unsigned char)input[i++];
            if (c == '=' || c == '\0') break; /* padding or end */
            int val = b64url_char_value(c);
            if (val < 0) continue; /* skip whitespace/invalid */
            v[k++] = val;
            count++;
        }

        if (count >= 2) {
            output[j++] = (unsigned char)((v[0] << 2) | (v[1] >> 4));
        }
        if (count >= 3) {
            output[j++] = (unsigned char)((v[1] << 4) | (v[2] >> 2));
        }
        if (count >= 4) {
            output[j++] = (unsigned char)((v[2] << 6) | v[3]);
        }
        if (count < 4) break; /* last group */
    }

    *output_len = j;
    return JWT_SUCCESS;
}
