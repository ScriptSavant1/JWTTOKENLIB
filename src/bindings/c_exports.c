/*
 * c_exports.c - DLL / SO Exported Functions
 *
 * This file implements the public API functions declared in include/jwtlib.h.
 * These are the functions users call from VuGen WEB HTTP/HTML scripts.
 *
 * Deployment:
 *   Windows: JWTTokenLib.dll  → LoadRunner bin/ folder or script extras/
 *   Linux:   libJWTTokenLib.so → LoadRunner lib/ folder
 *
 * VuGen Usage:
 *   lr_load_dll("JWTTokenLib.dll");          // Windows
 *   lr_load_dll("libJWTTokenLib.so");         // Linux
 *   int rc = JWT_Generate("PS256", payload, key, token, sizeof(token));
 */

#include "jwt_core.h"

/* ============================================================
 * Internal helper: extract the "exp" Unix timestamp from a
 * decoded JSON payload string using simple string search.
 * No external JSON parser needed - just finds "exp": <number>.
 * Returns -1 if "exp" claim is not found.
 * ============================================================ */
static long extract_exp_claim(const char* json, size_t json_len) {
    const char* pos = json;
    const char* end = json + json_len;

    while (pos < end - 5) {
        /*
         * Search for "exp" key. We look for the exact string "\"exp\""
         * to avoid matching fields like "expires_at".
         */
        if (strncmp(pos, "\"exp\"", 5) == 0) {
            pos += 5;

            /* Skip optional whitespace and the colon separator */
            while (pos < end && (*pos == ' ' || *pos == ':' || *pos == '\t')) {
                pos++;
            }

            /* Value must be a numeric Unix timestamp */
            if (pos < end && *pos >= '0' && *pos <= '9') {
                return atol(pos);
            }
        }
        pos++;
    }
    return -1L;
}

/* ============================================================
 * JWT_Generate
 * Exported DLL function - primary entry point for VuGen scripts.
 * ============================================================ */
JWTLIB_API int JWT_Generate(const char* algorithm,
                             const char* payload_json,
                             const char* key_or_secret,
                             char*       output_token,
                             int         buffer_size)
{
    return jwt_generate_token(algorithm, payload_json, key_or_secret,
                              output_token, buffer_size);
}

/* ============================================================
 * JWT_Is_Token_Expiring
 * Checks if the token's "exp" claim is within threshold_seconds
 * of the current time. Returns 1 if expiring, 0 if valid, -1 on error.
 *
 * Use in long load test runs (> 15 min) to know when to regenerate:
 *
 *   if (JWT_Is_Token_Expiring(jwt_token, 300)) {
 *       // Less than 5 minutes remaining - generate fresh token
 *       JWT_Generate("PS256", payload, key, jwt_token, sizeof(jwt_token));
 *   }
 * ============================================================ */
JWTLIB_API int JWT_Is_Token_Expiring(const char* token, int threshold_seconds) {
    const char*   dot1        = NULL;
    const char*   dot2        = NULL;
    const char*   payload_b64 = NULL;
    size_t        payload_b64_len;
    unsigned char payload_json[8192];
    size_t        payload_json_len = 0;
    long          exp_time;
    long          current_time;
    long          time_remaining;
    int           rc;

    if (!token || token[0] == '\0') return -1;

    /* Locate the two dots separating header.payload.signature */
    dot1 = strchr(token, '.');
    if (!dot1) return -1;

    dot2 = strchr(dot1 + 1, '.');
    if (!dot2) return -1;

    /* The payload is the base64url string between the two dots */
    payload_b64     = dot1 + 1;
    payload_b64_len = (size_t)(dot2 - payload_b64);

    /* Decode the payload */
    memset(payload_json, 0, sizeof(payload_json));
    rc = base64url_decode(payload_b64, payload_b64_len,
                          payload_json, &payload_json_len);
    if (rc != JWT_SUCCESS || payload_json_len == 0) return -1;
    payload_json[payload_json_len] = '\0';

    /* Extract exp claim */
    exp_time = extract_exp_claim((const char*)payload_json, payload_json_len);
    if (exp_time < 0) return -1; /* No "exp" claim in token */

    /* Compare with current UTC time */
    current_time   = (long)time(NULL);
    time_remaining = exp_time - current_time;

    /* Return 1 if less than threshold_seconds remain */
    return (time_remaining < (long)threshold_seconds) ? 1 : 0;
}

/* ============================================================
 * JWT_Get_Error_Message
 * Converts an error code to a human-readable string.
 * The returned pointer is a static string - do NOT free it.
 * ============================================================ */
JWTLIB_API const char* JWT_Get_Error_Message(int error_code) {
    switch (error_code) {
        case JWT_SUCCESS:               return "Success";
        case JWT_ERROR_INVALID_ALG:     return "Unsupported algorithm. Use PS256, RS256, HS256, ES256, etc.";
        case JWT_ERROR_INVALID_KEY:     return "Invalid key or secret. Check PEM format or HMAC secret.";
        case JWT_ERROR_INVALID_JSON:    return "Invalid JSON payload. Ensure valid JSON format.";
        case JWT_ERROR_BUFFER_SMALL:    return "Output buffer too small. Use at least 4096 bytes.";
        case JWT_ERROR_SIGN_FAILED:     return "Cryptographic signing failed. Check key matches algorithm.";
        case JWT_ERROR_NULL_POINTER:    return "NULL argument passed. All parameters are required.";
        case JWT_ERROR_FILE_NOT_FOUND:  return "Key file not found. Check path (relative to script folder).";
        case JWT_ERROR_MEMORY:          return "Memory allocation failed. System out of memory.";
        case JWT_ERROR_ENCODE:          return "Base64URL encoding failed. Internal error.";
        default:                        return "Unknown error code.";
    }
}

/* ============================================================
 * JWT_Get_Version
 * Returns the library version string.
 * ============================================================ */
JWTLIB_API const char* JWT_Get_Version(void) {
    return "1.0.0";
}

/* ============================================================
 * JWT_Is_Algorithm_Supported
 * Returns 1 if the algorithm name is supported, 0 if not.
 * ============================================================ */
JWTLIB_API int JWT_Is_Algorithm_Supported(const char* algorithm) {
    if (!algorithm) return 0;
    return (jwt_parse_algorithm(algorithm) != JWT_ALG_UNKNOWN) ? 1 : 0;
}
