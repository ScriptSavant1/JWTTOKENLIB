/*
 * ============================================================
 * JWTTokenLib - JWT Token Generation Library
 * For LoadRunner Enterprise (LRE) - WEB HTTP/HTML & DevWeb
 * ============================================================
 *
 * Version:   1.0.0
 * Platforms: Windows 2022/2025 (DLL), RedHat Linux (SO)
 * Protocols: WEB HTTP/HTML (C) via lr_load_dll()
 *            DevWeb (JavaScript) via jwt-lib.js wrapper
 *
 * Algorithms supported:
 *   HS256, HS384, HS512  (HMAC - symmetric)
 *   RS256, RS384, RS512  (RSA PKCS#1 v1.5 - asymmetric)
 *   PS256, PS384, PS512  (RSA-PSS - asymmetric)  <-- PRIMARY
 *   ES256, ES384, ES512  (ECDSA - asymmetric)
 *
 * Key auto-detection (key_or_secret parameter):
 *   Starts with "-----BEGIN"   -> PEM content string (from rts.yaml param)
 *   Ends with ".pem"           -> PEM file path (from extras/ folder)
 *   Ends with ".p12" or ".pfx" -> PKCS#12 file path
 *   Anything else              -> HMAC secret string (for HS* only)
 * ============================================================
 */

#ifndef JWTLIB_H
#define JWTLIB_H

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================
 * Platform Export / Import Macros
 * ============================================================ */
#ifdef _WIN32
  #ifdef JWTLIB_EXPORTS
    #define JWTLIB_API __declspec(dllexport)
  #else
    #define JWTLIB_API __declspec(dllimport)
  #endif
#else
  /* GCC/Clang visibility for Linux .so */
  #define JWTLIB_API __attribute__((visibility("default")))
#endif

/* ============================================================
 * Error Codes
 * ============================================================ */
#define JWT_SUCCESS               0   /* Operation succeeded              */
#define JWT_ERROR_INVALID_ALG    -1   /* Algorithm not supported          */
#define JWT_ERROR_INVALID_KEY    -2   /* Key is invalid or wrong format   */
#define JWT_ERROR_INVALID_JSON   -3   /* Payload JSON is malformed        */
#define JWT_ERROR_BUFFER_SMALL   -4   /* Output buffer too small (use 4096)*/
#define JWT_ERROR_SIGN_FAILED    -5   /* Cryptographic signing failed     */
#define JWT_ERROR_NULL_POINTER   -6   /* Required argument is NULL        */
#define JWT_ERROR_FILE_NOT_FOUND -7   /* Key file path not found          */
#define JWT_ERROR_MEMORY         -8   /* Memory allocation failed         */
#define JWT_ERROR_ENCODE         -9   /* Base64URL encoding failed        */

/* ============================================================
 * Core Functions
 * ============================================================ */

/*
 * JWT_Generate
 * ------------
 * Generate a signed JWT token.
 *
 * Parameters:
 *   algorithm     - "PS256", "RS256", "HS256", "ES256", etc.
 *   payload_json  - JSON string: "{\"sub\":\"user1\",\"exp\":1735689600,...}"
 *   key_or_secret - Auto-detected key (see file header for rules)
 *   output_token  - Buffer to receive the JWT token (recommend 4096 bytes)
 *   buffer_size   - Size of output_token buffer
 *
 * Returns: JWT_SUCCESS (0) on success, negative error code on failure
 *
 * VuGen Example:
 *   char token[4096];
 *   int rc = JWT_Generate("PS256",
 *       "{\"iss\":\"loadtest\",\"sub\":\"user-1\",\"exp\":1735689600}",
 *       "extras/private_key.pem",
 *       token, sizeof(token));
 *
 * rts.yaml key example:
 *   int rc = JWT_Generate("PS256", payload,
 *       lr_eval_string("{PrivateKeyPEM}"),  // PEM content from parameter
 *       token, sizeof(token));
 */
JWTLIB_API int JWT_Generate(
    const char* algorithm,
    const char* payload_json,
    const char* key_or_secret,
    char*       output_token,
    int         buffer_size
);

/*
 * JWT_Is_Token_Expiring
 * ---------------------
 * Check whether a token is expiring soon. Use this in long load test
 * runs (> token lifetime) to decide when to regenerate the token.
 *
 * Parameters:
 *   token              - Current JWT token string
 *   threshold_seconds  - Return 1 if token expires within this many seconds
 *
 * Returns:
 *    1  - Token expiring soon, regenerate recommended
 *    0  - Token still valid
 *   -1  - Cannot determine (no "exp" claim, or invalid token)
 *
 * VuGen Example (token expires in 15 min, refresh when < 5 min left):
 *   if (strlen(jwt_token) == 0 || JWT_Is_Token_Expiring(jwt_token, 300)) {
 *       JWT_Generate("PS256", payload, key, jwt_token, sizeof(jwt_token));
 *   }
 */
JWTLIB_API int JWT_Is_Token_Expiring(
    const char* token,
    int         threshold_seconds
);

/*
 * JWT_Get_Error_Message
 * ---------------------
 * Convert an error code to a human-readable description.
 *
 * Returns: Pointer to a static string (do NOT free this pointer)
 *
 * Example:
 *   lr_error_message("JWT failed: %s", JWT_Get_Error_Message(rc));
 */
JWTLIB_API const char* JWT_Get_Error_Message(int error_code);

/*
 * JWT_Get_Version
 * ---------------
 * Returns library version string, e.g. "1.0.0"
 */
JWTLIB_API const char* JWT_Get_Version(void);

/*
 * JWT_Is_Algorithm_Supported
 * --------------------------
 * Check whether an algorithm name is supported by this library.
 *
 * Returns: 1 if supported, 0 if not
 */
JWTLIB_API int JWT_Is_Algorithm_Supported(const char* algorithm);

#ifdef __cplusplus
}
#endif

#endif /* JWTLIB_H */
